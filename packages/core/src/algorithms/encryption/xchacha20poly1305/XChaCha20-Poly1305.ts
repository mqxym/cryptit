import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { CryptoProvider }    from '../../../providers/CryptoProvider.js';
import { DecryptionError }   from '../../../errors/index.js';
import { BaseAEADWithPadAAD } from '../base/BaseAEADWithPadAAD.js';
import type { PaddingAwareEncryptionAlgorithm } from '../../../types/index.js';

/**
 * XChaCha20-Poly1305 encryption with padding policy binding via {@link BaseAEADWithPadAAD}.
 *
 * ## Framing
 * - Output ciphertext is framed as: `[ NONCE(24) | ciphertext || tag(16) ]`.
 * - NONCE is generated per-call via the provided {@link CryptoProvider.getRandomValues}.
 *
 * ## AAD and policy
 * - Uses the base class to compose the final AAD (`headerAAD || padAAD`) and to enforce
 *   padding policy after decryption.
 * - The bound AAD ensures decrypt will fail if either header or pad settings differ.
 *
 * ## Key handling
 * - This class accepts a WebCrypto {@link CryptoKey} via {@link setKey}, then exports
 *   its raw bytes to feed `@noble/ciphers` (which requires a raw 32-byte key).
 * - The exported raw key is stored in memory; {@link zeroKey} overwrites and discards it.
 *
 * ## Zeroization
 * - Plaintext zeroization occurs in {@link BaseAEADWithPadAAD.encryptChunk}, not here.
 */
export class XChaCha20Poly1305 extends BaseAEADWithPadAAD implements PaddingAwareEncryptionAlgorithm {
  /** XChaCha20-Poly1305 nonce length in bytes. */
  public static readonly IV_LENGTH: number = 24;

  /** Poly1305 tag length in bytes. */
  public static readonly TAG_LENGTH: number = 16;

  /** Instance nonce length (exposed for interface parity). */
  public readonly IV_LENGTH = XChaCha20Poly1305.IV_LENGTH;

  /** Instance tag length (exposed for interface parity). */
  public readonly TAG_LENGTH = XChaCha20Poly1305.TAG_LENGTH;

  /**
   * Raw 32-byte key material for `@noble/ciphers`. When `null`, the instance
   * cannot encrypt/decrypt.
   * @internal
   */
  private key: Uint8Array | null = null;

  /**
   * Construct an XChaCha20-Poly1305 instance backed by the given crypto provider.
   * @param p - Platform crypto provider (WebCrypto subtle + CSPRNG).
   */
  constructor(p: CryptoProvider) { super(p); }

  /**
   * Set the key using a WebCrypto {@link CryptoKey}.
   *
   * @param k - A WebCrypto secret key (e.g., imported/generated 256-bit secret).
   * @returns Resolves once the key is exported and stored.
   *
   * @remarks
   * - The key is **exported as raw bytes** using `subtle.exportKey('raw', k)` and kept
   *   in memory for use with `@noble/ciphers`.
   * - Ensure the provided key was created/imported with `extractable: true`.
   */
  public async setKey(k: CryptoKey) {
    this.key = new Uint8Array(await this.p.subtle.exportKey('raw', k));
  }

  /**
   * Overwrite and discard the in-memory raw key bytes.
   * Subsequent calls to encrypt/decrypt will fail until {@link setKey}.
   */
  public zeroKey(): void {
    if (this.key) this.key.fill(0);
    this.key = null;
  }

  /**
   * **Subclass hook:** Perform XChaCha20-Poly1305 encryption with the supplied AAD.
   *
   * @param toEncrypt - Plaintext (may already include a padding trailer; see base).
   * @param aad - AAD produced by the base (`headerAAD || padAAD`).
   * @returns Ciphertext framed as `[ NONCE(24) | ciphertext || tag(16) ]`.
   *
   * @remarks
   * - NONCE is generated fresh using {@link CryptoProvider.getRandomValues}.
   * - The same AAD must be provided at decrypt-time or authentication will fail.
   */
  protected async encryptWithAAD(toEncrypt: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    const nonce = this.p.getRandomValues(new Uint8Array(XChaCha20Poly1305.IV_LENGTH));
    const cipher = xchacha20poly1305(this.requireRawKey(), nonce, aad);
    const cipherAndTag = cipher.encrypt(toEncrypt);

    const out = new Uint8Array(nonce.length + cipherAndTag.length); // [nonce | ct||tag]
    out.set(nonce, 0);
    out.set(cipherAndTag, nonce.length);
    return out;
  }

  /**
   * **Subclass hook:** Perform XChaCha20-Poly1305 decryption with the supplied AAD.
   *
   * @param data - Ciphertext framed as `[ NONCE(24) | ciphertext || tag(16) ]`.
   * @param aad  - AAD that must exactly match what was used during encryption.
   * @returns The recovered plaintext on success (padding policy enforced in base).
   * @throws {DecryptionError}
   *  - If the frame is too short,
   *  - If authentication fails (AAD mismatch, wrong key/nonce/tag),
   *  - Or if the underlying cipher rejects inputs.
   */
  protected async decryptWithAAD(data: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    if (data.byteLength < XChaCha20Poly1305.IV_LENGTH + XChaCha20Poly1305.TAG_LENGTH) {
      throw new DecryptionError('Invalid ciphertext: too short.');
    }
    const nonce        = data.subarray(0, XChaCha20Poly1305.IV_LENGTH);
    const cipherAndTag = data.subarray(XChaCha20Poly1305.IV_LENGTH);

    const cipher = xchacha20poly1305(this.requireRawKey(), nonce, aad);
    try {
      return cipher.decrypt(cipherAndTag);
    } catch {
      throw new DecryptionError('Decryption failed: wrong passphrase or corrupted ciphertext');
    }
  }

  /**
   * Ensure a raw key is present; throw otherwise.
   * @returns The raw 32-byte key.
   * @throws {Error} If no key has been set.
   * @internal
   */
  private requireRawKey(): Uint8Array {
    if (!this.key) throw new Error('Encryption key not set');
    return this.key;
  }
}