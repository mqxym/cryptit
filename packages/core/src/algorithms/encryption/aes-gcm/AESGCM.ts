import { CryptoProvider } from '../../../providers/CryptoProvider.js';
import { DecryptionError } from '../../../errors/index.js';
import { BaseAEADWithPadAAD } from '../base/BaseAEADWithPadAAD.js';
import type { PaddingAwareEncryptionAlgorithm } from '../../../types/index.js';

/**
 * AES-GCM encryption with padding policy binding via {@link BaseAEADWithPadAAD}.
 *
 * ## Framing
 * - Output ciphertext is framed as: `[ IV(12) | ciphertext || tag(16) ]`.
 * - IV is generated per-call via the provided {@link CryptoProvider.getRandomValues}.
 *
 * ## AAD and policy
 * - This subclass relies on the base class to compose the final AAD as
 *   `headerAAD || padAAD` and to enforce the padding policy (`require | forbid | auto`)
 *   after decryption.
 * - The `padAAD` fragment (see base class docs) cryptographically binds the
 *   "is padding expected?" decision into the AEAD.
 *
 * ## Zeroization
 * - Plaintext zeroization occurs in {@link BaseAEADWithPadAAD.encryptChunk}, not here.
 *
 * @remarks
 * Interoperates with WebCrypto’s `AES-GCM`. Keys are held as non-extractable
 * {@link CryptoKey} objects in this class by default.
 */
export class AESGCM extends BaseAEADWithPadAAD implements PaddingAwareEncryptionAlgorithm {
  /** AES-GCM nonce/IV length in bytes. */
  public static readonly IV_LENGTH: number = 12;

  /** AES-GCM tag length in bytes. */
  public static readonly TAG_LENGTH: number = 16;

  /** Instance IV length (exposed for interface parity). */
  public readonly IV_LENGTH = AESGCM.IV_LENGTH;

  /** Instance tag length (exposed for interface parity). */
  public readonly TAG_LENGTH = AESGCM.TAG_LENGTH;

  /**
   * Current WebCrypto key. When `null`, the instance cannot encrypt/decrypt.
   * @internal
   */
  private key: CryptoKey | null = null;

  /**
   * Construct an AES-GCM instance backed by the given crypto provider.
   * @param p - Platform crypto provider (WebCrypto subtle + CSPRNG).
   */
  constructor(p: CryptoProvider) { super(p); }

  /**
   * Set the WebCrypto key used for AES-GCM operations.
   *
   * @param k - A {@link CryptoKey} for `AES-GCM` with usages `encrypt` and `decrypt`.
   * @returns Resolves once the key is associated with the instance.
   *
   * @remarks
   * - The key is stored as-is (no re-wrapping).
   * - Passing a key with insufficient usages will cause runtime errors on use.
   */
  public async setKey(k: CryptoKey) { this.key = k; }

  /**
   * Zeroize the in-memory key handle and make the instance unusable until
   * {@link setKey} is called again.
   *
   * @remarks
   * WebCrypto keys are non-extractable by default; this simply drops the handle.
   */
  public zeroKey() { this.key = null; }

  /**
   * **Subclass hook:** Perform AES-GCM encryption with the supplied AAD.
   *
   * @param toEncrypt - Plaintext (may already include a padding trailer; see base).
   * @param aad - AAD produced by the base (`headerAAD || padAAD`).
   * @returns Ciphertext framed as `[ IV(12) | ciphertext || tag(16) ]`.
   *
   * @remarks
   * - IV is generated fresh using {@link CryptoProvider.getRandomValues}.
   * - `additionalData` is always supplied and must match on decrypt for auth to succeed.
   */
  protected async encryptWithAAD(toEncrypt: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    const iv = this.p.getRandomValues(new Uint8Array(AESGCM.IV_LENGTH));
    const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource };

    const cipherBuf = await this.p.subtle.encrypt(params, this.requireKey(), toEncrypt as BufferSource);
    const cipher = new Uint8Array(cipherBuf);

    const out = new Uint8Array(iv.length + cipher.length); // [iv | ciphertext+tag]
    out.set(iv, 0);
    out.set(cipher, iv.length);
    return out;
  }

  /**
   * **Subclass hook:** Perform AES-GCM decryption with the supplied AAD.
   *
   * @param data - Ciphertext framed as `[ IV(12) | ciphertext || tag(16) ]`.
   * @param aad  - AAD that must exactly match what was used during encryption.
   * @returns The recovered plaintext on success (padding policy enforced in base).
   * @throws {DecryptionError}
   *  - If the frame is too short,
   *  - If AEAD authentication fails (AAD mismatch, wrong key/IV/tag),
   *  - Or if WebCrypto rejects the parameters.
   */
  protected async decryptWithAAD(data: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    if (data.byteLength < AESGCM.IV_LENGTH + AESGCM.TAG_LENGTH) {
      throw new DecryptionError('Invalid ciphertext: too short.');
    }
    const iv     = data.subarray(0, AESGCM.IV_LENGTH);
    const cipher = data.subarray(AESGCM.IV_LENGTH);

    const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource };

    try {
      const buf = await this.p.subtle.decrypt(params, this.requireKey(), cipher as BufferSource);
      return new Uint8Array(buf);
    } catch {
      throw new DecryptionError('Decryption failed: wrong passphrase or corrupted ciphertext');
    }
  }

  /**
   * Ensure a key is present; throw otherwise.
   * @returns The current {@link CryptoKey}.
   * @throws {Error} If no key has been set.
   * @internal
   */
  private requireKey(): CryptoKey {
    if (!this.key) throw new Error('Encryption key not set');
    return this.key;
  }
}