import { CryptoProvider } from '../../../providers/CryptoProvider.js';
import { DecryptionError } from '../../../errors/index.js';
import { BaseAEADWithPadAAD } from '../base/BaseAEADWithPadAAD.js';
import type { PaddingAwareEncryptionAlgorithm } from '../../../types/index.js';
import { asArrayBufferView } from '../../../util/bytes.js';

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
  public static readonly IV_LENGTH: number = 12;
  public static readonly TAG_LENGTH: number = 16;

  public readonly IV_LENGTH = AESGCM.IV_LENGTH;
  public readonly TAG_LENGTH = AESGCM.TAG_LENGTH;

  private key: CryptoKey | null = null;

  constructor(p: CryptoProvider) { super(p); }

  public async setKey(k: CryptoKey) { this.key = k; }

  public zeroKey() { this.key = null; }

  protected async encryptWithAAD(toEncrypt: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    const iv = asArrayBufferView(
      this.p.getRandomValues(new Uint8Array(AESGCM.IV_LENGTH))
    );
    const aadView = asArrayBufferView(aad);
    const plainView = asArrayBufferView(toEncrypt);

    const params: AesGcmParams = {
      name: 'AES-GCM',
      iv,
      additionalData: aadView,
    };

    const cipherBuf = await this.p.subtle.encrypt(params, this.requireKey(), plainView);
    const cipher = new Uint8Array(cipherBuf);

    const out = new Uint8Array(iv.length + cipher.length);
    out.set(iv, 0);
    out.set(cipher, iv.length);
    return out;
  }

  protected async decryptWithAAD(data: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    if (data.byteLength < AESGCM.IV_LENGTH + AESGCM.TAG_LENGTH) {
      throw new DecryptionError('Invalid ciphertext: too short.');
    }

    const iv = asArrayBufferView(data.subarray(0, AESGCM.IV_LENGTH));
    const cipher = asArrayBufferView(data.subarray(AESGCM.IV_LENGTH));
    const aadView = asArrayBufferView(aad);

    const params: AesGcmParams = {
      name: 'AES-GCM',
      iv,
      additionalData: aadView,
    };

    try {
      const buf = await this.p.subtle.decrypt(params, this.requireKey(), cipher);
      return new Uint8Array(buf);
    } catch {
      throw new DecryptionError('Decryption failed: wrong passphrase or corrupted ciphertext');
    }
  }

  private requireKey(): CryptoKey {
    if (!this.key) throw new Error('Encryption key not set');
    return this.key;
  }
}