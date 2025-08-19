// packages/core/src/algorithms/encryption/aes-gcm/AESGCM.ts
import { CryptoProvider }      from '../../../providers/CryptoProvider.js';
import { EncryptionAlgorithm } from '../../../types/index.js';
import { DecryptionError }     from '../../../errors/index.js';

export class AESGCM implements EncryptionAlgorithm {
  public static readonly IV_LENGTH: number = 12;
  public static readonly TAG_LENGTH: number = 16;
  public readonly IV_LENGTH = AESGCM.IV_LENGTH;
  public readonly TAG_LENGTH = AESGCM.TAG_LENGTH;

  private key!: CryptoKey | null;
  private aad: Uint8Array = new Uint8Array(0);

  constructor(private readonly p: CryptoProvider) {}

  public async setKey(k: CryptoKey) { this.key = k; }

  public async encryptChunk(plain: Uint8Array): Promise<Uint8Array> {

    const iv = this.p.getRandomValues(new Uint8Array(AESGCM.IV_LENGTH));

    const params: AesGcmParams = this.aad.length
      ? { name: 'AES-GCM', iv: iv as BufferSource, additionalData: this.aad as BufferSource }
      : { name: 'AES-GCM', iv: iv as BufferSource };

    const cipherBuf = await this.p.subtle.encrypt(params, this.requireKey(), plain as BufferSource);
    const cipher = new Uint8Array(cipherBuf);

    // Zero plaintext after use
    plain.fill(0);

    // [iv | ciphertext+tag]
    const out = new Uint8Array(iv.length + cipher.length);
    out.set(iv, 0);
    out.set(cipher, iv.length);
    return out;
  }

  public async decryptChunk(data: Uint8Array): Promise<Uint8Array> {
    const iv     = data.slice(0, AESGCM.IV_LENGTH);
    const cipher = data.slice(AESGCM.IV_LENGTH);

    const params: AesGcmParams = this.aad.length
      ? { name: 'AES-GCM', iv: iv as BufferSource, additionalData: this.aad as BufferSource }
      : { name: 'AES-GCM', iv: iv as BufferSource};

    try {
      const plain = await this.p.subtle.decrypt(params, this.requireKey(), cipher as BufferSource);
      return new Uint8Array(plain);
    } catch {
      throw new DecryptionError(
        'Decryption failed: wrong passphrase or corrupted ciphertext',
      );
    }
  }

  public zeroKey() {
    this.key = null;
  } // Non-extractable CryptoKey

  // Set additional authenticated data
  public setAAD(aadData: Uint8Array): void {
    this.aad = aadData && aadData.byteLength
      ? new Uint8Array(aadData) // copy to avoid caller mutations
      : new Uint8Array(0);
  }

  private requireKey(): CryptoKey {
    if (!this.key) {
      throw new Error('Encryption key not set');
    }
    return this.key;
  }

}