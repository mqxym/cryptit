import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { CryptoProvider } from '../../../providers/CryptoProvider.js';
import { EncryptionAlgorithm } from '../../../types/index.js';
import { DecryptionError } from '../../../errors/index.js';

export class XChaCha20Poly1305 implements EncryptionAlgorithm {
  public static readonly IV_LENGTH: number = 24;
  public static readonly TAG_LENGTH: number = 16;
  public readonly IV_LENGTH = XChaCha20Poly1305.IV_LENGTH;
  public readonly TAG_LENGTH = XChaCha20Poly1305.TAG_LENGTH;


  private key!: Uint8Array;
  private aad: Uint8Array = new Uint8Array(0);

  constructor(private readonly p: CryptoProvider) {}

  /**
   * Export the raw key material for use with @noble/ciphers
   */
  public async setKey(k: CryptoKey) {
    this.key = new Uint8Array(await this.p.subtle.exportKey('raw', k));
  }

  /**
   * Encrypts a chunk with XChaCha20-Poly1305:
   * - Generates a 24-byte nonce
   * - Prepends nonce to ciphertext || tag
   * - Uses AAD if set (omitted when empty)
   */
  public async encryptChunk(plain: Uint8Array): Promise<Uint8Array> {
    if (!this.key) throw new Error('Key not set');

    const nonce = this.p.getRandomValues(new Uint8Array(XChaCha20Poly1305.IV_LENGTH));

    // Only pass AAD when non-empty (same behavior as AES-GCM fix)
    const cipher = this.aad.length
      ? xchacha20poly1305(this.key, nonce, this.aad)
      : xchacha20poly1305(this.key, nonce);

    const cipherAndTag = cipher.encrypt(plain);
    plain.fill(0);

    const out = new Uint8Array(nonce.length + cipherAndTag.length);
    out.set(nonce, 0);
    out.set(cipherAndTag, nonce.length);
    return out;
  }

  /**
   * Decrypts a chunk with XChaCha20-Poly1305:
   * - Extracts nonce (first 24 bytes)
   * - Decrypts ciphertext || tag
   * - Uses the same AAD rule (omit when empty)
   * - Throws on authentication failure
   */
  public async decryptChunk(data: Uint8Array): Promise<Uint8Array> {
    if (!this.key) throw new Error('Key not set');
    if (data.byteLength < XChaCha20Poly1305.IV_LENGTH + 16 /* tag */) {
      throw new DecryptionError('Invalid ciphertext: too short.');
    }

    const nonce = data.slice(0, XChaCha20Poly1305.IV_LENGTH);
    const cipherAndTag = data.slice(XChaCha20Poly1305.IV_LENGTH);

    const cipher = this.aad.length
      ? xchacha20poly1305(this.key, nonce, this.aad)
      : xchacha20poly1305(this.key, nonce);

    try {
      return cipher.decrypt(cipherAndTag);
    } catch {
      throw new DecryptionError(
        'Decryption failed: wrong passphrase or corrupted ciphertext'
      );
    }
  }

  public zeroKey(): void {
    if (this.key) this.key.fill(0);
  }

  // Set additional authenticated data
  public setAAD(aadData: Uint8Array): void {
    this.aad = aadData && aadData.byteLength
      ? new Uint8Array(aadData) // copy to avoid caller mutations
      : new Uint8Array(0);
  }
}