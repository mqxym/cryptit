import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { CryptoProvider } from '../../../providers/CryptoProvider.js';
import { EncryptionAlgorithm } from '../../../types/index.js';
import { DecryptionError } from '../../../errors/index.js';

export class XChaCha20Poly1305 implements EncryptionAlgorithm {

  public static readonly IV_LENGTH: number = 24;
  public readonly IV_LENGTH = XChaCha20Poly1305.IV_LENGTH;

  private key!: Uint8Array;

  constructor(private readonly p: CryptoProvider) {}

  /**
   * Export the raw key material for use with @noble/ciphers
   */
  async setKey(k: CryptoKey) {
    this.key = new Uint8Array(await this.p.subtle.exportKey('raw', k));
  }

  /**
   * Encrypts a chunk with XChaCha20-Poly1305:
   * - Generates a 24-byte nonce
   * - Prepends nonce to ciphertext || tag
   */
  async encryptChunk(plain: Uint8Array): Promise<Uint8Array> {
    const nonce = this.p.getRandomValues(new Uint8Array(XChaCha20Poly1305.IV_LENGTH));
    const cipher = xchacha20poly1305(this.key, nonce);
    const cipherAndTag = cipher.encrypt(plain);
    plain.fill(0);
    this.key.fill(0);
    const out = new Uint8Array(nonce.length + cipherAndTag.length);
    out.set(nonce, 0);
    out.set(cipherAndTag, nonce.length);
    return out;
  }

  /**
   * Decrypts a chunk with XChaCha20-Poly1305:
   * - Extracts nonce (first 24 bytes)
   * - Decrypts ciphertext || tag
   * - Throws on authentication failure
   */
  async decryptChunk(data: Uint8Array): Promise<Uint8Array> {
    const nonce = data.slice(0, XChaCha20Poly1305.IV_LENGTH);
    const cipherAndTag = data.slice(XChaCha20Poly1305.IV_LENGTH);
    const cipher = xchacha20poly1305(this.key, nonce);
    try {
      return cipher.decrypt(cipherAndTag);
    } catch {
      throw new DecryptionError(
        'Decryption failed: wrong passphrase or corrupted ciphertext'
      );
    } finally {
      this.key.fill(0);
    }
  }
}