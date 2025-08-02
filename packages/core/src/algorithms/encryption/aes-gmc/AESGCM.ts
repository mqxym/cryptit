// packages/core/src/algorithms/encryption/aes-gmc/AESGCM.ts
import { CryptoProvider }    from '../../../providers/CryptoProvider.js';
import { EncryptionAlgorithm } from '../../../types/index.js';
import { DecryptionError }   from '../../../errors/index.js';

export class AESGCM implements EncryptionAlgorithm {
  private key!: CryptoKey;

  constructor(private readonly p: CryptoProvider) {}

  async setKey(k: CryptoKey) { this.key = k; }

  async encryptChunk(plain: Uint8Array): Promise<Uint8Array> {
    const iv = this.p.getRandomValues(new Uint8Array(12));
    const cipher = new Uint8Array(
      await this.p.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, plain),
    );
    const out = new Uint8Array(iv.length + cipher.length);
    out.set(iv);
    out.set(cipher, iv.length);
    return out;
  }

  async decryptChunk(data: Uint8Array): Promise<Uint8Array> {
    const iv     = data.slice(0, 12);
    const cipher = data.slice(12);
    const plain  = await this.p.subtle.decrypt({ name: 'AES-GCM', iv }, this.key, cipher);
    try {
      const plain = await this.p.subtle.decrypt(
        { name: 'AES-GCM', iv },
        this.key,
        cipher,
      );
      return new Uint8Array(plain);
    } catch {
      throw new DecryptionError(
        'Decryption failed: wrong passphrase or corrupted ciphertext',
      );
    }
  }
}