// packages/core/src/algorithms/encryption/aes-gmc/AESGCM.ts
import { CryptoProvider }    from '../../../providers/CryptoProvider.js';
import { EncryptionAlgorithm } from '../../../types/index.js';
import { DecryptionError }   from '../../../errors/index.js';

export class AESGCM implements EncryptionAlgorithm {
  public static readonly IV_LENGTH: number = 12;
  public readonly IV_LENGTH = AESGCM.IV_LENGTH;

  private key!: CryptoKey;

  constructor(private readonly p: CryptoProvider) {}

  public async setKey(k: CryptoKey) { this.key = k; }

  public async encryptChunk(plain: Uint8Array): Promise<Uint8Array> {
    
    const iv = this.p.getRandomValues(
      new Uint8Array(AESGCM.IV_LENGTH),
    );

    const cipher = new Uint8Array(
      await this.p.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, plain),
    );
    plain.fill(0)
    const out = new Uint8Array(iv.length + cipher.length);
    out.set(iv);
    out.set(cipher, iv.length);
    return out;
  }

  public async decryptChunk(data: Uint8Array): Promise<Uint8Array> {
    const iv     = data.slice(0, AESGCM.IV_LENGTH);
    const cipher = data.slice(AESGCM.IV_LENGTH);
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

  public zeroKey() {}
}