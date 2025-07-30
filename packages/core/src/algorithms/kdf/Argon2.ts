// packages/core/src/algorithms/kdf/Argon2.ts
import { KeyDerivation } from '../../types/index.js';
import { argon2id, Argon2Tuning } from './argon2-wrapper.js';
import { CryptoProvider } from '../../providers/CryptoProvider.js';

export class Argon2KDF implements KeyDerivation {
  constructor(private readonly presets: Record<string, Argon2Tuning>) {}

  async derive(
    pass: Uint8Array | string,
    salt: Uint8Array,
    diff: string,
    p: CryptoProvider,
  ): Promise<CryptoKey> {
    const { hash } = await argon2id(pass, salt, this.presets[diff], p.isNode ? 'node' : 'browser');
    return p.subtle.importKey('raw', hash, { name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ]);
  }
}