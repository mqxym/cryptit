// packages/core/src/algorithms/kdf/Argon2.ts
import type { KeyDerivation } from '../../types/index.js';
import { argon2id, type Argon2Tuning } from './argon2-wrapper.js';
import type { CryptoProvider } from '../../providers/CryptoProvider.js';

/**
 * Argon2-id Key-Derivation Function
 */
export class Argon2KDF implements KeyDerivation<'low' | 'middle' | 'high'> {
  readonly name = 'argon2id';

  constructor(
    private readonly presets: Readonly<Record<'low' | 'middle' | 'high', Argon2Tuning>>,
    private exportExtractable: boolean = false
  ) {}

  async derive(
    passphrase: Uint8Array | string,
    salt: Uint8Array,
    difficulty: 'low' | 'middle' | 'high',
    provider: CryptoProvider,
  ): Promise<CryptoKey> {
    const { hash } = await argon2id(
      passphrase,
      salt,
      this.presets[difficulty],
      provider.isNode ? 'node' : 'browser'
    );
    if (this.exportExtractable) {
      return provider.subtle.importKey(
        'raw',
        hash,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
    } else {
      return provider.subtle.importKey(
        'raw',
        hash,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    }
  }
}