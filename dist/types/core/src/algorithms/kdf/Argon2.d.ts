import type { KeyDerivation } from '../../types/index.js';
import { type Argon2Tuning } from './argon2-wrapper.js';
import type { CryptoProvider } from '../../providers/CryptoProvider.js';
import { CryptoKeyLike } from '../../types/crypto-key-like.js';
/**
 * Argon2-id Key-Derivation Function
 */
export declare class Argon2KDF implements KeyDerivation<'low' | 'middle' | 'high'> {
    private readonly presets;
    private exportExtractable;
    readonly name = "argon2id";
    constructor(presets: Readonly<Record<'low' | 'middle' | 'high', Argon2Tuning>>, exportExtractable?: boolean);
    derive(passphrase: Uint8Array | string, salt: Uint8Array, difficulty: 'low' | 'middle' | 'high', provider: CryptoProvider): Promise<CryptoKeyLike>;
}
