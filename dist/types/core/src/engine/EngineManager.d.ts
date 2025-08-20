import type { SchemeDescriptor, EncryptionAlgorithm, KeyDerivation, Secret } from '../types/index.js';
import type { CryptoProvider } from '../providers/CryptoProvider.js';
export interface Engine {
    desc: SchemeDescriptor;
    cipher: EncryptionAlgorithm;
    kdf: KeyDerivation;
    chunkSize: number;
    provider: CryptoProvider;
}
export declare class EngineManager {
    static getEngine(provider: CryptoProvider, schemeId: number): Engine;
    static deriveKey(engine: Engine, secret: Secret, salt: Uint8Array, difficulty: 'low' | 'middle' | 'high'): Promise<void>;
}
