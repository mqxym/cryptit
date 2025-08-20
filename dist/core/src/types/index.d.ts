import type { CryptoProvider } from '../providers/CryptoProvider.js';
export interface EncryptionAlgorithm {
    encryptChunk(plain: Uint8Array): Promise<Uint8Array>;
    decryptChunk(cipher: Uint8Array): Promise<Uint8Array>;
    setKey(k: CryptoKey): Promise<void>;
    zeroKey(): void;
    setAAD(aadData: Uint8Array): void;
    readonly IV_LENGTH: number;
    readonly TAG_LENGTH: number;
}
export interface KeyDerivation<D extends string = string> {
    readonly name: string;
    derive(passphrase: Uint8Array | string, salt: Uint8Array, difficulty: D, provider: CryptoProvider): Promise<CryptoKey>;
}
export interface CipherConstructor {
    readonly IV_LENGTH: number;
    readonly TAG_LENGTH: number;
    new (p: CryptoProvider): EncryptionAlgorithm;
}
export interface SchemeDescriptor<S extends string = string, D extends string = string> {
    readonly id: number;
    readonly cipher: CipherConstructor;
    readonly kdf: KeyDerivation<D>;
    readonly saltLengths: Record<S, number>;
    readonly difficulties: Record<D, unknown>;
    readonly defaultChunkSize: number;
}
export type Secret = {
    value: string;
};
