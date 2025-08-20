import { CryptoProvider } from '../../../providers/CryptoProvider.js';
import { EncryptionAlgorithm } from '../../../types/index.js';
export declare class AESGCM implements EncryptionAlgorithm {
    private readonly p;
    static readonly IV_LENGTH: number;
    static readonly TAG_LENGTH: number;
    readonly IV_LENGTH: number;
    readonly TAG_LENGTH: number;
    private key;
    private aad;
    constructor(p: CryptoProvider);
    setKey(k: CryptoKey): Promise<void>;
    encryptChunk(plain: Uint8Array): Promise<Uint8Array>;
    decryptChunk(data: Uint8Array): Promise<Uint8Array>;
    zeroKey(): void;
    setAAD(aadData: Uint8Array): void;
    private requireKey;
}
