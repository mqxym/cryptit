import { CryptoProvider } from '../../providers/CryptoProvider.js';
import { DefaultConfig } from '../../config/defaults.js';
export declare class AESGCMEncryption {
    private provider;
    private key;
    constructor(provider: CryptoProvider);
    deriveKey(passphrase: Uint8Array | string, salt: Uint8Array, diff: keyof typeof DefaultConfig.argon): Promise<void>;
    encryptChunk(plain: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
    decryptChunk(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
}
//# sourceMappingURL=AESGCMEncryption.d.ts.map