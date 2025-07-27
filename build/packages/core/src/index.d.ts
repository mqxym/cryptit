import type { CryptoProvider } from "./providers/CryptoProvider.js";
import { type Difficulty, type SaltStrength } from "./config/defaults.js";
export interface EncryptionConfig {
    difficulty?: Difficulty;
    saltStrength?: SaltStrength;
    chunkSize?: number;
}
export declare class Cryptit {
    private readonly provider;
    private readonly algo;
    private readonly difficulty;
    private readonly saltStrength;
    private readonly chunkSize;
    /** StreamProcessor can only be constructed *after* the three fields above */
    private readonly streamer;
    constructor(provider: CryptoProvider, cfg?: EncryptionConfig);
    encryptText(plain: string | Uint8Array, pass: string): Promise<string>;
    decryptText(b64: string, pass: string): Promise<string>;
    encryptFile(file: Blob, pass: string): Promise<Blob>;
    decryptFile(file: Blob, pass: string): Promise<Blob>;
    createEncryptionStream(pass: string): Promise<TransformStream>;
    createDecryptionStream(pass: string): Promise<TransformStream>;
    private genSalt;
}
//# sourceMappingURL=index.d.ts.map