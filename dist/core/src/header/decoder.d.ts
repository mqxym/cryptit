import { EncryptionAlgorithm } from '../types/index.js';
export declare function decodeHeader(buf: Uint8Array, cipher?: EncryptionAlgorithm): {
    scheme: number;
    difficulty: "low" | "middle" | "high";
    saltStrength: "low" | "high";
    salt: Uint8Array<ArrayBuffer>;
    headerLen: number;
};
