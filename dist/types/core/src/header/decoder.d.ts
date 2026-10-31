import { EncryptionAlgorithm } from '../types/index.js';
export declare function decodeHeaderPrefix(buf: Uint8Array): {
    scheme: number;
    saltStrength: "low" | "high";
    prefixLength: number;
};
export declare function decodeHeader(buf: Uint8Array, cipher?: EncryptionAlgorithm): {
    scheme: number;
    difficulty: "low" | "middle" | "high";
    saltStrength: "low" | "high";
    salt: Uint8Array<ArrayBuffer>;
    headerLen: number;
    streamFormat: "legacy" | "authenticated-v1";
};
