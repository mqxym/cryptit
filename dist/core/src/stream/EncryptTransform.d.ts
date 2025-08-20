import type { EncryptionAlgorithm } from '../types/index.js';
/**
 * TransformStream that:
 *   • collects plaintext into fixed‐size blocks
 *   • encrypts each block
 *   • emits: [4-byte length ‖ encryptedBlock]
 */
export declare class EncryptTransform {
    private readonly engine;
    private readonly chunkSize;
    private buffer;
    constructor(engine: EncryptionAlgorithm, chunkSize?: number);
    toTransformStream(): TransformStream<Uint8Array | ArrayBuffer | Blob, Uint8Array>;
    private transform;
    private flush;
}
