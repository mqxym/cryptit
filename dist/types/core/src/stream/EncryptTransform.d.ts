import type { EncryptionAlgorithm } from '../types/index.js';
/**
 * TransformStream that:
 *   • collects plaintext into fixed‐size blocks
 *   • encrypts each block
 *   • emits: [4-byte length ‖ encryptedBlock]
 *
 * Back-pressure / sizing contract:
 *   A single write must not exceed `min(chunkSize * 4, 64 MiB)`. Larger writes
 *   throw a {@link RangeError} synchronously from `transform()` rather than being
 *   buffered, to bound peak memory. Callers streaming big payloads should write
 *   in chunks at or below this limit (the surrounding pipeline already does so).
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
