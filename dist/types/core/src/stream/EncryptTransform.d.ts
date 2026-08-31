import type { EncryptionAlgorithm } from '../types/index.js';
import { type StreamFormat } from '../util/frame.js';
export interface EncryptTransformOptions {
    format?: StreamFormat;
    header?: Uint8Array;
}
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
    private recordIndex;
    private readonly format;
    private readonly header;
    constructor(engine: EncryptionAlgorithm, chunkSize?: number, options?: EncryptTransformOptions);
    toTransformStream(): TransformStream<Uint8Array | ArrayBuffer | Blob, Uint8Array>;
    private transform;
    private flush;
    private emitRecord;
}
