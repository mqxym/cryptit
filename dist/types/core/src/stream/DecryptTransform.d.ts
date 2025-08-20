import type { EncryptionAlgorithm } from '../types/index.js';
/**
 * Counterpart to EncryptTransform.
 * Streams framed ciphertext → raw plaintext.
 */
export declare class DecryptTransform {
    private readonly engine;
    private readonly chunkSize;
    private buffer;
    constructor(engine: EncryptionAlgorithm, chunkSize?: number);
    toTransformStream(): TransformStream<Uint8Array | ArrayBuffer | Blob, Uint8Array>;
    private transform;
    private flush;
}
