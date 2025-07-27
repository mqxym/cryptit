import type { IEncryptionAlgorithm } from "../types.js";
/**
 * Counterpart to EncryptTransform.
 * Accepts the framed ciphertext and streams out raw plaintext.
 *
 * Emits Uint8Array chunks identical to the original plaintext
 * (except block boundaries aren’t guaranteed to match).
 */
export declare class DecryptTransform {
    private readonly engine;
    private readonly chunkSize;
    private buffer;
    constructor(engine: IEncryptionAlgorithm, chunkSize?: number);
    toTransformStream(): TransformStream<Uint8Array | ArrayBuffer | Blob, Uint8Array>;
    private transform;
    private flush;
    private asUint8Array;
}
//# sourceMappingURL=DecryptTransform.d.ts.map