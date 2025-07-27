import type { IEncryptionAlgorithm } from "../types.js";
/**
 * TransformStream that:
 *   • collects plaintext into fixed-size blocks (default 512 KiB)
 *   • encrypts each block via the provided crypto engine
 *   • emits: [4-byte big-endian length ‖ encryptedBlock]
 *
 * Input  types accepted: Uint8Array | ArrayBuffer | Blob
 * Output type:           Uint8Array
 */
export declare class EncryptTransform {
    private readonly engine;
    private readonly chunkSize;
    private buffer;
    constructor(engine: IEncryptionAlgorithm, chunkSize?: number);
    /** Public factory – keeps callers one-liner-simple */
    toTransformStream(): TransformStream<Uint8Array | ArrayBuffer | Blob, Uint8Array>;
    private transform;
    private flush;
    private asUint8Array;
}
//# sourceMappingURL=EncryptTransform.d.ts.map