import type { EncryptionAlgorithm } from '../types/index.js';
import { type StreamFormat } from '../util/frame.js';
export interface DecryptTransformOptions {
    format?: StreamFormat;
    header?: Uint8Array;
}
/**
 * Counterpart to EncryptTransform.
 * Streams framed ciphertext → raw plaintext.
 */
export declare class DecryptTransform {
    private readonly engine;
    private readonly chunkSize;
    private buffer;
    private bufferedLength;
    private bufferedFrameLength;
    private recordIndex;
    private terminalSeen;
    private failed;
    private readonly format;
    private readonly header;
    constructor(engine: EncryptionAlgorithm, chunkSize?: number, options?: DecryptTransformOptions);
    toTransformStream(): TransformStream<Uint8Array | ArrayBuffer | Blob, Uint8Array>;
    private transform;
    private flush;
    private readRecord;
    private decryptRecord;
    private appendToBuffer;
    private stashPartial;
    private resetBuffer;
    private clearBuffer;
    private asDecryptionError;
    private fail;
}
