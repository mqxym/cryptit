import { type EncryptTransformOptions } from './EncryptTransform.js';
import type { PaddingAwareEncryptionAlgorithm } from '../types/index.js';
export declare class StreamProcessor {
    private readonly engine;
    private readonly chunkSize;
    constructor(engine: PaddingAwareEncryptionAlgorithm, chunkSize?: number);
    encryptionStream(options?: EncryptTransformOptions): TransformStream<Uint8Array, Uint8Array>;
    decryptionStream(headerLen: number): TransformStream<Uint8Array, Uint8Array>;
    collect(readable: ReadableStream<Uint8Array>, transform: TransformStream<Uint8Array, Uint8Array>, prefix?: Uint8Array | null): Promise<Uint8Array>;
    getEngine(): PaddingAwareEncryptionAlgorithm;
}
