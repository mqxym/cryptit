import type { IEncryptionAlgorithm } from "../types.js";
export declare class StreamProcessor {
    private readonly engine;
    private readonly chunkSize;
    constructor(engine: IEncryptionAlgorithm, chunkSize?: number);
    encryptionStream(header: Uint8Array): TransformStream<Uint8Array, Uint8Array>;
    decryptionStream(headerLen: number): TransformStream<Uint8Array, Uint8Array>;
    collect(readable: ReadableStream<Uint8Array>, transform: TransformStream<Uint8Array, Uint8Array>, prefix?: Uint8Array | null): Promise<Uint8Array>;
}
//# sourceMappingURL=StreamProcessor.d.ts.map