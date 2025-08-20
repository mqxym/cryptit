/**
 * Unified, zero -copy accessor for Blob | Uint8Array | Base64 -encoded string.
 * Slices are read on -demand so even multi -gigabyte Blobs are handled
 * without loading them fully into memory.
 */
export declare class ByteSource {
    #private;
    private readonly src;
    constructor(src: Blob | Uint8Array | string);
    /** Total byte length of the underlying data */
    get length(): number;
    /**
     * Read a slice *[offset, offset + len)* as Uint8Array.
     * The returned view is a fresh copy — safe to mutate by caller.
     */
    read(offset: number, len: number): Promise<Uint8Array>;
    /** lazily decode Base64 text into a Uint8Array (once) */
    private ensureUint8;
}
export interface RandomAccessSource {
    /** total length in bytes */
    readonly length: number;
    /**
     * return a copy of bytes `[offset, offset + len)`
     * throws if the range is out of bounds
     */
    read(offset: number, len: number): Promise<Uint8Array>;
}
export declare class FileByteSource implements RandomAccessSource {
    private readonly fd;
    readonly length: number;
    private constructor();
    static open(path: string): Promise<FileByteSource>;
    read(offset: number, len: number): Promise<Uint8Array>;
    /** always call after finishing */
    close(): Promise<void>;
}
