export declare const MAX_PLAINTEXT_CHUNK_SIZE: number;
export declare const MAX_STREAM_WRITE_SIZE: number;
export declare const MAX_CIPHER_FRAME_SIZE: number;
export type StreamFormat = 'legacy' | 'authenticated-v1';
export interface StreamRecord {
    length: number;
    terminal: boolean;
    word: number;
}
export declare function encodeFrameLen(n: number): Uint8Array;
export declare function encodeStreamRecord(length: number, terminal?: boolean): Uint8Array;
export declare function decodeStreamRecord(buf: Uint8Array, off?: number): StreamRecord;
export declare function buildStreamRecordAAD(header: Uint8Array, recordIndex: bigint, record: Pick<StreamRecord, 'terminal' | 'word'>): Uint8Array;
export declare function decodeFrameLen(buf: Uint8Array, off?: number): number;
export declare const FRAME_HEADER_BYTES: 4;
