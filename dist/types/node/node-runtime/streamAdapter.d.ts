import { Readable, Writable } from 'node:stream';
/** Cast Node streams to WHATWG streams in one place */
export declare function toWebReadable(r: Readable): ReadableStream<Uint8Array>;
export declare function toWebWritable(w: Writable): WritableStream<Uint8Array>;
