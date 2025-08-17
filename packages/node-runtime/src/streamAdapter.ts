import { Readable, Writable } from 'node:stream';

/** Cast Node streams to WHATWG streams in one place */
export function toWebReadable(r: Readable): ReadableStream<Uint8Array> {
  return (Readable as any).toWeb(r) as ReadableStream<Uint8Array>;
}
export function toWebWritable(w: Writable): WritableStream<Uint8Array> {
  return (Writable as any).toWeb(w) as WritableStream<Uint8Array>;
}