// packages/core/src/util/frame.ts
const LEN_BYTES = 4 as const;
const TERMINAL_FLAG = 0x80000000;
const LENGTH_MASK = 0x7fffffff;
const MAX_RECORD_INDEX = 0xffffffffffffffffn;

export const MAX_PLAINTEXT_CHUNK_SIZE = 128 * 1024 * 1024;
export const MAX_STREAM_WRITE_SIZE = 64 * 1024 * 1024;
export const MAX_CIPHER_FRAME_SIZE = MAX_PLAINTEXT_CHUNK_SIZE + 40;

export type StreamFormat = 'legacy' | 'authenticated-v1';

export interface StreamRecord {
  length: number;
  terminal: boolean;
  word: number;
}

export function encodeFrameLen(n: number): Uint8Array {
  const hdr = new Uint8Array(LEN_BYTES);
  new DataView(hdr.buffer).setUint32(0, n, false);   // big‑endian
  return hdr;
}

export function encodeStreamRecord(length: number, terminal = false): Uint8Array {
  if (!Number.isInteger(length) || length < 0 || length > LENGTH_MASK) {
    throw new RangeError(`Invalid stream record length: ${length}`);
  }
  return encodeFrameLen((length | (terminal ? TERMINAL_FLAG : 0)) >>> 0);
}

export function decodeStreamRecord(buf: Uint8Array, off = 0): StreamRecord {
  const word = decodeFrameLen(buf, off);
  return {
    length: word & LENGTH_MASK,
    terminal: (word & TERMINAL_FLAG) !== 0,
    word,
  };
}

export function buildStreamRecordAAD(
  header: Uint8Array,
  recordIndex: bigint,
  record: Pick<StreamRecord, 'terminal' | 'word'>,
): Uint8Array {
  if (recordIndex < 0n || recordIndex > MAX_RECORD_INDEX) {
    throw new RangeError('Stream record index exceeds uint64');
  }

  const domain = new Uint8Array([0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x54, 0x01]);
  const metadata = new Uint8Array(13);
  const view = new DataView(metadata.buffer);
  view.setBigUint64(0, recordIndex, false);
  metadata[8] = record.terminal ? 1 : 0;
  view.setUint32(9, record.word, false);

  const aad = new Uint8Array(domain.length + header.length + metadata.length);
  aad.set(domain, 0);
  aad.set(header, domain.length);
  aad.set(metadata, domain.length + header.length);
  return aad;
}

export function decodeFrameLen(buf: Uint8Array, off = 0): number {
  if (buf.length - off < LEN_BYTES) {
    throw new RangeError('Not enough bytes for frame header');
  }
  return new DataView(buf.buffer, buf.byteOffset + off, LEN_BYTES)
           .getUint32(0, false);
}
export const FRAME_HEADER_BYTES = LEN_BYTES;