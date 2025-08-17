// packages/core/src/util/frame.ts
const LEN_BYTES = 4 as const;

export function encodeFrameLen(n: number): Uint8Array {
  const hdr = new Uint8Array(LEN_BYTES);
  new DataView(hdr.buffer).setUint32(0, n, false);   // big‑endian
  return hdr;
}

export function decodeFrameLen(buf: Uint8Array, off = 0): number {
  if (buf.length - off < LEN_BYTES) {
    throw new RangeError('Not enough bytes for frame header');
  }
  return new DataView(buf.buffer, buf.byteOffset + off, LEN_BYTES)
           .getUint32(0, false);
}
export const FRAME_HEADER_BYTES = LEN_BYTES;