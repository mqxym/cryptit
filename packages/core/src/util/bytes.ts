export function concat(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

/**
 * Base64-encode one or more Uint8Arrays without intermediate copies.
 */
export function base64Encode(...chunks: Uint8Array[]): string {
  return Buffer.from(concat(...chunks)).toString('base64');
}

/** Reverse of `base64Encode` */
export function base64Decode(b64: string): Uint8Array {
  return Uint8Array.from(Buffer.from(b64, 'base64'));
}