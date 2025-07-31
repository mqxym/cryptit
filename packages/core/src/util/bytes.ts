import { EncodingError, DecodingError } from "../errors/index.js";

/**
 * Tiny run-time test – are we really in Node/Bun, **not** a browser bundle
 * that merely polyfilled `Buffer`?
 */
function isNodeLike(): boolean {
  return (
    typeof process !== 'undefined' &&
    typeof process.versions === 'object' &&
    // `browserify` & friends set `process.browser = true`
    (process as any).browser !== true
  );
}

/* ------------------------------------------------------------------ */

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

/* ----------  Base64 encode  --------------------------------------- */
export function base64Encode(...chunks: Uint8Array[]): string {
  try {
    const data = concat(...chunks);

    if (isNodeLike()) {
      // genuine Node / Bun
      return (Buffer as any).from(data).toString('base64');
    }

    // Browser (skip any injected Buffer polyfill)
    let binary = '';
    for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
    return btoa(binary);
  } catch (err: any) {
    const msg = "Base64 Enconding Error";
    throw new EncodingError(msg);
  }
  
}

/* ----------  Base64 decode  --------------------------------------- */
export function base64Decode(b64: string): Uint8Array {
  try {
    if (isNodeLike()) {
      return new Uint8Array((Buffer as any).from(b64, 'base64'));
    }

    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch (err: any) {
    const msg = "Base64 Decoding Error";
    throw new DecodingError(msg);
  }
  
}