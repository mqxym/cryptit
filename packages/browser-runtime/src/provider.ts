// packages/browser-runtime/src/provider.ts
import type { CryptoProvider } from "../../core/src/providers/CryptoProvider.js";

function asArrayBufferBacked(buf: Uint8Array): Uint8Array<ArrayBuffer> {
  if (buf.buffer instanceof ArrayBuffer) {
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  const copy = new Uint8Array(buf.byteLength);
  copy.set(buf);
  return copy;
}

/**
 * Crypto shim for modern browsers (and Bun when used in “browser” code-paths).
 */
export const browserProvider: CryptoProvider = {
  subtle: globalThis.crypto.subtle,
  getRandomValues(buf: Uint8Array): Uint8Array {
    const view = asArrayBufferBacked(buf);
    globalThis.crypto.getRandomValues(view);

    // If we had to copy, copy back so caller still gets its original buffer populated.
    if (view !== buf) buf.set(view);

    return buf;
  },
  isNode: false,
};