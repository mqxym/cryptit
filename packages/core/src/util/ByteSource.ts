// packages/core/src/util/ByteSource.ts
import { base64Decode } from './bytes.js';

/**
 * Unified, zero‑copy accessor for Blob | Uint8Array | Base64‑encoded string.
 * Slices are read on‑demand so even multi‑gigabyte Blobs are handled
 * without loading them fully into memory.
 */
export class ByteSource {
  #buf: Uint8Array | null = null;

  constructor(private readonly src: Blob | Uint8Array | string) {}

  /** Total byte length of the underlying data */
  get length(): number {
    if (this.src instanceof Uint8Array) return this.src.byteLength;
    if (this.src instanceof Blob)      return this.src.size;
    /* string (Base64) */
    return this.ensureUint8().byteLength;
  }

  /**
   * Read a slice *[offset, offset + len)* as Uint8Array.
   * The returned view is a fresh copy — safe to mutate by caller.
   */
  async read(offset: number, len: number): Promise<Uint8Array> {
    if (offset < 0 || len < 0 || offset + len > this.length) {
      throw new RangeError('read() slice exceeds data bounds');
    }

    // Uint8Array path – cheapest
    if (this.src instanceof Uint8Array) {
      return this.src.slice(offset, offset + len);
    }

    // Blob path – use slice() + arrayBuffer()
    if (this.src instanceof Blob) {
      const buf = await this.src.slice(offset, offset + len).arrayBuffer();
      return new Uint8Array(buf);
    }

    // Base64 text path – decode once then reuse
    return this.ensureUint8().slice(offset, offset + len);
  }

  /* ------------------------------------------------------------------ */
  /*  Internals                                                          */
  /* ------------------------------------------------------------------ */

  /** lazily decode Base64 text into a Uint8Array (once) */
  private ensureUint8(): Uint8Array {
    if (!this.#buf) {
      this.#buf = base64Decode(this.src as string);
    }
    return this.#buf;
  }
}