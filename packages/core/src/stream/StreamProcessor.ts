// packages/core/src/stream/StreamProcessor.ts
import { EncryptTransform }  from "./EncryptTransform.js";
import { DecryptTransform }  from "./DecryptTransform.js";
import type { IEncryptionAlgorithm } from "../types.js";

export class StreamProcessor {
  constructor(
    private readonly engine: IEncryptionAlgorithm,
    private readonly chunkSize = 512 * 1024,
  ) {}

  // ─────────────────────────────────────────────────────────────
  //  Encrypt: prepend header once, then run EncryptTransform
  // ─────────────────────────────────────────────────────────────
  encryptionStream(header: Uint8Array): TransformStream<Uint8Array, Uint8Array> {
    let pushed = false;
    const prepend = new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, ctl) {
        if (!pushed) {
          ctl.enqueue(header);
          pushed = true;
        }
        ctl.enqueue(chunk);
      },
    });

    const encrypted = new EncryptTransform(this.engine, this.chunkSize)
      .toTransformStream();

    /* .readable → pipeThrough → returns ReadableStream
       Cast back to TransformStream so callers can use it with
       Readable.pipeThrough(transform). */
    return {
  writable: prepend.writable,          // upstream entry
  readable: prepend.readable
              .pipeThrough(encrypted),    // downstream exit
} as unknown as TransformStream<Uint8Array, Uint8Array>;
  }

  // ─────────────────────────────────────────────────────────────
  //  Decrypt: strip header bytes first, then run DecryptTransform
  // ─────────────────────────────────────────────────────────────
  decryptionStream(headerLen: number): TransformStream<Uint8Array, Uint8Array> {
    let skip = headerLen;
    const strip = new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, ctl) {
        if (skip === 0) {
          ctl.enqueue(chunk);
          return;
        }
        if (chunk.byteLength <= skip) {
          skip -= chunk.byteLength;      // still inside header
          return;
        }
        ctl.enqueue(chunk.slice(skip));
        skip = 0;
      },
    });

    const decrypted = new DecryptTransform(this.engine, this.chunkSize)
      .toTransformStream();

    return {
  writable: strip.writable,
  readable: strip.readable
              .pipeThrough(decrypted),
} as unknown as TransformStream<Uint8Array, Uint8Array>;
  }

  // ─────────────────────────────────────────────────────────────
  //  Helper that collects a full stream into a single Uint8Array
  // ─────────────────────────────────────────────────────────────
  async collect(
    readable: ReadableStream<Uint8Array>,
    transform: TransformStream<Uint8Array, Uint8Array>,
    prefix: Uint8Array | null = null,
  ): Promise<Uint8Array> {
    const reader = readable.pipeThrough(transform).getReader();
    const chunks: Uint8Array[] = [];
    if (prefix?.length) chunks.push(prefix);

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
    }

    const total = chunks.reduce((n, c) => n + c.byteLength, 0);
    const out   = new Uint8Array(total);
    let offset  = 0;
    for (const c of chunks) {
      out.set(c, offset);
      offset += c.byteLength;
    }
    return out;
  }
}