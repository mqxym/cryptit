// packages/core/src/stream/StreamProcessor.ts
import { EncryptTransform } from './EncryptTransform.js';
import { DecryptTransform } from './DecryptTransform.js';
import type { EncryptionAlgorithm } from '../types/index.js';

export class StreamProcessor {
  constructor(
    private readonly engine: EncryptionAlgorithm,
    private readonly chunkSize = 512 * 1024,
  ) {}

  encryptionStream(): TransformStream<Uint8Array, Uint8Array> {
    const enc = new EncryptTransform(this.engine, this.chunkSize)
                  .toTransformStream();
    return {
      writable: enc.writable,
      readable: enc.readable,
    } as TransformStream<Uint8Array, Uint8Array>;
  }

  decryptionStream(headerLen: number): TransformStream<Uint8Array, Uint8Array> {
    let skip = headerLen;
    const strip = new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, ctl) {
        if (skip === 0) {
          ctl.enqueue(chunk);
          return;
        }
        if (chunk.byteLength <= skip) {
          skip -= chunk.byteLength;
          return;
        }
        ctl.enqueue(chunk.slice(skip));
        skip = 0;
      },
    });

    const decryptTs = new DecryptTransform(this.engine, this.chunkSize)
                        .toTransformStream();

    return {
      writable: strip.writable,
      readable: strip.readable.pipeThrough(decryptTs),
    } as TransformStream<Uint8Array, Uint8Array>;
  }

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