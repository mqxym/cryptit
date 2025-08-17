// packages/core/src/stream/StreamProcessor.ts
import { EncryptTransform } from './EncryptTransform.js';
import { DecryptTransform } from './DecryptTransform.js';
import type { EncryptionAlgorithm } from '../types/index.js';
import { collectStream } from '../util/stream.js';

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
   return collectStream(readable.pipeThrough(transform), prefix ?? undefined);
  }
}