// packages/core/src/stream/EncryptTransform.ts
import type { EncryptionAlgorithm } from '../types/index.js';

/**
 * TransformStream that:
 *   • collects plaintext into fixed‐size blocks
 *   • encrypts each block
 *   • emits: [4-byte length ‖ encryptedBlock]
 */
export class EncryptTransform {
  private buffer = new Uint8Array(0);

  constructor(
    private readonly engine: EncryptionAlgorithm,
    private readonly chunkSize = 512 * 1024,
  ) {}

  toTransformStream(): TransformStream<Uint8Array | ArrayBuffer | Blob, Uint8Array> {
    return new TransformStream({
      transform: async (chunk, ctl) => {
        await this.transform(
          await this.asUint8Array(chunk),
          ctl,
        );
      },
      flush: async ctl => this.flush(ctl),
    });
  }

  private async transform(
    bytes: Uint8Array,
    ctl: TransformStreamDefaultController<Uint8Array>,
  ) {
    if (bytes.length > this.chunkSize * 4) {
      throw new RangeError(`Input block (${bytes.length} B) exceeds sane limit`);
    }
    const combined = new Uint8Array(this.buffer.length + bytes.length);
    combined.set(this.buffer);
    combined.set(bytes, this.buffer.length);

    let offset = 0;
    while (combined.length - offset >= this.chunkSize) {
      const block = combined.slice(offset, offset + this.chunkSize);
      offset += this.chunkSize;

      const encrypted = await this.engine.encryptChunk(block);

      const header = new Uint8Array(4);
      new DataView(header.buffer).setUint32(0, encrypted.length, false);

      const out = new Uint8Array(4 + encrypted.length);
      out.set(header);
      out.set(encrypted, header.length);

      ctl.enqueue(out);
    }

    this.buffer = combined.slice(offset);
  }

  private async flush(ctl: TransformStreamDefaultController<Uint8Array>) {
    if (!this.buffer.length) return;
    const encrypted = await this.engine.encryptChunk(this.buffer);

    const header = new Uint8Array(4);
    new DataView(header.buffer).setUint32(0, encrypted.length, false);

    const out = new Uint8Array(4 + encrypted.length);
    out.set(header);
    out.set(encrypted, 4);

    ctl.enqueue(out);
    this.buffer = new Uint8Array(0);
  }

  private async asUint8Array(
    input: Uint8Array | ArrayBuffer | Blob,
  ): Promise<Uint8Array> {
    if (input instanceof Uint8Array) return input;
    if (input instanceof ArrayBuffer) return new Uint8Array(input);
    return new Uint8Array(await input.arrayBuffer());
  }
}