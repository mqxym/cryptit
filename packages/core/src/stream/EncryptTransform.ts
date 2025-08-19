// packages/core/src/stream/EncryptTransform.ts
import type { EncryptionAlgorithm } from '../types/index.js';
import { ensureUint8Array } from '../util/convert.js';
import { encodeFrameLen, FRAME_HEADER_BYTES } from '../util/frame.js';

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
          await ensureUint8Array(chunk),
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
    const HARD_LIMIT = 64 * 1024 * 1024; // 64 MiB safety
    if (bytes.length > Math.min(this.chunkSize * 4, HARD_LIMIT)) {
      throw new RangeError(
        `Input block (${bytes.length} B) exceeds maximum allowed ` +
        `${Math.min(this.chunkSize * 4, HARD_LIMIT)} B`,
      );
    }
    const combined = new Uint8Array(this.buffer.length + bytes.length);
    combined.set(this.buffer);
    combined.set(bytes, this.buffer.length);

    let offset = 0;
    while (combined.length - offset >= this.chunkSize) {
      const block = combined.slice(offset, offset + this.chunkSize);
      offset += this.chunkSize;

      const encrypted = await this.engine.encryptChunk(block);
      const out = new Uint8Array(FRAME_HEADER_BYTES + encrypted.length);
      out.set(encodeFrameLen(encrypted.length));
      out.set(encrypted, FRAME_HEADER_BYTES);
      ctl.enqueue(out);
    
    }

    this.buffer = combined.slice(offset);
  }

  private async flush(ctl: TransformStreamDefaultController<Uint8Array>) {
    if (!this.buffer.length) return;
    const encrypted = await this.engine.encryptChunk(this.buffer);

    const out = new Uint8Array(FRAME_HEADER_BYTES + encrypted.length);
    out.set(encodeFrameLen(encrypted.length));
    out.set(encrypted, FRAME_HEADER_BYTES);
    ctl.enqueue(out);
    
    this.buffer = new Uint8Array(0);

    this.engine.zeroKey();
  }

}