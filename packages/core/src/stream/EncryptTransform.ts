// packages/core/src/stream/EncryptTransform.ts
import type { EncryptionAlgorithm } from '../types/index.js';
import { ensureUint8Array } from '../util/convert.js';
import {
  buildStreamRecordAAD,
  encodeFrameLen,
  encodeStreamRecord,
  FRAME_HEADER_BYTES,
  MAX_STREAM_WRITE_SIZE,
  type StreamFormat,
} from '../util/frame.js';

export interface EncryptTransformOptions {
  format?: StreamFormat;
  header?: Uint8Array;
}

/**
 * TransformStream that:
 *   • collects plaintext into fixed‐size blocks
 *   • encrypts each block
 *   • emits: [4-byte length ‖ encryptedBlock]
 *
 * Back-pressure / sizing contract:
 *   A single write must not exceed `min(chunkSize * 4, 64 MiB)`. Larger writes
 *   throw a {@link RangeError} synchronously from `transform()` rather than being
 *   buffered, to bound peak memory. Callers streaming big payloads should write
 *   in chunks at or below this limit (the surrounding pipeline already does so).
 */
export class EncryptTransform {
  private buffer = new Uint8Array(0);
  private recordIndex = 0n;
  private readonly format: StreamFormat;
  private readonly header: Uint8Array;

  constructor(
    private readonly engine: EncryptionAlgorithm,
    private readonly chunkSize = 512 * 1024,
    options: EncryptTransformOptions = {},
  ) {
    this.format = options.format ?? 'legacy';
    this.header = options.header?.slice() ?? new Uint8Array(0);
    if (this.format === 'authenticated-v1' && this.header.length === 0) {
      throw new Error('Authenticated stream encryption requires the encoded header');
    }
  }

  toTransformStream(): TransformStream<Uint8Array | ArrayBuffer | Blob, Uint8Array> {
    return new TransformStream({
      transform: async (chunk, ctl) => {
        try {
          await this.transform(
            await ensureUint8Array(chunk),
            ctl,
          );
        } catch (err) {
          this.buffer.fill(0);
          this.buffer = new Uint8Array(0);
          this.engine.zeroKey();
          throw err;
        }
      },
      flush: async ctl => this.flush(ctl),
    });
  }

  private async transform(
    bytes: Uint8Array,
    ctl: TransformStreamDefaultController<Uint8Array>,
  ) {
    // Per-write cap: reject anything larger than min(chunkSize*4, 64 MiB) so a
    // single oversized write cannot blow up peak memory (see class docs).
    if (bytes.length > Math.min(this.chunkSize * 4, MAX_STREAM_WRITE_SIZE)) {
      throw new RangeError(
        `Input block (${bytes.length} B) exceeds maximum allowed ` +
        `${Math.min(this.chunkSize * 4, MAX_STREAM_WRITE_SIZE)} B`,
      );
    }
    const combined = new Uint8Array(this.buffer.length + bytes.length);
    combined.set(this.buffer);
    combined.set(bytes, this.buffer.length);

    let offset = 0;
    while (combined.length - offset >= this.chunkSize) {
      const block = combined.slice(offset, offset + this.chunkSize);
      offset += this.chunkSize;

      await this.emitRecord(block, false, ctl);
    
    }

    this.buffer = combined.slice(offset);
  }

  private async flush(ctl: TransformStreamDefaultController<Uint8Array>) {
    try {
      if (this.buffer.length) await this.emitRecord(this.buffer, false, ctl);
      if (this.format === 'authenticated-v1') {
        await this.emitRecord(new Uint8Array(0), true, ctl);
      }
    } finally {
      this.buffer.fill(0);
      this.buffer = new Uint8Array(0);
      this.engine.zeroKey();
    }
  }

  private async emitRecord(
    plain: Uint8Array,
    terminal: boolean,
    ctl: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    let expectedLength: number | null = null;
    let frame: Uint8Array;

    if (this.format === 'authenticated-v1') {
      expectedLength = this.engine.IV_LENGTH + plain.length + this.engine.TAG_LENGTH;
      frame = encodeStreamRecord(expectedLength, terminal);
      const word = new DataView(frame.buffer, frame.byteOffset, frame.byteLength)
        .getUint32(0, false);
      this.engine.setAAD(buildStreamRecordAAD(this.header, this.recordIndex, { terminal, word }));
    } else {
      frame = new Uint8Array(0);
    }

    const encrypted = await this.engine.encryptChunk(plain);
    if (expectedLength !== null && encrypted.length !== expectedLength) {
      encrypted.fill(0);
      throw new Error(`Cipher produced ${encrypted.length} bytes; expected ${expectedLength}`);
    }
    if (this.format === 'legacy') frame = encodeFrameLen(encrypted.length);

    const output = new Uint8Array(FRAME_HEADER_BYTES + encrypted.length);
    output.set(frame, 0);
    output.set(encrypted, FRAME_HEADER_BYTES);
    ctl.enqueue(output);
    this.recordIndex++;
  }

}