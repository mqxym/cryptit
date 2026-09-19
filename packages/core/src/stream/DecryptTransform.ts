// packages/core/src/stream/DecryptTransform.ts
import type { EncryptionAlgorithm } from '../types/index.js';
import { DecryptionError } from '../errors/index.js';
import { ensureUint8Array } from '../util/convert.js';
import {
  buildStreamRecordAAD,
  decodeFrameLen,
  decodeStreamRecord,
  FRAME_HEADER_BYTES,
  MAX_CIPHER_FRAME_SIZE,
  type StreamFormat,
} from '../util/frame.js';

export interface DecryptTransformOptions {
  format?: StreamFormat;
  header?: Uint8Array;
}

/**
 * Counterpart to EncryptTransform.
 * Streams framed ciphertext → raw plaintext.
 */
export class DecryptTransform {
  private buffer = new Uint8Array(0);
  private bufferedLength = 0;
  private bufferedFrameLength: number | null = null;
  private recordIndex = 0n;
  private terminalSeen = false;
  private failed = false;
  private readonly format: StreamFormat;
  private readonly header: Uint8Array;

  constructor(
    private readonly engine: EncryptionAlgorithm,
    private readonly chunkSize = 512 * 1024,
    options: DecryptTransformOptions = {},
  ) {
    this.format = options.format ?? 'legacy';
    this.header = options.header?.slice() ?? new Uint8Array(0);
    if (this.format === 'authenticated-v1' && this.header.length === 0) {
      throw new Error('Authenticated stream decryption requires the encoded header');
    }
  }

  toTransformStream(): TransformStream<Uint8Array | ArrayBuffer | Blob, Uint8Array> {
    return new TransformStream({
      transform: async (chunk, ctl) => {
        try {
          await this.transform(await ensureUint8Array(chunk), ctl);
        } catch (err) {
          if (!this.failed) this.fail(ctl, this.asDecryptionError(err));
        }
      },
      flush: async ctl => this.flush(ctl),
    });
  }

  private async transform(
    bytes: Uint8Array,
    ctl: TransformStreamDefaultController<Uint8Array>,
  ) {
    let offset = 0;

    if (this.bufferedLength > 0) {
      if (this.bufferedFrameLength === null) {
        const take = Math.min(
          FRAME_HEADER_BYTES - this.bufferedLength,
          bytes.length - offset,
        );
        this.appendToBuffer(bytes.subarray(offset, offset + take));
        offset += take;
        if (this.bufferedLength < FRAME_HEADER_BYTES) return;

        const record = this.readRecord(this.buffer, 0);
        this.bufferedFrameLength = FRAME_HEADER_BYTES + record.length;
      }

      const take = Math.min(
        this.bufferedFrameLength - this.bufferedLength,
        bytes.length - offset,
      );
      this.appendToBuffer(bytes.subarray(offset, offset + take));
      offset += take;
      if (this.bufferedLength < this.bufferedFrameLength) return;

      if (this.terminalSeen) {
        throw new DecryptionError('Data found after authenticated stream terminator');
      }

      const buffered = this.buffer;
      const record = this.readRecord(buffered, 0);
      this.resetBuffer();
      await this.decryptRecord(
        record,
        buffered.subarray(FRAME_HEADER_BYTES, FRAME_HEADER_BYTES + record.length),
        ctl,
      );
    }

    while (offset < bytes.length) {
      if (this.terminalSeen) {
        throw new DecryptionError('Data found after authenticated stream terminator');
      }

      const remaining = bytes.length - offset;
      if (remaining < FRAME_HEADER_BYTES) {
        this.stashPartial(bytes.subarray(offset), null);
        return;
      }

      const record = this.readRecord(bytes, offset);
      const frameLength = FRAME_HEADER_BYTES + record.length;
      if (remaining < frameLength) {
        this.stashPartial(bytes.subarray(offset), frameLength);
        return;
      }

      await this.decryptRecord(
        record,
        bytes.subarray(offset + FRAME_HEADER_BYTES, offset + frameLength),
        ctl,
      );
      offset += frameLength;
    }
  }

  private async flush(ctl: TransformStreamDefaultController<Uint8Array>) {
    try {
      await this.transform(new Uint8Array(0), ctl);
      if (this.failed) return;
      if (this.bufferedLength !== 0) {
        this.fail(ctl, new DecryptionError('Truncated ciphertext: incomplete final frame'));
        return;
      }
      if (this.format === 'authenticated-v1' && !this.terminalSeen) {
        this.fail(ctl, new DecryptionError('Truncated ciphertext: missing stream terminator'));
      }
    } finally {
      this.clearBuffer();
      this.engine.zeroKey();
    }
  }

  private readRecord(buf: Uint8Array, offset: number) {
    const record = this.format === 'authenticated-v1'
      ? decodeStreamRecord(buf, offset)
      : { length: decodeFrameLen(buf, offset), terminal: false, word: 0 };
    const minFrame = this.engine.IV_LENGTH + this.engine.TAG_LENGTH;
    if (record.length < minFrame || record.length > MAX_CIPHER_FRAME_SIZE) {
      throw new DecryptionError(
        `Invalid frame length ${record.length} (min=${minFrame}, max=${MAX_CIPHER_FRAME_SIZE})`,
      );
    }
    return record;
  }

  private async decryptRecord(
    record: ReturnType<DecryptTransform['readRecord']>,
    cipher: Uint8Array,
    ctl: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    if (this.format === 'authenticated-v1') {
      this.engine.setAAD(buildStreamRecordAAD(this.header, this.recordIndex, record));
    }
    const plain = await this.engine.decryptChunk(cipher);
    if (record.terminal) {
      if (plain.length !== 0) {
        plain.fill(0);
        throw new DecryptionError('Authenticated stream terminator is not empty');
      }
      this.terminalSeen = true;
    } else {
      ctl.enqueue(plain);
    }
    this.recordIndex++;
  }

  private appendToBuffer(bytes: Uint8Array): void {
    if (bytes.length === 0) return;
    const required = this.bufferedLength + bytes.length;
    if (required > FRAME_HEADER_BYTES + MAX_CIPHER_FRAME_SIZE) {
      throw new DecryptionError('Buffered ciphertext exceeds maximum frame size');
    }
    if (required > this.buffer.length) {
      const limit = this.bufferedFrameLength ?? FRAME_HEADER_BYTES;
      const capacity = Math.min(limit, Math.max(required, this.buffer.length * 2));
      const next = new Uint8Array(capacity);
      next.set(this.buffer.subarray(0, this.bufferedLength));
      this.buffer.fill(0);
      this.buffer = next;
    }
    this.buffer.set(bytes, this.bufferedLength);
    this.bufferedLength = required;
  }

  private stashPartial(bytes: Uint8Array, frameLength: number | null): void {
    this.clearBuffer();
    this.buffer = bytes.slice();
    this.bufferedLength = bytes.length;
    this.bufferedFrameLength = frameLength;
  }

  private resetBuffer(): void {
    this.buffer = new Uint8Array(0);
    this.bufferedLength = 0;
    this.bufferedFrameLength = null;
  }

  private clearBuffer(): void {
    this.buffer.fill(0);
    this.resetBuffer();
  }

  private asDecryptionError(err: unknown): DecryptionError {
    return err instanceof DecryptionError
      ? err
      : new DecryptionError('Decryption failed: Wrong passphrase or corrupted ciphertext');
  }

  private fail(
    ctl: TransformStreamDefaultController<Uint8Array>,
    error: DecryptionError,
  ): void {
    this.failed = true;
    this.clearBuffer();
    this.engine.zeroKey();
    ctl.error(error);
  }
}