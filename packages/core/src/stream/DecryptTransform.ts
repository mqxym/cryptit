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
    const combined = new Uint8Array(this.buffer.length + bytes.length);
    combined.set(this.buffer);
    combined.set(bytes, this.buffer.length);

    let offset = 0;
    while (true) {
      if (combined.length - offset < FRAME_HEADER_BYTES) break;
      const record = this.format === 'authenticated-v1'
        ? decodeStreamRecord(combined, offset)
        : { length: decodeFrameLen(combined, offset), terminal: false, word: 0 };
      const cipherLen = record.length;
      const minFrame   = this.engine.IV_LENGTH + this.engine.TAG_LENGTH;

      if (!Number.isInteger(cipherLen) || cipherLen < minFrame || cipherLen > MAX_CIPHER_FRAME_SIZE) {
        ctl.error(new DecryptionError(
          `Invalid frame length ${cipherLen} (min=${minFrame}, max=${MAX_CIPHER_FRAME_SIZE})`
        ));
        return; // IMPORTANT: stop now that the stream is errored
      }
      
      if (combined.length - offset - FRAME_HEADER_BYTES < cipherLen) break;
      if (this.terminalSeen) {
        this.fail(ctl, new DecryptionError('Data found after authenticated stream terminator'));
        return;
      }
      offset += FRAME_HEADER_BYTES;
      const cipher = combined.slice(offset, offset + cipherLen);
      offset += cipherLen;

      try {
        if (this.format === 'authenticated-v1') {
          this.engine.setAAD(buildStreamRecordAAD(
            this.header,
            this.recordIndex,
            record,
          ));
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
      } catch (err) {
        this.fail(ctl,
          err instanceof DecryptionError
            ? err
            : new DecryptionError('Decryption failed: Wrong passphrase or corrupted ciphertext')
        );
        return;
      }
    }

    this.buffer = combined.slice(offset);
  }

  private async flush(ctl: TransformStreamDefaultController<Uint8Array>) {
    try {
      await this.transform(new Uint8Array(0), ctl);
      if (this.failed) return;
      if (this.buffer.byteLength !== 0) {
        this.fail(ctl, new DecryptionError('Truncated ciphertext: incomplete final frame'));
        return;
      }
      if (this.format === 'authenticated-v1' && !this.terminalSeen) {
        this.fail(ctl, new DecryptionError('Truncated ciphertext: missing stream terminator'));
      }
    } finally {
      this.buffer.fill(0);
      this.buffer = new Uint8Array(0);
      this.engine.zeroKey();
    }
  }

  private fail(
    ctl: TransformStreamDefaultController<Uint8Array>,
    error: DecryptionError,
  ): void {
    this.failed = true;
    this.buffer.fill(0);
    this.engine.zeroKey();
    ctl.error(error);
  }
}