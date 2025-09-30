// packages/core/src/stream/DecryptTransform.ts
import type { EncryptionAlgorithm } from '../types/index.js';
import { DecryptionError } from '../errors/index.js';
import { ensureUint8Array } from '../util/convert.js';
import { decodeFrameLen, FRAME_HEADER_BYTES } from '../util/frame.js';

/**
 * Counterpart to EncryptTransform.
 * Streams framed ciphertext → raw plaintext.
 */
export class DecryptTransform {
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
    const combined = new Uint8Array(this.buffer.length + bytes.length);
    combined.set(this.buffer);
    combined.set(bytes, this.buffer.length);

    let offset = 0;
    while (true) {
      if (combined.length - offset < FRAME_HEADER_BYTES) break;
      const cipherLen = decodeFrameLen(combined, offset);
      const HARD_LIMIT = 64 * 1024 * 1024; // 64 MiB
      const minFrame   = this.engine.IV_LENGTH + this.engine.TAG_LENGTH;

      if (!Number.isInteger(cipherLen) || cipherLen < minFrame || cipherLen > HARD_LIMIT) {
        ctl.error(new DecryptionError(
          `Invalid frame length ${cipherLen} (min=${minFrame}, max=${HARD_LIMIT})`
        ));
        return; // IMPORTANT: stop now that the stream is errored
      }
      
      if (combined.length - offset - FRAME_HEADER_BYTES < cipherLen) break;
      offset += FRAME_HEADER_BYTES;
      const cipher = combined.slice(offset, offset + cipherLen);
      offset += cipherLen;

      try {
        const plain = await this.engine.decryptChunk(cipher);
        ctl.enqueue(plain);
      } catch (err) {
        ctl.error(
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
    await this.transform(new Uint8Array(0), ctl);
    const leftover = this.buffer.byteLength;
    this.buffer = new Uint8Array(0);
    this.engine.zeroKey();
    if (leftover !== 0) {
      ctl.error(new DecryptionError('Truncated ciphertext: incomplete final frame'));
      return;
    }
  }
}