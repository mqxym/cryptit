// packages/core/src/stream/DecryptTransform.ts
import type { EncryptionAlgorithm } from '../types/index.js';
import { DecryptionError } from '../errors/index.js';

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
    const combined = new Uint8Array(this.buffer.length + bytes.length);
    combined.set(this.buffer);
    combined.set(bytes, this.buffer.length);

    let offset = 0;
    while (true) {
      if (combined.length - offset < 4) break;
      const cipherLen = new DataView(
        combined.buffer,
        combined.byteOffset + offset,
        4,
      ).getUint32(0, false);
        if (cipherLen > this.chunkSize * 2) {
          throw new DecryptionError(
            `Frame length ${cipherLen} exceeds maximum allowed ${this.chunkSize * 2}`,
          );
        }
      if (combined.length - offset - 4 < cipherLen) break;

      offset += 4;
      const cipher = combined.slice(offset, offset + cipherLen);
      offset += cipherLen;

      try {
        const plain = await this.engine.decryptChunk(cipher);
        ctl.enqueue(plain);
      } catch (err) {
        throw err instanceof DecryptionError
          ? err
         : new DecryptionError(
              'Decryption failed: Wrong passphrase or corrupted ciphertext',
            );
      }
    }

    this.buffer = combined.slice(offset);
  }

  private async flush(ctl: TransformStreamDefaultController<Uint8Array>) {
    await this.transform(new Uint8Array(0), ctl);
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