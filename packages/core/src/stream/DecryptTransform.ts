import type { IEncryptionAlgorithm } from "../types.js";

/**
 * Counterpart to EncryptTransform.
 * Accepts the framed ciphertext and streams out raw plaintext.
 *
 * Emits Uint8Array chunks identical to the original plaintext
 * (except block boundaries aren’t guaranteed to match).
 */
export class DecryptTransform {
  private buffer = new Uint8Array(0);

  constructor(
    private readonly engine: IEncryptionAlgorithm,
    private readonly chunkSize = 512 * 1024,
  ) {}

  toTransformStream(): TransformStream<
    Uint8Array | ArrayBuffer | Blob,
    Uint8Array
  > {
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

  // --------------------------------------------------------------------------

  private async transform(
    bytes: Uint8Array,
    ctl: TransformStreamDefaultController<Uint8Array>,
  ) {
    const combined = new Uint8Array(this.buffer.length + bytes.length);
    combined.set(this.buffer);
    combined.set(bytes, this.buffer.length);

    let offset = 0;
    while (true) {
      if (combined.length - offset < 4) break; // not enough for header

      const cipherLen = new DataView(
        combined.buffer,
        combined.byteOffset + offset,
        4,
      ).getUint32(0, false);
      if (combined.length - offset - 4 < cipherLen) break; // incomplete

      offset += 4;
      const cipher = combined.slice(offset, offset + cipherLen);
      offset += cipherLen;

      const plain = await this.engine.decryptChunk(cipher);
      ctl.enqueue(plain);
    }

    this.buffer = combined.slice(offset);
  }

  private async flush(ctl: TransformStreamDefaultController<Uint8Array>) {
    await this.transform(new Uint8Array(0), ctl); // process any tail
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