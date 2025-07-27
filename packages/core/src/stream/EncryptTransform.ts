import type { IEncryptionAlgorithm } from "../types.js";

/**
 * TransformStream that:
 *   • collects plaintext into fixed-size blocks (default 512 KiB)
 *   • encrypts each block via the provided crypto engine
 *   • emits: [4-byte big-endian length ‖ encryptedBlock]
 *
 * Input  types accepted: Uint8Array | ArrayBuffer | Blob
 * Output type:           Uint8Array
 */
export class EncryptTransform {
  private buffer = new Uint8Array(0);

  constructor(
    private readonly engine: IEncryptionAlgorithm,
    private readonly chunkSize = 512 * 1024,
  ) {}

  /** Public factory – keeps callers one-liner-simple */
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
    // concat previous tail + new data
    const combined = new Uint8Array(this.buffer.length + bytes.length);
    combined.set(this.buffer);
    combined.set(bytes, this.buffer.length);

    let offset = 0;
    while (combined.length - offset >= this.chunkSize) {
      const block = combined.slice(offset, offset + this.chunkSize);
      offset += this.chunkSize;

      const encrypted = await this.engine.encryptChunk(block);

      // prepend 4-byte length-header (big-endian)
      const header = new Uint8Array(4);
      new DataView(header.buffer).setUint32(0, encrypted.length, false);

      const out = new Uint8Array(header.length + encrypted.length);
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
    this.buffer = new Uint8Array(0); // GC friendly
  }

  private async asUint8Array(
    input: Uint8Array | ArrayBuffer | Blob,
  ): Promise<Uint8Array> {
    if (input instanceof Uint8Array) return input;
    if (input instanceof ArrayBuffer) return new Uint8Array(input);
    // Blob
    return new Uint8Array(await input.arrayBuffer());
  }
}