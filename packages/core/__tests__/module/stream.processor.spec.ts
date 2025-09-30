import { StreamProcessor }      from '../../src/stream/StreamProcessor.js';
import type { EncryptionAlgorithm } from '../../src/types/index.js';

class FakeEngine implements EncryptionAlgorithm {
  async encryptChunk(p: Uint8Array) {
    return Uint8Array.from(p, v => (v + 1) & 0xFF);
  }
  async decryptChunk(c: Uint8Array) {
    return Uint8Array.from(c, v => (v - 1) & 0xFF);
  }
  async setKey(k: CryptoKey): Promise<void> { }
  zeroKey(): void { }
  IV_LENGTH: number;
}

describe('StreamProcessor.collect', () => {
  it('collects with prefix', async () => {
    const engine = new FakeEngine();
    const sp     = new StreamProcessor(engine, 8);

    const plain  = new Uint8Array([1, 2, 3, 4]);
    const rs     = new ReadableStream({
      start(c) { c.enqueue(plain); c.close(); },
    });

    const enc = await sp.collect(
      rs,
      sp.encryptionStream(),
      new Uint8Array([9]),
    );
    // first byte is prefix
    expect(enc[0]).toBe(9);

    const dec = await sp.collect(
      new ReadableStream({
        start(c) { c.enqueue(enc.slice(1)); c.close(); },
      }),
      sp.decryptionStream(0),
    );
    expect(dec).toEqual(plain);
  });

  it('decryptionStream strips header across chunk boundaries', async () => {
    // This ensures the header split across two chunks is correctly skipped.
    const engine = new FakeEngine();
    const sp     = new StreamProcessor(engine, 8);

    // Construct header (9 bytes) and ciphertext (encoded as one frame)
    const header = new Uint8Array([1,2,3,4,5,6,7,8,9]);
    const cipher = new Uint8Array([0,0,0,4,  11,12,13,14]); // frame 4 bytes + 4 payload

    const rs = new ReadableStream({
      start(c) {
        c.enqueue(header.slice(0, 4)); // header split
        c.enqueue(header.slice(4));
        c.enqueue(cipher);
        c.close();
      }
    });

    const out = await sp.collect(rs, sp.decryptionStream(header.length));
    expect(out.byteLength).toBe(4);
  });
});