import { DecryptTransform } from '../../src/stream/DecryptTransform.js';
import type { EncryptionAlgorithm } from '../../src/types/index.js';
import { DecryptionError } from '../../src/errors/index.js';
import { collectStream as collect } from '../../src/util/stream.js';

/*  Naïve “no-op” engine - just echoes data back  */
class NopEngine implements EncryptionAlgorithm {
  async encryptChunk(p: Uint8Array) { return p; }
  async decryptChunk(c: Uint8Array) { return c; }
  async setKey() {}
  zeroKey() {}
  // Use nonzero IV/TAG so we can meaningfully test "min frame length".
  readonly IV_LENGTH = 12;
  readonly TAG_LENGTH = 16;
  setAAD(aadData: Uint8Array): void {}
}

describe('DecryptTransform  frame-length guard-rails', () => {
  it('throws DecryptionError when declared frame length exceeds hard cap', async () => {
    const engine = new NopEngine();
    const ts = new DecryptTransform(engine, 8).toTransformStream();

    const HARD_CAP_PLUS_ONE = 64 * 1024 * 1024 + 1; // 64 MiB + 1
    const hdr = new Uint8Array(4);
    new DataView(hdr.buffer).setUint32(0, HARD_CAP_PLUS_ONE, false); // big-endian

    const rs = new ReadableStream({ start(c) { c.enqueue(hdr); c.close(); } });
    await expect(collect(rs.pipeThrough(ts))).rejects.toThrow(DecryptionError);
  });

  it('throws DecryptionError when declared frame length is below IV+TAG minimum', async () => {
    const engine = new NopEngine();
    const ts = new DecryptTransform(engine, 8).toTransformStream();

    const belowMin = engine.IV_LENGTH + engine.TAG_LENGTH - 1; // 27
    const hdr = new Uint8Array(4);
    new DataView(hdr.buffer).setUint32(0, belowMin, false);

    const rs = new ReadableStream({ start(c) { c.enqueue(hdr); c.close(); } });
    await expect(collect(rs.pipeThrough(ts))).rejects.toThrow(DecryptionError);
  });

  it('throws DecryptionError on truncated ciphertext (incomplete final frame)', async () => {
    const engine = new NopEngine();
    const ts = new DecryptTransform(engine, 8).toTransformStream();

    const declared = engine.IV_LENGTH + engine.TAG_LENGTH; // minimal valid payload size
    const buf = new Uint8Array(4 + (declared - 1)); // intentionally 1 byte short
    new DataView(buf.buffer).setUint32(0, declared, false);

    const rs = new ReadableStream({ start(c) { c.enqueue(buf); c.close(); } });
    await expect(collect(rs.pipeThrough(ts))).rejects.toThrow(DecryptionError);
  });
});