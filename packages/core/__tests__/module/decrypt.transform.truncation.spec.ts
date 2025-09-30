import { DecryptTransform } from '../../src/stream/DecryptTransform.js';
import { encodeFrameLen } from '../../src/util/frame.js';
import { collectStream as collect } from '../../src/util/stream.js';
import { DecryptionError } from '../../src/errors/index.js';
import type { EncryptionAlgorithm } from '../../src/types/index.js';

class EchoEngine implements EncryptionAlgorithm {
  async encryptChunk(p: Uint8Array) { return p; }
  async decryptChunk(c: Uint8Array) { return c; }
  async setKey() {}
  zeroKey() {}
  readonly IV_LENGTH = 0;
  readonly TAG_LENGTH = 0;
  setAAD(aad: Uint8Array): void {}
}

describe('DecryptTransform - truncated tail detection', () => {
  it('throws DecryptionError on incomplete final frame', async () => {
    const engine = new EchoEngine();
    const ts = new DecryptTransform(engine, 8).toTransformStream();

    // Declare 10 bytes but provide only 7
    const hdr = encodeFrameLen(10);
    const body = new Uint8Array(7).fill(1);
    const truncated = new Uint8Array(hdr.length + body.length);
    truncated.set(hdr, 0);
    truncated.set(body, hdr.length);

    const rs = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(truncated); c.close(); },
    });

    await expect(collect(rs.pipeThrough(ts))).rejects.toThrow(DecryptionError);
  });
});