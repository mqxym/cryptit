/* ------------------------------------------------------------------
   EncryptTransform – defensive limits
   ------------------------------------------------------------------ */
import { EncryptTransform }   from '../../src/stream/EncryptTransform.js';
import type { EncryptionAlgorithm } from '../../src/types/index.js';
import { collectStream }      from '../../src/util/stream.js';

class NopEngine implements EncryptionAlgorithm {
  async encryptChunk(p: Uint8Array) { return p; }
  async decryptChunk(c: Uint8Array) { return c; }
  async setKey() {}
  zeroKey() {}
  readonly IV_LENGTH = 0;
  readonly TAG_LENGTH = 0;
  setAAD(aadData: Uint8Array): void {}
}

describe('EncryptTransform upper-bound check', () => {
  it('rejects a block larger than 4xchunkSize', async () => {
    const chunkSize = 1_024;
    const big       = new Uint8Array(chunkSize * 4 + 1);
    const encTs     = new EncryptTransform(new NopEngine(), chunkSize)
                        .toTransformStream();

    const rs = new ReadableStream({ start(c) { c.enqueue(big); c.close(); } });
    await expect(collectStream(rs.pipeThrough(encTs)))
      .rejects.toThrow(RangeError);
  });
});