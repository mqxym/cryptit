import { DecryptTransform } from '../src/stream/DecryptTransform.js';
import type { EncryptionAlgorithm } from '../src/types/index.js';
import { DecryptionError } from '../src/errors/index.js';

/*  Naïve “no-op” engine - just echoes data back  */
class NopEngine implements EncryptionAlgorithm {
  async encryptChunk(p: Uint8Array) { return p; }
  async decryptChunk(c: Uint8Array) { return c; }
  async setKey() {}
}

async function collect(rs: ReadableStream<Uint8Array>) {
  const r = rs.getReader(); const parts: Uint8Array[] = [];
  for (;;) { const { done, value } = await r.read(); if (done) break; parts.push(value); }
  return Uint8Array.from(parts.flatMap(b => [...b]));
}

describe('DecryptTransform  frame-length guard-rails', () => {
  it('throws DecryptionError when declared frame length exceeds **2: chunkSize**', async () => {
    const engine = new NopEngine();
    const ts = new DecryptTransform(engine, 8).toTransformStream();   // ⇒ limit = 16 bytes

    /* Craft an invalid frame: header = 20 bytes ( > 16 ) */
    const bogus = new Uint8Array(4 + 20);
    new DataView(bogus.buffer).setUint32(0, 20, false);

    const rs = new ReadableStream({ start(c) { c.enqueue(bogus); c.close(); } });

    await expect(collect(rs.pipeThrough(ts))).rejects.toThrow(DecryptionError);
  });
});