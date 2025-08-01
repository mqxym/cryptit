import { EncryptTransform } from '../src/stream/EncryptTransform.js';
import { DecryptTransform } from '../src/stream/DecryptTransform.js';
import type { EncryptionAlgorithm } from '../src/types/index.js';

class EchoEngine implements EncryptionAlgorithm {
  async encryptChunk(p: Uint8Array) { return p; }
  async decryptChunk(c: Uint8Array) { return c; }
}

async function collect<T extends Uint8Array>(rs: ReadableStream<T>) {
  const r = rs.getReader();
  const chunks: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await r.read();
    if (done) break;
    chunks.push(value);
  }
  return Uint8Array.from(chunks.flatMap(c => [...c]));
}

describe('Encrypt/Decrypt Transform framing', () => {
  const engine = new EchoEngine();
  const plain  = new Uint8Array(10_000).map((_, i) => i & 0xFF);

  it('frames and deframes with default 512 k chunks', async () => {
    const enc = new EncryptTransform(engine).toTransformStream();
    const dec = new DecryptTransform(engine).toTransformStream();

    const cipher = await collect(
      new ReadableStream({
        pull(c) { c.enqueue(plain); c.close(); },
      }).pipeThrough(enc),
    );

    const roundtrip = await collect(
      new ReadableStream({
        pull(c) { c.enqueue(cipher); c.close(); },
      }).pipeThrough(dec),
    );

    expect(roundtrip).toEqual(plain);
  });
});