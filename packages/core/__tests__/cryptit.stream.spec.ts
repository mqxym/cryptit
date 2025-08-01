import { Cryptit }      from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

async function collect(rs: ReadableStream<Uint8Array>) {
  const reader = rs.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return Uint8Array.from(parts.flatMap(v => [...v]));
}
/*
describe('Cryptit streaming API', () => {
  const crypt = new Cryptit(nodeProvider, { chunkSize: 256 });

  it('pipes through encrypt→decrypt streams', async () => {
    const plain = crypto.getRandomValues(new Uint8Array(65_000));

    // encrypt
    const { header, writable, readable } =
      await crypt.createEncryptionStream('pw');

    const w1 = writable.getWriter();
    w1.write(plain.slice(0, 32_000));
    w1.write(plain.slice(32_000));
    w1.close();
    
    const cipher = Uint8Array.from(
      await collect(new ReadableStream({
        start(c) { c.enqueue(header); c.close(); },
      }).pipeThrough(
        new TransformStream({ transform: (_, ctl) { ctl.enqueue(header); } })
      )),
    ).concat(await collect(readable));

    // decrypt
    const decStream = await crypt.createDecryptionStream('pw');
    const rsPlain   = new ReadableStream({
      start(c) { c.enqueue(cipher); c.close(); },
    }).pipeThrough(decStream);

    const roundtrip = await collect(rsPlain);
    expect(roundtrip).toEqual(plain);
  });
});
*/