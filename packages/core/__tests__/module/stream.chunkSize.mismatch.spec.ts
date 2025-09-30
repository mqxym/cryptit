import { Cryptit } from '../../src/index.js';
import { nodeProvider } from '../../../node-runtime/src/provider.js';
import { collectStream as collect } from '../../src/util/stream.js';

describe('Streaming decrypt tolerates writer chunkSize != reader chunkSize', () => {
  it('decrypts when writer used a larger chunkSize than reader', async () => {
    // Writer with ~1.1 MiB chunks
    const enc = new Cryptit(nodeProvider, { scheme: 0, difficulty: 'low', chunkSize: 1_100_000 });
    const plain = crypto.getRandomValues(new Uint8Array(1_200_000)); // > 1 frame

    const { header, writable, readable } = await enc.createEncryptionStream('pw');
    const w = writable.getWriter();
    w.write(plain);
    w.close();

    const body = await collect(readable);
    const full = new Uint8Array(header.length + body.length);
    full.set(header);
    full.set(body, header.length);

    // Reader with default chunkSize (512 KiB)
    const dec = new Cryptit(nodeProvider, { scheme: 0, difficulty: 'low' });
    const ts  = await dec.createDecryptionStream('pw');

    const rs = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(full); c.close(); },
    }).pipeThrough(ts);

    const out = await collect(rs);
    expect(out).toEqual(plain);
  });
});