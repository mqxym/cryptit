import { Cryptit }      from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

const randomBlob = (bytes: number) =>
  new Blob([crypto.getRandomValues(new Uint8Array(bytes))]);

describe('Cryptit file helpers', () => {
  const crypt = new Cryptit(nodeProvider);

  it('round-trips a 2 MiB Blob loss-lessly', async () => {
    const plain = randomBlob(2_097_152);      // 2 MiB
    const enc   = await crypt.encryptFile(plain, 'hunter2');
    const dec   = await crypt.decryptFile(enc, 'hunter2');

    expect(await dec.arrayBuffer()).toEqual(await plain.arrayBuffer());
  });
});

/* ------------------------------------------------------------------ */
/*  Empty-blob round-trip                                             */
/* ------------------------------------------------------------------ */
describe('Cryptit file helpers - extra cases', () => {
  const crypt = new Cryptit(nodeProvider);

  it('round-trips a **zero-byte Blob**', async () => {
    const empty = new Blob([]);
    const enc   = await crypt.encryptFile(empty, 'pw');
    const dec   = await crypt.decryptFile(enc, 'pw');
    expect(dec.size).toBe(0);
  });

  it('encrypts empty blob without unhandled rejections', async () => {
    const crypt = new Cryptit(nodeProvider);
    const empty = new Blob([]);
    await expect(crypt.encryptFile(empty, 'pw')).resolves.toBeInstanceOf(Blob);
  });
});