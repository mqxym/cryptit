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