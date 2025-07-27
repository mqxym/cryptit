import { Cryptit } from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

it('round trips text', async () => {
  const crypt = new Cryptit(nodeProvider);
  const cipher = await crypt.encryptText('hello', 'secret');
  expect(await crypt.decryptText(cipher, 'secret')).toBe('hello');
});

it("file round-trip", async () => {
  const plain = new Blob([crypto.getRandomValues(new Uint8Array(2_000_000))]);
  const crypt = new Cryptit(nodeProvider);
  const enc   = await crypt.encryptFile(plain, "hunter2");
  const dec   = await crypt.decryptFile(enc, "hunter2");
  expect(await dec.arrayBuffer()).toEqual(await plain.arrayBuffer());
});