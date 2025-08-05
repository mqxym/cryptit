import { Cryptit } from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { SCHEMES } from './test.constants.js';

describe.each(SCHEMES)('Cryptit round-trip sanity (scheme %i)', scheme => {
  let crypt: Cryptit;

  beforeEach(() => {
    crypt = new Cryptit(nodeProvider, { scheme });
  });

  it('round trips text', async () => {
    const cipher = await crypt.encryptText('hello', 'secret');
    expect(await crypt.decryptText(cipher, 'secret')).toBe('hello');
  });

  it('file round-trip', async () => {
    const plain = new Blob([crypto.getRandomValues(new Uint8Array(2_000_000))]);
    const enc   = await crypt.encryptFile(plain, 'hunter2');
    const dec   = await crypt.decryptFile(enc, 'hunter2');
    expect(await dec.arrayBuffer()).toEqual(await plain.arrayBuffer());
  });
});