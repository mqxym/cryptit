import { webcrypto } from 'node:crypto';
import { Cryptit } from '../src/index.js';
import type { CryptoProvider } from '../src/providers/CryptoProvider.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

const PASSPHRASE = 'correct horse';
const PLAINTEXT = 'compatibility-vector';

const VECTORS = [
  {
    scheme: 0,
    ciphertext: 'AQAAAQIDBAUGBwgJCgsQERITFBUWFxgZGht9/PS7ADOYjZgfsuwhGh8frLB5i7ppIdu3rT5Y+Q7fdUufCOVEbfcujx+sNIfwvHc=',
  },
  {
    scheme: 1,
    ciphertext: 'ASAAAQIDBAUGBwgJCgsQERITFBUWFxgZGhscHR4fICEiIyQlJicz/pC0BCvPNq5dd8EIcCyFTZF4TCTbdmsrzdYNpeH6SahIImWvusrtuwSuvG7u+DE=',
  },
] as const;

function deterministicProvider(): CryptoProvider {
  let nextByte = 0;
  return {
    subtle: webcrypto.subtle as SubtleCrypto,
    isNode: true,
    getRandomValues(buffer: Uint8Array): Uint8Array {
      for (let index = 0; index < buffer.length; index++) {
        buffer[index] = nextByte++ & 0xff;
      }
      return buffer;
    },
  };
}

describe.each(VECTORS)('immutable text compatibility vector | scheme $scheme', vector => {
  it('decrypts the fixed ciphertext', async () => {
    const crypt = new Cryptit(nodeProvider, { difficulty: 'low' });
    const plaintext = await crypt.decryptText(vector.ciphertext, PASSPHRASE);

    expect(plaintext.text).toBe(PLAINTEXT);
  });

  it('keeps the current wire format byte-for-byte stable', async () => {
    const crypt = new Cryptit(deterministicProvider(), {
      scheme: vector.scheme,
      difficulty: 'low',
      saltStrength: 'low',
    });
    const ciphertext = await crypt.encryptText(PLAINTEXT, PASSPHRASE);

    expect(ciphertext.base64).toBe(vector.ciphertext);
  });
});
