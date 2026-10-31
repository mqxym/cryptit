import { webcrypto } from 'node:crypto';
import { Cryptit } from '../src/index.js';
import type { CryptoProvider } from '../src/providers/CryptoProvider.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { collectStream } from '../src/util/stream.js';

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

const FILE_VECTORS = [
  { scheme: 0, streamFormat: 'legacy', plaintext: '', ciphertext: 'AQAAAQIDBAUGBwgJCgs=' },
  { scheme: 0, streamFormat: 'legacy', plaintext: PLAINTEXT, ciphertext: 'AQAAAQIDBAUGBwgJCgsAAAAwDA0ODxAREhMUFRYXvacYZr6qIf2aA1aJn+8hBryrM2FhB6Z/Vp7larTUSoP5djnf' },
  { scheme: 0, streamFormat: 'authenticated-v1', plaintext: '', ciphertext: 'AQgAAQIDBAUGBwgJCguAAAAcDA0ODxAREhMUFRYXEBFNeStMwDR1RslnchUsmA==' },
  { scheme: 0, streamFormat: 'authenticated-v1', plaintext: PLAINTEXT, ciphertext: 'AQgAAQIDBAUGBwgJCgsAAAAwDA0ODxAREhMUFRYXvacYZr6qIf2aA1aJn+8hBryrM2FftrCYghZ46uyS0+B49aZNgAAAHBgZGhscHR4fICEiI9SoN2x2OdB6aY1ffk7NC4E=' },
  { scheme: 1, streamFormat: 'legacy', plaintext: '', ciphertext: 'ASAAAQIDBAUGBwgJCgs=' },
  { scheme: 1, streamFormat: 'legacy', plaintext: PLAINTEXT, ciphertext: 'ASAAAQIDBAUGBwgJCgsAAAA8DA0ODxAREhMUFRYXGBkaGxwdHh8gISIjf0RzNHVckIDXUZCDqu98KXDw/a4UmO7Sjm0kyPDNz2ZEAUeu' },
  { scheme: 1, streamFormat: 'authenticated-v1', plaintext: '', ciphertext: 'ASgAAQIDBAUGBwgJCguAAAAoDA0ODxAREhMUFRYXGBkaGxwdHh8gISIja6CdTsCtyIPnVHttSTFSYw==' },
  { scheme: 1, streamFormat: 'authenticated-v1', plaintext: PLAINTEXT, ciphertext: 'ASgAAQIDBAUGBwgJCgsAAAA8DA0ODxAREhMUFRYXGBkaGxwdHh8gISIjf0RzNHVckIDXUZCDqu98KXDw/a5TE4KeGM1646Dd10eNo/iYgAAAKCQlJicoKSorLC0uLzAxMjM0NTY3ODk6O4hVyEgxVQaWtO7EeoRSQHo=' },
] as const;

describe.each(FILE_VECTORS)('v2.6.0 file fixture | scheme $scheme | $streamFormat | "$plaintext"', vector => {
  it('decrypts the fixed fixture through the default file and streaming readers', async () => {
    const crypt = new Cryptit(nodeProvider);
    const file = new Blob([Buffer.from(vector.ciphertext, 'base64')]);
    expect(await (await crypt.decryptFile(file, PASSPHRASE)).text()).toBe(vector.plaintext);
    const transform = await crypt.createDecryptionStream(PASSPHRASE);
    const plain = await collectStream(file.stream().pipeThrough(transform));
    expect(new TextDecoder().decode(plain)).toBe(vector.plaintext);
  });

  it('preserves the writer bytes captured before security remediation', async () => {
    const crypt = new Cryptit(deterministicProvider(), {
      scheme: vector.scheme,
      streamFormat: vector.streamFormat,
      difficulty: 'low',
      saltStrength: 'low',
      chunkSize: 32,
    });
    const file = await crypt.encryptFile(new Blob([vector.plaintext]), PASSPHRASE);
    expect(Buffer.from(await file.arrayBuffer()).toString('base64')).toBe(vector.ciphertext);
  });
});
