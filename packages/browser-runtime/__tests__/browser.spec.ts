/**
 * Runs under Jest’s jsdom environment.
 * All crypto operations use the stubbed Argon2 and the real WebCrypto
 * (poly-filled in setup-tests.ts).
 */
/* eslint-env jest, browser */

import { createCryptit } from '../src/index.js';

describe('browser-runtime facade', () => {
  const crypt = createCryptit({ chunkSize: 1024 });

  it('encrypts & decrypts in a browser context', async () => {
    const cipher = await crypt.encryptText('Foo', 'pw');
    const plain  = await crypt.decryptText(cipher, 'pw');
    expect(plain).toBe('Foo');
  });
});

describe('browser-runtime scheme 1', () => {
  const crypt = createCryptit({ chunkSize: 1024, scheme: 1 });

  it('encrypts & decrypts in a browser context', async () => {
    const cipher = await crypt.encryptText('Foo', 'pw');
    const plain  = await crypt.decryptText(cipher, 'pw');
    expect(plain).toBe('Foo');
  });
});