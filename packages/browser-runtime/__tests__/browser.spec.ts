/**
 * Runs under Jest’s jsdom environment.
 * All crypto operations use the stubbed Argon2 and the real WebCrypto
 * (poly-filled in setup-tests.ts).
 */
/* eslint-env jest, browser */

import { createCryptit } from '../src/index.js';

describe('browser-runtime facade', () => {
  const crypt = createCryptit();

  it('encrypts & decrypts in a browser context', async () => {
    const cipher = await crypt.encryptText('Foo', 'pw');
    const plain  = await crypt.decryptText(cipher.base64, 'pw');
    expect(plain.text).toBe('Foo');
  });
});

describe('browser-runtime | Scheme 1', () => {
  const crypt1 = createCryptit({ difficulty: "low", saltStrength: "low", scheme: 1 });

  it('encrypts & decrypts in a browser context', async () => {
    const cipher = await crypt1.encryptText('Foo', 'pw');
    const plain  = await crypt1.decryptText(cipher.base64, 'pw');
    expect(plain.text).toBe('Foo');
  });
});