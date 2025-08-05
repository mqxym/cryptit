import { Cryptit }      from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { DecryptionError } from '../src/errors/index.js';
import { browserProvider } from '../../browser-runtime/src/provider.js';
import type { CryptoProvider } from '../src/providers/CryptoProvider.js';
import { SCHEMES } from './test.constants.js';

describe.each(SCHEMES)('Cryptit text helpers (scheme %i)', scheme => {
  let crypt: Cryptit;

  beforeEach(() => {
    crypt = new Cryptit(nodeProvider, { scheme });
  });

  it('encrypts & decrypts a UTF-8 string', async () => {
    const secret = await crypt.encryptText('héllo 🌍', 'pw');
    expect(typeof secret).toBe('string');
    expect(secret).toMatch(/^[A-Za-z0-9+/]+=*$/);

    const plain = await crypt.decryptText(secret, 'pw');
    expect(plain).toBe('héllo 🌍');
  });

  it('fails with wrong passphrase', async () => {
    const cipher = await crypt.encryptText('test', 'a');
    await expect(crypt.decryptText(cipher, 'b'))
      .rejects.toThrow(DecryptionError);
  });

  it('isEncrypted() detects Cryptit payloads', async () => {
    const cipher = await crypt.encryptText('abc', 'x');
    expect(await Cryptit.isEncrypted(cipher)).toBe(true);
    expect(await Cryptit.isEncrypted('plain')).toBe(false);
  });
});


/* ------------------------------------------------------------------ */
/*  Additional edge-case & crossover tests                             */
/* ------------------------------------------------------------------ */
describe.each(SCHEMES)('Cryptit text helpers extras (scheme %i)', scheme => {
  let crypt: Cryptit;

  beforeEach(() => {
    crypt = new Cryptit(nodeProvider, { scheme });
  });

  it('encrypts & decrypts an **empty string**', async () => {
    const cipher = await crypt.encryptText('', 'pw');
    expect(await crypt.decryptText(cipher, 'pw')).toBe('');
  });

  it('handles **multi-megabyte** UTF-8 data (> default chunk size)', async () => {
    const big = 'x'.repeat(1_200_000);               // ≈ 1.2 MiB
    const cipher = await crypt.encryptText(big, 'pw');
    expect(await crypt.decryptText(cipher, 'pw')).toBe(big);
  });

  it('cross-runtime: **node encrypt → browser decrypt**', async () => {
    const nodeCrypt = new Cryptit(nodeProvider);
    const cipher    = await nodeCrypt.encryptText('cross-ok', 'pw');

    const browserCrypt = new Cryptit(browserProvider as CryptoProvider);
    const plain        = await browserCrypt.decryptText(cipher, 'pw');
    expect(plain).toBe('cross-ok');
  });

  it('rejects **truncated ciphertext** with a meaningful error', async () => {
    const cipher = await crypt.encryptText('cut-off', 'pw');
    const damaged = cipher.slice(0, cipher.length - 10);      // remove tail
    await expect(crypt.decryptText(damaged, 'pw')).rejects.toThrow();
  });

  it('supports switching to **scheme 1** (XChaCha20-Poly1305)', async () => {
    crypt.setScheme(1);
    const cipher = await crypt.encryptText('scheme-1', 'pw');
    expect(await crypt.decryptText(cipher, 'pw')).toBe('scheme-1');
  });
});