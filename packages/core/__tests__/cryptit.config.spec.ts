/* ------------------------------------------------------------------
   Runtime‑configuration edge cases
   ------------------------------------------------------------------ */
import { Cryptit }      from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { SchemeError, ConfigError }  from '../src/errors/index.js';

describe('Cryptit configuration guards', () => {

  const crypt = new Cryptit(nodeProvider);

  /* ── chunk‑size validation ─────────────────────────────────────── */
  it.each([0, -1, 3.14, NaN, Infinity])(
    'setChunkSize(%p) → throws',
    bad => {
      // force a cast so the compiler still allows the call
      expect(() => crypt.setChunkSize(bad as unknown as number))
        .toThrow(Error);
    },
  );

  /* ── chunk‑size boundary: 128 MiB is the inclusive ceiling ─────── */
  const MAX_CHUNK = 128 * 1024 * 1024; // 134_217_728

  it('setChunkSize(128 MiB) is accepted (inclusive maximum)', () => {
    const fresh = new Cryptit(nodeProvider);
    expect(fresh.setChunkSize(MAX_CHUNK)).toBe(MAX_CHUNK);
    expect(fresh.getChunkSize()).toBe(MAX_CHUNK);
  });

  it('setChunkSize(128 MiB + 1) → ConfigError (typed, catchable via CryptitError)', () => {
    expect(() => crypt.setChunkSize(MAX_CHUNK + 1)).toThrow(ConfigError);
  });

  it('setChunkSize(null) falls back to the scheme default', () => {
    const fresh   = new Cryptit(nodeProvider);
    const fallback = fresh.setChunkSize(null as unknown as number);
    expect(fallback).toBeGreaterThan(0);
    expect(fresh.getChunkSize()).toBe(fallback);
  });

  /* ── scheme guards ─────────────────────────────────────────────── */
  it('setScheme(8) → SchemeError (id outside registry)', () => {
    const fresh = new Cryptit(nodeProvider);
    expect(() => fresh.setScheme(8)).toThrow(SchemeError);
  });

  /* ── verbosity round-trips through getter ──────────────────────── */
  it('setVerbose/getVerbose round-trip', () => {
    const fresh = new Cryptit(nodeProvider);
    fresh.setVerbose(4);
    expect(fresh.getVerbose()).toBe(4);
    fresh.setVerbose(0);
    expect(fresh.getVerbose()).toBe(0);
  });

  /* ── scheme switching must not break legacy ciphertexts ────────── */
  it('decrypts old scheme-0 ciphertext after scheme switch', async () => {
    const cipher = await crypt.encryptText('legacy', 'pw');   // scheme 0
    crypt.setScheme(1);                                       // switch
    const plain = await crypt.decryptText(cipher.uint8array, 'pw');
    expect(plain.text).toBe('legacy');
  });
});

describe('Cryptit decryption resource policy', () => {
  it('rejects ciphertext above the configured KDF ceiling', async () => {
    const writer = new Cryptit(nodeProvider, { difficulty: 'middle' });
    const encrypted = await writer.encryptText('policy check', 'pw');
    const reader = new Cryptit(nodeProvider, { maxDecryptionDifficulty: 'low' });

    await expect(reader.decryptText(encrypted.uint8array, 'pw'))
      .rejects.toThrow(/exceeds configured maximum/);
  });
});