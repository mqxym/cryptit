/* ------------------------------------------------------------------
   Runtime‑configuration edge cases
   ------------------------------------------------------------------ */
import { Cryptit, type CryptitOptions } from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { SchemeError, ConfigError }  from '../src/errors/index.js';
import { describe, expect, it, spyOn } from 'bun:test';
import { EngineManager } from '../src/engine/EngineManager.js';
import { encodeHeader } from '../src/header/encoder.js';
import { collectStream } from '../src/util/stream.js';
import { concat } from '../src/util/bytes.js';
import { encodeFrameLen, encodeStreamRecord, MAX_CIPHER_FRAME_SIZE } from '../src/util/frame.js';

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
  it.each([
    { maxDecryptionDifficulty: 'invalid' },
    { maxDecryptionDifficulty: null },
    { requireAuthenticatedStream: 'false' },
    { requireAuthenticatedStream: null },
    { acceptUnauthenticatedHeader: 'false' },
    { streamFormat: 'unknown' },
  ])('rejects invalid security configuration %j', options => {
    expect(() => new Cryptit(nodeProvider, options as unknown as CryptitOptions)).toThrow(ConfigError);
  });

  it('rejects ciphertext above the configured KDF ceiling', async () => {
    const writer = new Cryptit(nodeProvider, { difficulty: 'middle' });
    const encrypted = await writer.encryptText('policy check', 'pw');
    const reader = new Cryptit(nodeProvider, { maxDecryptionDifficulty: 'low' });

    await expect(reader.decryptText(encrypted.uint8array, 'pw'))
      .rejects.toThrow(/exceeds configured maximum/);
  });

  it.each([0, 1])('rejects impossible scheme %i payloads before deriving a key', async scheme => {
    const crypt = new Cryptit(nodeProvider);
    const salt = new Uint8Array(12);
    const header = encodeHeader(scheme, 'low', 'low', salt);
    const authenticatedHeader = encodeHeader(scheme, 'low', 'low', salt, undefined, 'authenticated-v1');
    const minimum = scheme === 0 ? 28 : 40;
    const derive = spyOn(EngineManager, 'deriveKey');
    try {
      await expect(crypt.decryptText(concat(header, new Uint8Array(minimum - 1)), 'pw')).rejects.toThrow();
      for (const body of [
        new Uint8Array(0),
        new Uint8Array(3),
        encodeStreamRecord(minimum - 1),
        encodeStreamRecord(MAX_CIPHER_FRAME_SIZE + 1),
        encodeStreamRecord(minimum + 1, true),
      ]) {
        const file = new Blob([concat(authenticatedHeader, body) as BufferSource]);
        await expect(crypt.decryptFile(file, 'pw')).rejects.toThrow();
        const transform = await crypt.createDecryptionStream('pw');
        await expect(collectStream(file.stream().pipeThrough(transform))).rejects.toThrow();
      }
      const truncated = new Blob([concat(header, encodeFrameLen(minimum)) as BufferSource]);
      await expect(crypt.decryptFile(truncated, 'pw')).rejects.toThrow();
      expect(derive).not.toHaveBeenCalled();
    } finally {
      derive.mockRestore();
    }
  });
});