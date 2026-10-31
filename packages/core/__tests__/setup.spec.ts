import { describe, expect, it } from 'bun:test';
import * as browserArgon2 from 'argon2-browser';
import * as nativeArgon2 from '@node-rs/argon2';
import { argon2id } from '../src/algorithms/kdf/argon2-wrapper.js';

const salt = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
const options = { time: 2, mem: 64, hashLen: 65, parallelism: 1, type: 2 };
const digestHex = '28a869f463dfbc7a3cd77363f1ec6a73a349600c12178a5a98ab4ea759cb9f95069b249b1ad81a874babf0fe4b51bfcde7d2844b7c460a20bfff542d2e63377eda';

const suite = process.env.CRYPTIT_TEST_REAL_ARGON2 === '1' ? describe.skip : describe;

suite('test-only Argon2 mocks', () => {
  it('expands a deterministic digest and matches the native encoded result', async () => {
    const browser = await browserArgon2.hash({ pass: 'päss', salt, ...options });
    const native = await nativeArgon2.hash('päss', {
      salt,
      timeCost: options.time,
      memoryCost: options.mem,
      outputLen: options.hashLen,
      parallelism: options.parallelism,
      algorithm: nativeArgon2.Algorithm.Argon2id,
    });
    expect(browser.hash).toBeInstanceOf(Uint8Array);
    expect(browser.hash.length).toBe(65);
    expect(browser.hashHex).toBe(digestHex);
    expect(native).toBe(browser.encoded);
    expect(Buffer.from(native.split('$').pop()!, 'base64').toString('hex')).toBe(digestHex);
    expect((await browserArgon2.hash({ pass: 'päss', salt, ...options })).hash).toEqual(browser.hash);
  });

  it.each([
    { pass: 'different' },
    { salt: new Uint8Array([7, 6, 5, 4, 3, 2, 1, 0]) },
    { time: 3 },
    { mem: 128 },
    { hashLen: 66 },
    { parallelism: 2 },
  ])('includes changed inputs in the digest: %j', async change => {
    const result = await browserArgon2.hash({ pass: 'päss', salt, ...options, ...change });
    expect(Buffer.from(result.hash).toString('hex').slice(0, 64)).not.toBe(digestHex.slice(0, 64));
  });

  it('supports UTF-8 strings and raw-byte passwords across both wrapper paths', async () => {
    const tuning = { time: 2, mem: 64, parallelism: 1 };
    const stringHash = await argon2id('päss', salt, tuning, 'browser');
    const utf8Hash = await argon2id(new TextEncoder().encode('päss'), salt, tuning, 'node');
    expect(stringHash.hash).toEqual(utf8Hash.hash);

    const bytes = new Uint8Array([0, 255, 128, 42]);
    const original = bytes.slice();
    const browser = await argon2id(bytes, salt, tuning, 'browser');
    const native = await argon2id(bytes, salt, tuning, 'node');
    expect(browser.hash).toHaveLength(32);
    expect(native.hash).toEqual(browser.hash);
    expect(bytes).toEqual(original);
  });

  it('rejects invalid tuning and salt explicitly', async () => {
    await expect(browserArgon2.hash({
      pass: 'pw', salt, ...options, time: 0,
    })).rejects.toThrow('argon2 mock: invalid inputs');
    await expect(nativeArgon2.hash('pw', {
      salt: new Uint8Array(1),
      timeCost: 2,
      memoryCost: 64,
      outputLen: 32,
      parallelism: 1,
      algorithm: nativeArgon2.Algorithm.Argon2id,
    })).rejects.toThrow('argon2 mock: invalid inputs');
  });
});
