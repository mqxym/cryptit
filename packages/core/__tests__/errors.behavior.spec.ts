/* ------------------------------------------------------------------
   Error-handling behaviour: typed config errors, decrypt-path null
   guards, cause chaining, and env-controlled stack-trace redaction.
   ------------------------------------------------------------------ */
import { Cryptit }       from '../src/index.js';
import {
  CryptitError,
  ConfigError,
  DecryptionError,
  DecodingError,
}                        from '../src/errors/index.js';
import { base64Decode }  from '../src/util/bytes.js';
import { makeCrypt }     from './test.constants.js';

describe('Typed configuration errors', () => {
  it('setChunkSize range violation throws a ConfigError (a CryptitError)', () => {
    const crypt = makeCrypt();
    expect(() => crypt.setChunkSize(128 * 1024 * 1024 + 1)).toThrow(ConfigError);
    try {
      crypt.setChunkSize(0);
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError);
      expect(e).toBeInstanceOf(CryptitError);
    }
  });
});

describe('Decrypt-path null-password guards', () => {
  it('decryptText(null) rejects with DecryptionError (not EncryptionError)', async () => {
    const crypt = makeCrypt();
    await expect(crypt.decryptText('AA==', null)).rejects.toThrow(DecryptionError);
  });

  it('decryptFile(null) rejects with DecryptionError', async () => {
    const crypt = makeCrypt();
    await expect(crypt.decryptFile(new Blob([]), null)).rejects.toThrow(DecryptionError);
  });
});

describe('Error cause chaining', () => {
  it('base64Decode preserves the originating error as `cause`', () => {
    try {
      base64Decode('not valid base64!');
      throw new Error('expected base64Decode to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(DecodingError);
      expect((e as DecodingError).cause).toBeInstanceOf(Error);
    }
  });
});

describe('Stack-trace redaction is environment-controlled', () => {
  const KEY = 'CRYPTIT_DISABLE_STACKTRACE';

  afterEach(() => { delete process.env[KEY]; });

  it('keeps stack traces by default', () => {
    delete process.env[KEY];
    expect(new CryptitError('boom').stack).toBeDefined();
  });

  it('redacts stack traces when the env flag is truthy', () => {
    process.env[KEY] = '1';
    expect(new CryptitError('boom').stack).toBeUndefined();
  });
});
