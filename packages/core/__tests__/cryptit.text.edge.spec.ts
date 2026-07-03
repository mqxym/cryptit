/* ------------------------------------------------------------------
   Text encryption edge cases: binary payloads, Convertible inputs,
   and malformed-ciphertext rejection paths.
   ------------------------------------------------------------------ */
import { Cryptit }                    from '../src/index.js';
import { ConvertibleInput }           from '../src/util/Convertible.js';
import { DecryptionError, DecodingError } from '../src/errors/index.js';
import { makeCrypt, randomBytes, SCHEMES } from './test.constants.js';

describe.each(SCHEMES)('Cryptit text edge cases (scheme %i)', scheme => {
  it('round-trips raw binary covering all 256 byte values', async () => {
    const crypt    = makeCrypt({ scheme, difficulty: 'low' });
    const bytes    = new Uint8Array(256).map((_, i) => i); // 0x00 … 0xFF
    const expected = bytes.slice();                        // encryptText zeroes its input

    const cipher = await crypt.encryptText(bytes, 'pw');
    const plain  = await crypt.decryptText(cipher.uint8array, 'pw');
    expect(plain.uint8array).toEqual(expected);
  });

  it('accepts a ConvertibleInput as plaintext source', async () => {
    const crypt = makeCrypt({ scheme, difficulty: 'low' });
    const data  = randomBytes(64);
    const input = ConvertibleInput.from(data.slice()); // copy: encrypt may zero it

    const cipher = await crypt.encryptText(input, 'pw');
    const plain  = await crypt.decryptText(cipher.uint8array, 'pw');
    expect(plain.uint8array).toEqual(data);
  });

  it('rejects a ciphertext shorter than IV + tag with DecryptionError', async () => {
    const crypt  = makeCrypt({ scheme, difficulty: 'low', saltStrength: 'low' });
    const cipher = await crypt.encryptText('x', 'pw');
    // header (14 B for low salt) + 2 payload bytes ≪ IV+tag minimum
    const truncated = cipher.uint8array.slice(0, 16);
    await expect(crypt.decryptText(truncated, 'pw')).rejects.toThrow(DecryptionError);
  });

  it('rejects a non-base64 ciphertext string with DecodingError', async () => {
    const crypt = makeCrypt({ scheme, difficulty: 'low' });
    await expect(crypt.decryptText('!!! not base64 !!!', 'pw'))
      .rejects.toThrow(DecodingError);
  });
});
