import '../../src/config/defaults.js';
import { encodeHeader } from '../../src/header/encoder.js';
import { decodeHeader } from '../../src/header/decoder.js';
import { InvalidHeaderError } from '../../src/errors/index.js';

describe('header encode/decode', () => {
  const salt = new Uint8Array(12).fill(9);

  it('is a perfect round-trip', () => {
    const h = encodeHeader(0, 'high', 'low', salt);
    const dec = decodeHeader(h);
    expect(dec.scheme).toBe(0);
    expect(dec.difficulty).toBe('high');
    expect(Array.from(dec.salt)).toEqual(Array.from(salt));
  });

  it('preserves the wire layout for every supported header combination', () => {
    const difficulties = ['low', 'middle', 'high'] as const;
    const strengths = ['low', 'high'] as const;
    const formats = ['legacy', 'authenticated-v1'] as const;

    for (const scheme of [0, 1, 2]) {
      for (const [difficultyCode, difficulty] of difficulties.entries()) {
        for (const saltStrength of strengths) {
          for (const streamFormat of formats) {
            const salt = new Uint8Array(saltStrength === 'high' ? 16 : 12).fill(9);
            const header = encodeHeader(
              scheme, difficulty, saltStrength, salt, undefined, streamFormat,
            );
            const expectedInfo = (scheme << 5)
              | (streamFormat === 'authenticated-v1' ? 0x08 : 0)
              | (saltStrength === 'high' ? 0x04 : 0)
              | difficultyCode;

            expect(Array.from(header)).toEqual([0x01, expectedInfo, ...salt]);
            expect(decodeHeader(header)).toEqual({
              scheme, difficulty, saltStrength, salt, streamFormat,
              headerLen: 2 + salt.length,
            });
          }
        }
      }
    }
  });

  it('detects bad magic byte', () => {
    const broken = encodeHeader(0, 'low', 'low', salt).slice();
    broken[0] = 0xFF;
    expect(() => decodeHeader(broken)).toThrow(InvalidHeaderError);
  });

  it('rejects an extension marker without enough salt for the second info byte', () => {
    const header = encodeHeader(0, 'low', 'low', new Uint8Array(12));
    header[1] |= 0x10;
    expect(() => decodeHeader(header)).toThrow();
  });

  it('rejects the unassigned difficulty code', () => {
    const header = encodeHeader(0, 'low', 'low', new Uint8Array(12));
    header[1] = (header[1] & 0xfc) | 0x03;
    expect(() => decodeHeader(header)).toThrow();
  });
});

import { HeaderDecodeError } from '../../src/errors/index.js';               // NEW

/* ------------------------------------------------------------------ */
/*  Unknown-scheme detection                                          */
/* ------------------------------------------------------------------ */
describe('header encode/decode - extra cases', () => {
  const salt = new Uint8Array(12).fill(7);

  it('rejects an unknown scheme id before encoding', () => {
    expect(() => encodeHeader(7, 'low', 'low', salt)).toThrow();
  });

  it('rejects a salt whose length does not match the selected strength', () => {
    expect(() => encodeHeader(0, 'low', 'high', salt)).toThrow(
      'Scheme 0 high salt must be 16 bytes',
    );
  });

  it('rejects unsupported runtime format values', () => {
    expect(() => encodeHeader(
      0,
      'low',
      'low',
      salt,
      undefined,
      'future' as any,
    )).toThrow('Unsupported stream format');
  });

  it('throws InvalidHeaderError when header is too short', () => {
    // Minimum header is 2 bytes + 12-byte salt = 14 bytes
    const tooShort = new Uint8Array(13)
    tooShort[0] = 0x01;
    expect(() => decodeHeader(tooShort)).toThrow(InvalidHeaderError);
    expect(() => decodeHeader(tooShort)).toThrow('Invalid input format. Header too short.');
  });
});