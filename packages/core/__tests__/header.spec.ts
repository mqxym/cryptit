import { encodeHeader } from '../src/header/encoder.js';
import { decodeHeader } from '../src/header/decoder.js';
import { InvalidHeaderError } from '../src/errors/index.js';

describe('header encode/decode', () => {
  const salt = new Uint8Array(12).fill(9);

  it('is a perfect round-trip', () => {
    const h = encodeHeader(0, 'high', 'high', salt);
    const dec = decodeHeader(h);
    expect(dec.scheme).toBe(0);
    expect(dec.difficulty).toBe('high');
    expect(Array.from(dec.salt)).toEqual(Array.from(salt));
  });

  it('detects bad magic byte', () => {
    const broken = encodeHeader(0, 'low', 'low', salt).slice();
    broken[0] = 0xFF;
    expect(() => decodeHeader(broken)).toThrow(InvalidHeaderError);
  });
});