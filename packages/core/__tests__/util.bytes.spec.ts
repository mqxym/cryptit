import {
  base64Encode,
  base64Decode,
  concat,
} from '../src/util/bytes.js';
import { DecodingError } from '../src/errors/index.js';

describe('util/bytes helpers', () => {
  const a = new Uint8Array([1, 2, 3]);
  const b = new Uint8Array([4, 5]);

  it('concats arbitrary Uint8Arrays', () => {
    expect(Array.from(concat(a, b))).toEqual([1, 2, 3, 4, 5]);
  });

  it('base64 round-trips correctly', () => {
    const enc = base64Encode(a, b);
    expect(enc).toMatch(/^[A-Za-z0-9+/]+=*$/);
    const dec = base64Decode(enc);
    expect(Array.from(dec)).toEqual([1, 2, 3, 4, 5]);
  });

  it('throws DecodingError on corrupt input', () => {
    expect(() => base64Decode('*not-b64*')).toThrow(DecodingError);
  });

  it('rejects Base64 containing **whitespace**', () => {
    expect(() => base64Decode('Zm8 g')).toThrow(DecodingError);
  });

  it('throws DecodingError when length is not a multiple of 4', () => {
    // “Zm8” → 3 characters - illegal padding
    expect(() => base64Decode('Zm8')).toThrow(DecodingError);
  });

  it('throws DecodingError when input contains non-alphabet characters', () => {
    expect(() => base64Decode('YWJj$A==')).toThrow(DecodingError);
  });
});
