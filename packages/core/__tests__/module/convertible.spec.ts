import { ConvertibleInput, ConvertibleOutput } from '../../src/util/Convertible.js';
import { base64Encode } from '../../src/util/bytes.js';

/* Helpers */
const hex = (u8: Uint8Array) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');

describe('ConvertibleInput', () => {
  it('from(string) → bytes; clear() makes further access fail', () => {
    const s   = 'hello';
    const enc = new TextEncoder().encode(s);

    const ci = ConvertibleInput.from(s);
    expect(ci.toUint8Array()).toEqual(enc);

    ci.clear();
    expect(() => ci.toUint8Array()).toThrow(/cleared/i);
  });

  it('from(Uint8Array) zeros the original buffer on clear()', () => {
    const src = new Uint8Array([1, 2, 3, 4, 5]);
    const ci  = ConvertibleInput.from(src);

    // Touch it so an internal copy isn’t made (it isn’t)
    expect(ci.toUint8Array().byteLength).toBe(5);

    ci.clear();

    // the original reference is wiped
    expect(Array.from(src)).toEqual([0, 0, 0, 0, 0]);
    expect(() => ci.toUint8Array()).toThrow();
  });

  it('from(ConvertibleInput) returns the same instance', () => {
    const original = new ConvertibleInput(new Uint8Array([9]));
    const same     = ConvertibleInput.from(original);
    expect(same).toBe(original);
  });
});

describe('ConvertibleOutput', () => {
  it('exposes base64 / hex / uint8array / text views and toString()', () => {
    const text  = 'héllo 🌍';
    const bytes = new TextEncoder().encode(text);
    const out   = new ConvertibleOutput(bytes);

    // text view
    expect(out.text).toBe(text);

    // base64 view (and toString passthrough)
    const expectedB64 = base64Encode(bytes);
    expect(out.base64).toBe(expectedB64);
    expect(String(out)).toBe(expectedB64);

    // hex view
    expect(out.hex).toBe(hex(bytes));

    // uint8array view references the internal buffer (read-only by convention)
    const view = out.uint8array;
    expect(view).toBeInstanceOf(Uint8Array);
    expect(view.byteLength).toBe(bytes.byteLength);
  });

  it('clear() zeroizes the internal buffer and disables further accessors', () => {
    const bytes = new Uint8Array([10, 20, 30]);
    const out   = new ConvertibleOutput(bytes);

    const viewBefore = out.uint8array; // capture reference to test zeroization

    out.clear();

    // Previously exposed view should now be all zeros
    expect(Array.from(viewBefore)).toEqual([0, 0, 0]);

    // All getters should throw after clear()
    expect(() => out.base64).toThrow(/cleared/i);
    expect(() => out.hex).toThrow(/cleared/i);
    expect(() => out.text).toThrow(/cleared/i);
    expect(() => out.uint8array).toThrow(/cleared/i);
  });
});