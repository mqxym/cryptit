import { Magic48VerCrc8Padding, MalformedPaddingError } from '../../../src/algorithms/padding/magic48ver-crc8.js';

function deterministicRng() {
  let x = 0;
  return (n: number) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = (x++ & 0xff);
    return out;
  };
}

describe('Magic48VerCrc8Padding', () => {
  it('round-trips (pad → tryUnpad) for various lengths & aligns', () => {
    const padder = new Magic48VerCrc8Padding();
    const aligns = [1, 2, 3, 7, 8, 13, 32, 64, 248]; // 248 is max allowed with LEN=1 (8 + a - 1 ≤ 255)
    for (let len = 0; len <= 128; len++) {
      const plain = new Uint8Array(len).map((_, i) => (i * 7) & 0xff);
      for (const align of aligns) {
        const rng = deterministicRng();
        const padded = padder.pad(plain, rng, align);
        // trailer length from LEN byte
        const k = padded[padded.length - 2];
        // invariants
        expect(k).toBeGreaterThanOrEqual(8);
        expect(k).toBeLessThanOrEqual(8 + align - 1);
        expect((padded.length) % align).toBe(0);
        expect(k).toBe(padded.length - plain.length);
        // tryUnpad success
        const { used, plain: unpadded } = padder.tryUnpad(padded);
        expect(used).toBe(true);
        expect(new Uint8Array(unpadded)).toEqual(plain);
      }
    }
  });

  it('prefers a full block when already aligned (k === align)', () => {
    const padder = new Magic48VerCrc8Padding();
    const plain = new Uint8Array(16);
    const rng = deterministicRng();
    const align = 8;
    const padded = padder.pad(plain, rng, align);
    const k = padded[padded.length - 2];
    expect(k).toBe(8); // full block preference
    expect(padded.length % align).toBe(0);
  });

  it('rejects align too large for 1-byte LEN (≥ 249)', () => {
    const padder = new Magic48VerCrc8Padding();
    const plain = new Uint8Array(10);
    const rng = deterministicRng();
    expect(() => padder.pad(plain, rng, 249)).toThrow(MalformedPaddingError);
  });

  it('throws when RNG returns wrong length', () => {
    const padder = new Magic48VerCrc8Padding();
    const plain = new Uint8Array(5);
    const badRng = (n: number) => new Uint8Array(Math.max(0, n - 1)); // underfills by 1
    expect(() => padder.pad(plain, badRng, 8)).toThrow(MalformedPaddingError);
  });

  it('tryUnpad returns {used:false} on non-padded input', () => {
    const padder = new Magic48VerCrc8Padding();
    const legacy = new Uint8Array([1, 2, 3, 4]);
    const { used, plain } = padder.tryUnpad(legacy);
    expect(used).toBe(false);
    expect(new Uint8Array(plain)).toEqual(legacy);
  });

  it('tryUnpad refuses malformed magic (no throw, used=false)', () => {
    const padder = new Magic48VerCrc8Padding();
    const rng = deterministicRng();
    const basePlain = new Uint8Array([9, 8, 7, 6, 5, 4]);
    const padded = padder.pad(basePlain, rng, 8);
    // Corrupt 1st magic byte at end-8
    padded[padded.length - 8] ^= 0xff;
    const { used, plain } = padder.tryUnpad(padded);
    expect(used).toBe(false);
    expect(new Uint8Array(plain)).toEqual(padded);
  });

  it('tryUnpad refuses bad CRC (no throw, used=false)', () => {
    const padder = new Magic48VerCrc8Padding();
    const rng = deterministicRng();
    const basePlain = new Uint8Array([1, 2, 3]);
    const padded = padder.pad(basePlain, rng, 8);
    // Corrupt CRC (last byte)
    padded[padded.length - 1] ^= 0x55;
    const { used, plain } = padder.tryUnpad(padded);
    expect(used).toBe(false);
    expect(new Uint8Array(plain)).toEqual(padded);
  });

  it('tryUnpad refuses when LEN out of range (len < 8 or len > total)', () => {
    const padder = new Magic48VerCrc8Padding();
    const rng = deterministicRng();
    const basePlain = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
    // Valid padded
    const padded = padder.pad(basePlain, rng, 8);

    // Case 1: set LEN to 7 (< STRUCT_SIZE)
    const mutated1 = padded.slice();
    mutated1[mutated1.length - 2] = 7;
    const res1 = padder.tryUnpad(mutated1);
    expect(res1.used).toBe(false);

    // Case 2: set LEN > total length
    const mutated2 = padded.slice();
    mutated2[mutated2.length - 2] = 0xff;
    const res2 = padder.tryUnpad(mutated2);
    expect(res2.used).toBe(false);
  });
});