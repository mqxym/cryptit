/**
 * algorithms/padding/magic48ver-crc8.ts
 *
 * AEAD-friendly padding trailer with a 40-bit magic, 1-byte VERSION, and CRC-8 guard.
 *
 * Trailer layout (appended after plaintext and authenticated by the AEAD):
 *   P || RND[(k-8) bytes] || MAGIC40(5) || VER(1) || LEN(1 = k) || CRC8(1 over MAGIC40||VER||LEN)
 *
 * Where:
 *   - k ≥ 8 and (len(plain) + k) % align === 0
 *   - LEN stores the total trailer length k (1 byte)
 *   - CRC8 is CRC-8-ATM over the 7 bytes: MAGIC40(5) || VER(1) || LEN(1)
 *
 * Design notes:
 *   - VERSION is carried "within the 48-bit magic scope": the original 6th magic byte
 *     is now a dedicated VERSION byte. Structure size remains 8 bytes total.
 *   - The 40-bit magic + 8-bit CRC + LEN-range still makes legacy false positives
 *     extremely rare for practical scanning use under an AEAD.
 *   - CRC8 is not for integrity (the AEAD covers that); it's only to minimize
 *     incidental false positives when scanning legacy payloads.
 *   - Equality checks avoid early exits (best-effort constant-time in JS/TS).
 *
 * Defaults in this implementation:
 *   - Default alignment is 8 bytes (align = 8).
 *   - Structure size is 8 bytes (5 + 1 + 1 + 1), so the minimal k is 8.
 *   - With align = 8, the largest k needed is 15 → maxPad (for default align) = 15.
 *
 * Example:
 *   const padder = new Magic48VerCrc8Padding();
 *   const rng = (n: number) => crypto.getRandomValues(new Uint8Array(n));
 *   const padded = padder.pad(new Uint8Array([1,2,3]), rng); // align=8 by default
 *   const { used, plain } = padder.tryUnpad(padded); // used === true, plain === original
 */

export class MalformedPaddingError extends Error {
  constructor(msg = 'Malformed padding') { super(msg); }
}

/** Generic interface for padding schemes used under an AEAD. */
export interface PaddingScheme {
  /** Maximum possible trailer length for this scheme (bytes). */
  readonly maxPad: number;

  /**
   * Pad `plain` to an alignment boundary. The RNG MUST be cryptographically secure.
   * @param plain input (WILL NOT be modified)
   * @param rng a function that returns `n` random bytes
   * @param align block size to align to (default 8)
   */
  pad(plain: Uint8Array, rng: (n: number) => Uint8Array, align?: number): Uint8Array;

  /**
   * Try to remove padding. Returns `{ used:false, plain }` when no padding is present (legacy).
   * Returns `{ used:true, plain }` when a valid trailer is removed.
   * Invalid/garbled trailers return `{ used:false, plain }` (safe, non-throwing).
   */
  tryUnpad(padded: Uint8Array): { used: boolean; plain: Uint8Array };
}

/**
 * Padding with a 40-bit magic, 1-byte VERSION, and CRC-8-ATM guard.
 *
 * Properties:
 *   - Default align = 8
 *   - Structure size (MAGIC40 + VER + LEN + CRC8) = 8 bytes
 *
 * Security notes:
 *   - Assumes padding happens *inside* an AEAD (ciphertext+tag authenticate the trailer).
 *   - Equality checks are best-effort constant-time; true constant time cannot be
 *     guaranteed in JS engines but this avoids early exits and data-dependent loops.
 *
 * Fixes implemented:
 *   - Fix A (alignment foot-gun): `computeK` derives the maximum feasible `k` from `align`
 *     and the 1-byte LEN constraint (`k ≤ STRUCT_SIZE + align - 1 ≤ 255`). No power-of-two
 *     restriction; any positive integer `align` that fits LEN is accepted.
 *   - Fix C (VERSION const): Introduce a VERSION byte within the magic scope
 *     (MAGIC40(5) + VER(1) replaces the previous MAGIC48(6)).
 */
export class Magic48VerCrc8Padding implements PaddingScheme {
  /** Total size of the trailer structure without the random prefix. */
  private static readonly STRUCT_SIZE = 8; // MAGIC40(5) + VER(1) + LEN(1) + CRC8(1)

  /** 40-bit magic constant (product/protocol unique). */
  private static readonly MAGIC40 = new Uint8Array([0xC4, 0xE7, 0x9B, 0xAD, 0xF2]); 

  /** Version byte (placed immediately after MAGIC40). */
  private static readonly VERSION = 0x29;

  /** CRC-8-ATM polynomial. */
  private static readonly CRC8_POLY = 0x07;

  /**
   * For the *default* align=8, the largest k needed is STRUCT_SIZE + 8 - 1 = 15.
   * This property reflects the default configuration for API parity with earlier versions.
   * (Internally, we derive the feasible k from the provided `align` at runtime.)
   */
  public readonly maxPad = Magic48VerCrc8Padding.STRUCT_SIZE + 8 - 1;

  // ---------------------------------------------------------------------------
  // Constant-time helpers (best-effort in JS/TS)
  // ---------------------------------------------------------------------------

  /** Constant-time equality for single byte. */
  private static ctEqU8(a: number, b: number): boolean {
    const x = ((a | 0) ^ (b | 0)) & 0xff;
    return x === 0;
  }

  /**
   * Constant-time equality for fixed-length byte arrays (no early exit).
   * Assumes a.length === b.length.
   */
  private static ctEqFixedLen(a: Uint8Array, b: Uint8Array): boolean {
    let diff = 0;
    const len = a.length;
    for (let i = 0; i < len; i++) {
      diff |= (a[i] ^ b[i]);
    }
    return diff === 0;
  }

  // ---------------------------------------------------------------------------
  // CRC-8-ATM over given buffer
  // ---------------------------------------------------------------------------

  /** Compute CRC-8-ATM (poly 0x07) over `buf`. */
  private crc8(buf: Uint8Array): number {
    let crc = 0x00;
    for (let i = 0; i < buf.length; i++) {
      crc ^= buf[i] & 0xff;
      for (let b = 0; b < 8; b++) {
        crc = (crc & 0x80) ? ((crc << 1) ^ Magic48VerCrc8Padding.CRC8_POLY) : (crc << 1);
        crc &= 0xff;
      }
    }
    return crc & 0xff;
  }

  // ---------------------------------------------------------------------------
  // Padding length computation (Fix A)
  // ---------------------------------------------------------------------------

  /**
   * Compute trailer length k such that:
   *   - (len + k) % align === 0
   *   - k >= STRUCT_SIZE (8 bytes)
   *   - k <= STRUCT_SIZE + align - 1
   *   - STRUCT_SIZE + align - 1 <= 255  (so LEN fits in one byte)
   *
   * @throws {MalformedPaddingError} if constraints cannot be satisfied.
   */
  private computeK(len: number, align: number): number {
    const s = Magic48VerCrc8Padding.STRUCT_SIZE;

    if (!Number.isInteger(align) || align < 1) {
      throw new MalformedPaddingError('align must be a positive integer');
    }
    if (s + align - 1 > 0xff) {
      throw new MalformedPaddingError('align too large for 1-byte LEN');
    }

    const maxPadForAlign = s + align - 1;

    // Minimal padding to reach the next multiple of `align`
    let k = (align - (len % align)) % align;
    if (k === 0) k = align;           // prefer a full block
    while (k < s) k += align;         // ensure room for structure

    if (k > maxPadForAlign) {
      throw new MalformedPaddingError('Cannot satisfy alignment within 1-byte LEN');
    }
    return k; // guarantees: (len + k) % align == 0 and k ∈ [STRUCT_SIZE .. s+align-1]
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Pad `plain` so that its length plus trailer is aligned to `align` (default 8).
   *
   * @param plain The plaintext to pad (will not be modified).
   * @param rng   A CSPRNG: given n, returns exactly n random bytes.
   * @param align Alignment boundary (positive integer). Default: 8.
   * @returns A new Uint8Array containing `plain || trailer`.
   * @throws  {MalformedPaddingError} if RNG misbehaves or constraints cannot be met.
   */
  public pad(plain: Uint8Array, rng: (n: number) => Uint8Array, align = 8): Uint8Array {
    const s = Magic48VerCrc8Padding.STRUCT_SIZE;
    const k = this.computeK(plain.length, align);
    const rndLen = k - s;

    const out = new Uint8Array(plain.length + k);
    out.set(plain, 0);

    if (rndLen > 0) {
      const rnd = rng(rndLen);
      if (!rnd || rnd.length !== rndLen) {
        throw new MalformedPaddingError('rng returned wrong length');
      }
      out.set(rnd, plain.length);
    }

    // Append MAGIC40 (5 bytes)
    const base = plain.length + rndLen;
    out.set(Magic48VerCrc8Padding.MAGIC40, base + 0);

    // VERSION byte
    out[base + 5] = Magic48VerCrc8Padding.VERSION & 0xff;

    // LEN byte (store k directly)
    out[base + 6] = k & 0xff;

    // CRC8 over MAGIC40 || VER || LEN  (7-byte input)
    const crcInput = new Uint8Array(7);
    crcInput.set(Magic48VerCrc8Padding.MAGIC40, 0); // 0..4
    crcInput[5] = Magic48VerCrc8Padding.VERSION & 0xff;
    crcInput[6] = k & 0xff;
    out[base + 7] = this.crc8(crcInput);

    return out;
  }

  /**
   * Attempt to remove a MAGIC40+VERSION+CRC8 trailer in a misuse-resistant way.
   *
   * Behavior:
   *   - If no valid trailer is present (legacy/plain input), returns `{ used:false, plain: padded }`.
   *   - If a valid trailer is present, returns `{ used:true, plain }` with the trailer removed.
   *   - Malformed/garbled trailers **do not throw**; they return `{ used:false, plain: padded }`.
   *
   * NOTE: This parser does not assume a particular `align` at unpad-time. It enforces
   *       minimal structure size and validates MAGIC40, VERSION, and CRC8. Given AEAD
   *       authentication, this remains safe while avoiding an align/foot-gun at parse time.
   *
   * @param padded Plaintext+trailer (already AEAD-verified ciphertext payload).
   * @returns `{ used, plain }` as described.
   */
  public tryUnpad(padded: Uint8Array): { used: boolean; plain: Uint8Array } {
    const s = Magic48VerCrc8Padding.STRUCT_SIZE;
    const fail = () => ({ used: false, plain: padded });

    // Need at least the 8-byte structure to even attempt parsing.
    if (padded.length < s) return fail();

    const end = padded.length;
    const crc = padded[end - 1] & 0xff;
    const lenByte = padded[end - 2] & 0xff;
    const verByte = padded[end - 3] & 0xff;

    // Bounds & range checks (public values; safe to branch on).
    // Minimal structure; cap by available bytes. (No maxPad check: align unknown here.)
    if (lenByte < s || lenByte > padded.length) return fail();

    // MAGIC40 is 5 bytes starting at end - STRUCT_SIZE
    const magicStart = end - s;
    const magic = padded.subarray(magicStart, magicStart + 5);

    // Constant-time MAGIC compare.
    const magicOk = Magic48VerCrc8Padding.ctEqFixedLen(magic, Magic48VerCrc8Padding.MAGIC40);
    if (!magicOk) return fail();

    // Constant-time VERSION compare.
    if (!Magic48VerCrc8Padding.ctEqU8(verByte, Magic48VerCrc8Padding.VERSION & 0xff)) return fail();

    // CRC8 over MAGIC40 || VER || LEN  (7-byte input)
    const crcInput = new Uint8Array(7);
    crcInput.set(Magic48VerCrc8Padding.MAGIC40, 0);
    crcInput[5] = verByte;
    crcInput[6] = lenByte;
    const expected = this.crc8(crcInput);

    // Constant-time single-byte compare for CRC.
    if (!Magic48VerCrc8Padding.ctEqU8(expected, crc)) return fail();

    // Success: strip trailer
    return { used: true, plain: padded.subarray(0, end - lenByte) };
  }
}