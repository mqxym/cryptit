// packages/core/src/util/convertible.ts
import { base64Encode } from './bytes.js';

function wipe(buf?: Uint8Array | null) {
  try { if (buf) buf.fill(0); } catch {}
}

function hexEncode(u8: Uint8Array): string {
  let s = '';
  for (let i = 0; i < u8.length; i++) {
    const v = u8[i].toString(16).padStart(2, '0');
    s += v;
  }
  return s;
}

/**
 * Normalizes user input (string or Uint8Array) to bytes.
 * You can clear() it to securely wipe the underlying memory.
 */
export class ConvertibleInput {
  private bytes: Uint8Array;
  private destroyed = false;

  static from(input: string | Uint8Array | ConvertibleInput): ConvertibleInput {
    if (input instanceof ConvertibleInput) return input;
    if (typeof input === 'string') return new ConvertibleInput(new TextEncoder().encode(input));
    if (input instanceof Uint8Array) return new ConvertibleInput(input);
    throw new TypeError('ConvertibleInput: unsupported input type');
  }

  constructor(bytes: Uint8Array) { this.bytes = bytes; }

  toUint8Array(): Uint8Array {
    if (this.destroyed) throw new Error('ConvertibleInput: already cleared');
    return this.bytes;
  }

  clear(): void {
    if (!this.destroyed) {
      wipe(this.bytes);
      // keep an empty buffer so accidental reuse throws
      this.bytes = new Uint8Array(0);
      this.destroyed = true;
    }
  }
}

/**
 * Wraps bytes and exposes multiple views, with secure wiping via clear().
 * String(result) yields Base64 for convenience.
 */
export class ConvertibleOutput {
  private bytes: Uint8Array;
  private destroyed = false;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /** Raw bytes view (do NOT mutate). */
  get uint8array(): Uint8Array {
    if (this.destroyed) throw new Error('ConvertibleOutput: already cleared');
    return this.bytes;
  }

  /** Base64 view of the underlying bytes. */
  get base64(): string {
    if (this.destroyed) throw new Error('ConvertibleOutput: already cleared');
    return base64Encode(this.bytes);
  }

  /** Hex view of the underlying bytes. */
  get hex(): string {
    if (this.destroyed) throw new Error('ConvertibleOutput: already cleared');
    return hexEncode(this.bytes);
  }

  /** UTF-8 decoded string (useful for decrypted text). */
  get text(): string {
    if (this.destroyed) throw new Error('ConvertibleOutput: already cleared');
    return new TextDecoder().decode(this.bytes);
  }

  /** Securely zero the buffer. */
  clear(): void {
    if (!this.destroyed) {
      wipe(this.bytes);
      this.bytes = new Uint8Array(0);
      this.destroyed = true;
    }
  }

  /** For backwards ergonomics: String(output) -> Base64 */
  toString(): string { return this.base64; }
}