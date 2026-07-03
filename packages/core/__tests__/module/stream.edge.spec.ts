/* ------------------------------------------------------------------
   Streaming edge cases:
     • empty (0-byte) end-to-end stream round-trip
     • a frame whose declared length is exactly the IV+tag minimum
     • framed ciphertext delivered one byte at a time (reassembly)
   ------------------------------------------------------------------ */
import { EncryptTransform } from '../../src/stream/EncryptTransform.js';
import { DecryptTransform } from '../../src/stream/DecryptTransform.js';
import type { EncryptionAlgorithm } from '../../src/types/index.js';
import { collectStream as collect } from '../../src/util/stream.js';
import { makeCrypt, randomBytes, SCHEMES } from '../test.constants.js';

/* Echo engine with realistic IV/TAG sizing so min-frame maths are exercised. */
class NopEngine implements EncryptionAlgorithm {
  async encryptChunk(p: Uint8Array) { return p; }
  async decryptChunk(c: Uint8Array) { return c; }
  async setKey() {}
  zeroKey() {}
  readonly IV_LENGTH = 12;
  readonly TAG_LENGTH = 16;
  setAAD(_aad: Uint8Array): void {}
}

/* ── empty end-to-end stream ─────────────────────────────────────── */
describe.each(SCHEMES)('Empty stream round-trip (scheme %i)', scheme => {
  it('encrypts and decrypts a zero-byte stream', async () => {
    const crypt = makeCrypt({ scheme, difficulty: 'low' });

    const { header, writable, readable } = await crypt.createEncryptionStream('pw');
    await writable.close();                       // no writes at all
    const body = await collect(readable);

    const cipher = new Uint8Array(header.length + body.length);
    cipher.set(header);
    cipher.set(body, header.length);

    const dec   = await crypt.createDecryptionStream('pw');
    const plain = await collect(
      new ReadableStream<Uint8Array>({ start(c) { c.enqueue(cipher); c.close(); } })
        .pipeThrough(dec),
    );
    expect(plain.length).toBe(0);
  });
});

/* ── exact minimum frame length is accepted ──────────────────────── */
describe('DecryptTransform minimum-frame boundary', () => {
  it('accepts a frame declared at exactly IV + TAG bytes', async () => {
    const engine = new NopEngine();
    const min    = engine.IV_LENGTH + engine.TAG_LENGTH; // 28
    const payload = randomBytes(min);

    const frame = new Uint8Array(4 + min);
    new DataView(frame.buffer).setUint32(0, min, false);
    frame.set(payload, 4);

    const dec = new DecryptTransform(engine, 8).toTransformStream();
    const out = await collect(
      new ReadableStream<Uint8Array>({ start(c) { c.enqueue(frame); c.close(); } })
        .pipeThrough(dec),
    );
    expect(out).toEqual(payload); // echo engine returns the chunk verbatim
  });
});

/* ── frame reassembly across single-byte deliveries ──────────────── */
describe('DecryptTransform frame reassembly', () => {
  it('reconstructs plaintext when ciphertext arrives one byte per chunk', async () => {
    const engine = new NopEngine();
    const plain  = randomBytes(5_000);

    // chunkSize 2048 → per-write limit is chunkSize*4 (8192 B), so one write fits;
    // the 5 000-byte payload still spans multiple frames.
    const enc = new EncryptTransform(engine, 2048).toTransformStream();
    const cipher = await collect(
      new ReadableStream<Uint8Array>({ start(c) { c.enqueue(plain); c.close(); } })
        .pipeThrough(enc),
    );

    const dec = new DecryptTransform(engine, 2048).toTransformStream();
    const out = await collect(
      new ReadableStream<Uint8Array>({
        start(c) {
          for (const b of cipher) c.enqueue(Uint8Array.of(b)); // dribble byte-by-byte
          c.close();
        },
      }).pipeThrough(dec),
    );
    expect(out).toEqual(plain);
  });
});
