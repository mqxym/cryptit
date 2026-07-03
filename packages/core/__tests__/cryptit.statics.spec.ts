/* ------------------------------------------------------------------
   Static inspection helpers: isEncrypted / decodeHeader / decodeData
   These never decrypt - they only parse framing & header metadata.
   ------------------------------------------------------------------ */
import { Cryptit }            from '../src/index.js';
import { makeCrypt, SCHEMES } from './test.constants.js';

/* ── isEncrypted ─────────────────────────────────────────────────── */
describe('Cryptit.isEncrypted', () => {
  it('returns true for a real container (base64 & bytes)', async () => {
    const crypt  = makeCrypt();
    const cipher = await crypt.encryptText('detect-me', 'pw');
    expect(await Cryptit.isEncrypted(cipher.base64)).toBe(true);
    expect(await Cryptit.isEncrypted(cipher.uint8array)).toBe(true);
  });

  it('returns false for non-Cryptit input', async () => {
    expect(await Cryptit.isEncrypted('plain text')).toBe(false);
    expect(await Cryptit.isEncrypted(new Uint8Array(0))).toBe(false);
    expect(await Cryptit.isEncrypted(new Uint8Array([0x01]))).toBe(false); // magic ok, too short
    expect(await Cryptit.isEncrypted(new Uint8Array([0xff, 0xff, 0xff, 0xff]))).toBe(false);
  });
});

/* ── decodeHeader ────────────────────────────────────────────────── */
describe.each(SCHEMES)('Cryptit.decodeHeader (scheme %i)', scheme => {
  it('exposes scheme, difficulty and salt metadata', async () => {
    const crypt  = makeCrypt({ scheme, difficulty: 'low', saltStrength: 'high' });
    const cipher = await crypt.encryptText('hdr', 'pw');

    const meta = await Cryptit.decodeHeader(cipher.uint8array);
    expect(meta.scheme).toBe(scheme);
    expect(meta.difficulty).toBe('low');
    expect(meta.saltLength).toBe(16);                 // 'high' salt strength
    expect(meta.saltBytes.byteLength).toBe(16);
    expect(typeof meta.salt).toBe('string');          // base64 view
  });

  it('reflects the low salt strength (12 bytes)', async () => {
    const crypt  = makeCrypt({ scheme, difficulty: 'low', saltStrength: 'low' });
    const cipher = await crypt.encryptText('hdr', 'pw');
    const meta   = await Cryptit.decodeHeader(cipher.uint8array);
    expect(meta.saltLength).toBe(12);
  });
});

describe('Cryptit.decodeHeader - rejection', () => {
  it('rejects garbage input', async () => {
    await expect(Cryptit.decodeHeader('not-a-container')).rejects.toThrow();
    await expect(Cryptit.decodeHeader(new Uint8Array([0x01, 0x00]))).rejects.toThrow();
  });
});

/* ── decodeData (single-block IV/tag) ────────────────────────────── */
describe.each(SCHEMES)('Cryptit.decodeData single-block (scheme %i)', scheme => {
  it('extracts IV & tag sized to the active cipher', async () => {
    const crypt  = makeCrypt({ scheme, difficulty: 'low' });
    const cipher = await crypt.encryptText('peek', 'pw');

    const meta = await Cryptit.decodeData(cipher.uint8array);
    expect(meta.isChunked).toBe(false);
    if (!meta.isChunked) {
      const expectedIv = scheme === 1 ? 24 : 12; // XChaCha20 nonce vs AES-GCM IV
      expect(meta.params.ivLength).toBe(expectedIv);
      expect(meta.params.iv.byteLength).toBe(expectedIv);
      expect(meta.params.tagLength).toBe(16);
      expect(meta.params.tag.byteLength).toBe(16);
    }
  });
});
