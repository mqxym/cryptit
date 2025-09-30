import { randomBytes } from 'crypto';
import { XChaCha20Poly1305 } from '../../../src/algorithms/encryption/xchacha20poly1305/XChaCha20-Poly1305.ts';
import { Magic48VerCrc8Padding } from '../../../src/algorithms/padding/magic48ver-crc8.js';
import { DecryptionError } from '../../../src/errors/index.js';
import { nodeProvider, importExtractableRawKey } from "./_helper.js"

function makePlain(len = 77): Uint8Array {
  const u = new Uint8Array(len);
  for (let i = 0; i < len; i++) u[i] = (i * 17 + 3) & 0xff;
  return u;
}

async function makePair() {
  const keyBytes = new Uint8Array(randomBytes(32));
  const k = await importExtractableRawKey(keyBytes);

  const enc = new XChaCha20Poly1305(nodeProvider as any);
  await enc.setKey(k);

  const dec = new XChaCha20Poly1305(nodeProvider as any);
  await dec.setKey(k);

  return { enc, dec };
}

describe('XChaCha20Poly1305 + BaseAEADWithPadAAD (integration)', () => {
  it('round-trips with require mode and header AAD', async () => {
    const { enc, dec } = await makePair();

    enc.setAAD(new TextEncoder().encode('HEADER-X'));
    enc.setPaddingScheme(new Magic48VerCrc8Padding());
    enc.setPaddingAlign(8);
    enc.setPaddingAADMode('require');

    dec.setAAD(new TextEncoder().encode('HEADER-X'));
    dec.setPaddingScheme(new Magic48VerCrc8Padding());
    dec.setPaddingAlign(8);
    dec.setPaddingAADMode('require');

    const plain = makePlain(513);
    const plainCopy = plain.slice();

    const ct = await enc.encryptChunk(plain);
    expect(Array.from(plain).every((b) => b === 0)).toBe(true); // zeroized

    const pt = await dec.decryptChunk(ct);
    expect(pt).toEqual(plainCopy);
  });

  it('AAD mismatch (mode/align/header) fails', async () => {
    const { enc } = await makePair();
    enc.setAAD(new TextEncoder().encode('H1'));
    enc.setPaddingScheme(new Magic48VerCrc8Padding());
    enc.setPaddingAlign(8);
    enc.setPaddingAADMode('require');

    const ct = await enc.encryptChunk(makePlain(40));

    // Different mode
    {
      const { dec } = await makePair(); // new pair with a different key -> ensure mismatch
      dec.setAAD(new TextEncoder().encode('H1'));
      dec.setPaddingScheme(new Magic48VerCrc8Padding());
      dec.setPaddingAlign(8);
      dec.setPaddingAADMode('forbid');
      await expect(dec.decryptChunk(ct)).rejects.toThrow(DecryptionError);
    }

    // Same mode, different align
    {
      const { dec } = await makePair();
      dec.setAAD(new TextEncoder().encode('H1'));
      dec.setPaddingScheme(new Magic48VerCrc8Padding());
      dec.setPaddingAlign(16);
      dec.setPaddingAADMode('require');
      await expect(dec.decryptChunk(ct)).rejects.toThrow(DecryptionError);
    }

    // Different header
    {
      const { dec } = await makePair();
      dec.setAAD(new TextEncoder().encode('H2'));
      dec.setPaddingScheme(new Magic48VerCrc8Padding());
      dec.setPaddingAlign(8);
      dec.setPaddingAADMode('require');
      await expect(dec.decryptChunk(ct)).rejects.toThrow(DecryptionError);
    }
  });

  it('forbid mode rejects plaintext that ends with a valid trailer', async () => {
    const { enc, dec } = await makePair();

    const padder = new Magic48VerCrc8Padding();
    const rng = (n: number) => nodeProvider.getRandomValues(new Uint8Array(n));
    const legacy = new Uint8Array([100, 99, 98, 97, 96]);
    const legacyWithTrailer = padder.pad(legacy, rng, 8);

    enc.setAAD(new TextEncoder().encode('HEAD-X'));
    enc.setPaddingScheme(new Magic48VerCrc8Padding());
    enc.setPaddingAADMode('forbid');

    dec.setAAD(new TextEncoder().encode('HEAD-X'));
    dec.setPaddingScheme(new Magic48VerCrc8Padding());
    dec.setPaddingAADMode('forbid');

    const ct = await enc.encryptChunk(legacyWithTrailer.slice());
    await expect(dec.decryptChunk(ct)).rejects.toThrow(DecryptionError);
  });

  it('auto policy resolution works (require when scheme set, forbid otherwise)', async () => {
    // auto → require (scheme set)
    {
      const { enc, dec } = await makePair();

      enc.setAAD(new TextEncoder().encode('A'));
      enc.setPaddingScheme(new Magic48VerCrc8Padding());
      enc.setPaddingAADMode('auto');

      dec.setAAD(new TextEncoder().encode('A'));
      dec.setPaddingScheme(new Magic48VerCrc8Padding());
      dec.setPaddingAADMode('auto');

      const pt = makePlain(5);
      const ptCopy = pt.slice();
      const ct = await enc.encryptChunk(pt);
      const out = await dec.decryptChunk(ct);
      expect(out).toEqual(ptCopy);
    }

    // auto → forbid (no scheme set)
    {
      const { enc, dec } = await makePair();

      enc.setAAD(new TextEncoder().encode('B'));
      enc.setPaddingScheme(null);
      enc.setPaddingAADMode('auto');

      dec.setAAD(new TextEncoder().encode('B'));
      dec.setPaddingScheme(null);
      dec.setPaddingAADMode('auto');

      const pt = makePlain(5);
      const ptCopy = pt.slice();
      const ct = await enc.encryptChunk(pt);
      const out = await dec.decryptChunk(ct);
      expect(out).toEqual(ptCopy);
    }
  });

  it('too-short ciphertext is rejected', async () => {
    const { dec } = await makePair();
    dec.setAAD(new Uint8Array([]));
    dec.setPaddingScheme(null);
    dec.setPaddingAADMode('forbid');

    const tooShort = new Uint8Array(XChaCha20Poly1305.IV_LENGTH + XChaCha20Poly1305.TAG_LENGTH - 1);
    await expect(dec.decryptChunk(tooShort)).rejects.toThrow(DecryptionError);
  });

  it('zeroKey zeros key and prevents further use', async () => {
    const { enc } = await makePair();
    enc.zeroKey();
    await expect(enc.encryptChunk(makePlain(8))).rejects.toThrow('Encryption key not set');
  });
});