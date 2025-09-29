import { AESGCM } from '../../../src/algorithms/encryption/aes-gcm/AESGCM.js';
import { Magic48VerCrc8Padding } from '../../../src/algorithms/padding/magic48ver-crc8.js';
import { DecryptionError } from '../../../src/errors/index.js';
import { nodeProvider, generateAesGcmKey } from './_helper.js';

function makePlain(len = 123): Uint8Array {
  const u = new Uint8Array(len);
  for (let i = 0; i < len; i++) u[i] = (i * 31 + 7) & 0xff;
  return u;
}

describe('AESGCM + BaseAEADWithPadAAD (integration)', () => {
  it('round-trips with require mode and header AAD', async () => {
    const key = await generateAesGcmKey();

    const enc = new AESGCM(nodeProvider as any);
    await enc.setKey(key);
    enc.setAAD(new TextEncoder().encode('HEADER-v1'));
    enc.setPaddingScheme(new Magic48VerCrc8Padding());
    enc.setPaddingAlign(8);
    enc.setPaddingAADMode('require');

    const dec = new AESGCM(nodeProvider as any);
    await dec.setKey(key);
    dec.setAAD(new TextEncoder().encode('HEADER-v1'));
    dec.setPaddingScheme(new Magic48VerCrc8Padding());
    dec.setPaddingAlign(8);
    dec.setPaddingAADMode('require');

    const plain = makePlain(1024);
    const plainCopy = plain.slice();

    const ct = await enc.encryptChunk(plain);
    // source buffer must be zeroized
    expect(Array.from(plain).every((b) => b === 0)).toBe(true);

    const out = await dec.decryptChunk(ct);
    expect(out).toEqual(plainCopy);
  });

  it('auto mode resolves to require when padding scheme is set; forbid when not set', async () => {
    const key = await generateAesGcmKey();
    const header = new TextEncoder().encode('HDR');

    // auto + scheme => require  (compare to a copy; source is zeroized)
    {
      const enc = new AESGCM(nodeProvider as any);
      await enc.setKey(key);
      enc.setAAD(header);
      enc.setPaddingScheme(new Magic48VerCrc8Padding());
      enc.setPaddingAADMode('auto');

      const dec = new AESGCM(nodeProvider as any);
      await dec.setKey(key);
      dec.setAAD(header);
      dec.setPaddingScheme(new Magic48VerCrc8Padding());
      dec.setPaddingAADMode('auto');

      const pt = makePlain(33);
      const ptCopy = pt.slice();
      const ct = await enc.encryptChunk(pt);
      const out = await dec.decryptChunk(ct);
      expect(out).toEqual(ptCopy);
    }

    // auto + no scheme => forbid  (still zeroized; compare to copy)
    {
      const enc = new AESGCM(nodeProvider as any);
      await enc.setKey(key);
      enc.setAAD(header);
      enc.setPaddingScheme(null);
      enc.setPaddingAADMode('auto');

      const dec = new AESGCM(nodeProvider as any);
      await dec.setKey(key);
      dec.setAAD(header);
      dec.setPaddingScheme(null);
      dec.setPaddingAADMode('auto');

      const pt = makePlain(17);
      const ptCopy = pt.slice();
      const ct = await enc.encryptChunk(pt);
      const out = await dec.decryptChunk(ct);
      expect(out).toEqual(ptCopy);
    }
  });

  it('AAD mismatch (mode or align) causes AEAD auth failure', async () => {
    const key = await generateAesGcmKey();
    const plain = makePlain(50);

    // Encrypt with require/align=8
    const enc = new AESGCM(nodeProvider as any);
    await enc.setKey(key);
    enc.setAAD(new TextEncoder().encode('H1'));
    enc.setPaddingScheme(new Magic48VerCrc8Padding());
    enc.setPaddingAlign(8);
    enc.setPaddingAADMode('require');

    const ct = await enc.encryptChunk(plain.slice());

    // Decrypt with forbid (different mode)
    const dec1 = new AESGCM(nodeProvider as any);
    await dec1.setKey(key);
    dec1.setAAD(new TextEncoder().encode('H1'));
    dec1.setPaddingScheme(new Magic48VerCrc8Padding());
    dec1.setPaddingAlign(8);
    dec1.setPaddingAADMode('forbid');
    await expect(dec1.decryptChunk(ct)).rejects.toThrow(DecryptionError);

    // Decrypt with same mode but different align -> mismatch
    const dec2 = new AESGCM(nodeProvider as any);
    await dec2.setKey(key);
    dec2.setAAD(new TextEncoder().encode('H1'));
    dec2.setPaddingScheme(new Magic48VerCrc8Padding());
    dec2.setPaddingAlign(13);
    dec2.setPaddingAADMode('require');
    await expect(dec2.decryptChunk(ct)).rejects.toThrow(DecryptionError);

    // Decrypt with different header AAD
    const dec3 = new AESGCM(nodeProvider as any);
    await dec3.setKey(key);
    dec3.setAAD(new TextEncoder().encode('H2'));
    dec3.setPaddingScheme(new Magic48VerCrc8Padding());
    dec3.setPaddingAlign(8);
    dec3.setPaddingAADMode('require');
    await expect(dec3.decryptChunk(ct)).rejects.toThrow(DecryptionError);
  });

  it('forbid mode rejects legacy/plaintext that happens to end with a valid trailer', async () => {
    const key = await generateAesGcmKey();
    const header = new TextEncoder().encode('HEAD');

    const padder = new Magic48VerCrc8Padding();
    const rng = (n: number) => nodeProvider.getRandomValues(new Uint8Array(n));

    const legacy = new Uint8Array([1, 2, 3, 4, 5, 6, 7]);
    const legacyWithTrailer = padder.pad(legacy, rng, 8);

    const enc = new AESGCM(nodeProvider as any);
    await enc.setKey(key);
    enc.setAAD(header);
    enc.setPaddingScheme(new Magic48VerCrc8Padding());
    enc.setPaddingAADMode('forbid');

    const dec = new AESGCM(nodeProvider as any);
    await dec.setKey(key);
    dec.setAAD(header);
    dec.setPaddingScheme(new Magic48VerCrc8Padding());
    dec.setPaddingAADMode('forbid');

    const ct = await enc.encryptChunk(legacyWithTrailer.slice());
    await expect(dec.decryptChunk(ct)).rejects.toThrow(DecryptionError);
  });

  it('wrong key → decryption fails', async () => {
    const key1 = await generateAesGcmKey();
    const key2 = await generateAesGcmKey();

    const enc = new AESGCM(nodeProvider as any);
    await enc.setKey(key1);
    enc.setAAD(new TextEncoder().encode('HDR'));
    enc.setPaddingScheme(new Magic48VerCrc8Padding());
    enc.setPaddingAADMode('require');

    const dec = new AESGCM(nodeProvider as any);
    await dec.setKey(key2);
    dec.setAAD(new TextEncoder().encode('HDR'));
    dec.setPaddingScheme(new Magic48VerCrc8Padding());
    dec.setPaddingAADMode('require');

    const pt = makePlain(64);
    const ct = await enc.encryptChunk(pt);
    await expect(dec.decryptChunk(ct)).rejects.toThrow(DecryptionError);
  });

  it('decrypt fails on too-short ciphertext', async () => {
    const key = await generateAesGcmKey();
    const dec = new AESGCM(nodeProvider as any);
    await dec.setKey(key);
    dec.setAAD(new Uint8Array([]));
    dec.setPaddingScheme(null);
    dec.setPaddingAADMode('forbid');

    const tooShort = new Uint8Array(AESGCM.IV_LENGTH + AESGCM.TAG_LENGTH - 1);
    await expect(dec.decryptChunk(tooShort)).rejects.toThrow(DecryptionError);
  });

  it('setPaddingAlign validates bounds', async () => {
    const aes = new AESGCM(nodeProvider as any);
    await aes.setKey(await generateAesGcmKey());
    expect(() => aes.setPaddingAlign(0)).toThrow();
    expect(() => aes.setPaddingAlign(256)).toThrow();
    aes.setPaddingAlign(8);
  });

  it('zeroKey prevents further use', async () => {
    const aes = new AESGCM(nodeProvider as any);
    await aes.setKey(await generateAesGcmKey());
    aes.zeroKey();
    await expect(aes.encryptChunk(makePlain(8))).rejects.toThrow('Encryption key not set');
  });
});