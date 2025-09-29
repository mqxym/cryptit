import { AESGCM } from '../../../src/algorithms/encryption/aes-gcm/AESGCM.js';
import { Magic48VerCrc8Padding } from '../../../src/algorithms/padding/magic48ver-crc8.js';
import { DecryptionError } from '../../../src/errors/index.js';
import { nodeProvider, generateAesGcmKey } from './_helper.js';

const te = new TextEncoder();

async function legacyEncryptAESGCM(
  key: CryptoKey,
  headerAAD: Uint8Array,
  plain: Uint8Array
): Promise<Uint8Array> {
  const iv = nodeProvider.getRandomValues(new Uint8Array(AESGCM.IV_LENGTH));
  const params = headerAAD.length
    ? { name: 'AES-GCM', iv, additionalData: headerAAD }
    : { name: 'AES-GCM', iv };
  const buf = await nodeProvider.subtle.encrypt(params as AesGcmParams, key, plain as BufferSource);
  const ct = new Uint8Array(buf);
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return out;
}

function makePlain(n: number) {
  const u = new Uint8Array(n);
  for (let i = 0; i < n; i++) u[i] = (i * 11 + 5) & 0xff;
  return u;
}

describe('AESGCM legacy AAD fallback', () => {
  it('reads legacy header-only AAD (unpadded) under legacy auto policy', async () => {
    const key = await generateAesGcmKey();
    const header = te.encode('HDR-LEGACY');
    const pt = makePlain(73);

    // Legacy writer: header-only AAD, no padding
    const ct = await legacyEncryptAESGCM(key, header, pt);

    // New reader: strict for new writes, but legacy fallback enabled (auto)
    const dec = new AESGCM(nodeProvider);
    await dec.setKey(key);
    dec.setAAD(header);
    dec.setPaddingScheme(new Magic48VerCrc8Padding());
    dec.setPaddingAADMode('require');
    dec.setLegacyAADFallback({ enabled: true, policy: 'auto', tryEmptyAAD: false });

    const out = await dec.decryptChunk(ct);
    expect(out).toEqual(pt);
  });

  it('reads legacy header-only AAD (padded) and strips trailer under legacy auto policy', async () => {
    const key = await generateAesGcmKey();
    const header = te.encode('HDR-LEGACY');
    const padder = new Magic48VerCrc8Padding();
    const rng = (n: number) => nodeProvider.getRandomValues(new Uint8Array(n));

    const orig = makePlain(91);
    const padded = padder.pad(orig.slice(), rng, 8);

    // Legacy writer: header-only AAD, but payload already padded
    const ct = await legacyEncryptAESGCM(key, header, padded);

    const dec = new AESGCM(nodeProvider);
    await dec.setKey(key);
    dec.setAAD(header);
    dec.setPaddingScheme(new Magic48VerCrc8Padding());
    dec.setPaddingAADMode('require'); // strict for new writes
    dec.setLegacyAADFallback({ enabled: true, policy: 'auto' });

    const out = await dec.decryptChunk(ct);
    expect(out).toEqual(orig); // trailer stripped
  });

  it('can enforce strict legacy policy if desired (forbid)', async () => {
    const key = await generateAesGcmKey();
    const header = te.encode('HDR-LEGACY');
    const padder = new Magic48VerCrc8Padding();
    const rng = (n: number) => nodeProvider.getRandomValues(new Uint8Array(n));

    const orig = makePlain(40);
    const padded = padder.pad(orig.slice(), rng, 8);
    const ct = await legacyEncryptAESGCM(key, header, padded);

    const dec = new AESGCM(nodeProvider);
    await dec.setKey(key);
    dec.setAAD(header);
    dec.setPaddingScheme(new Magic48VerCrc8Padding());
    dec.setPaddingAADMode('require');
    dec.setLegacyAADFallback({ enabled: true, policy: 'forbid' });

    await expect(dec.decryptChunk(ct)).rejects.toThrow(DecryptionError);
  });
});