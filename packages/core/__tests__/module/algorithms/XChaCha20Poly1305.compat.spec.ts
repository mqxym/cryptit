import { randomBytes } from 'crypto';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { XChaCha20Poly1305 } from '../../../src/algorithms/encryption/xchacha20poly1305/XChaCha20-Poly1305.js';
import { Magic48VerCrc8Padding } from '../../../src/algorithms/padding/magic48ver-crc8.js';
import { nodeProvider, importExtractableRawKey } from './_helper.js';

const te = new TextEncoder();

async function newX() {
  const keyBytes = new Uint8Array(randomBytes(32));
  const k = await importExtractableRawKey(keyBytes);
  const x = new XChaCha20Poly1305(nodeProvider);
  await x.setKey(k);
  return { x, keyBytes };
}

function xchachaLegacyEncrypt(key: Uint8Array, headerAAD: Uint8Array, plain: Uint8Array) {
  const nonce = nodeProvider.getRandomValues(new Uint8Array(XChaCha20Poly1305.IV_LENGTH));
  const cipher = headerAAD.length
    ? xchacha20poly1305(key, nonce, headerAAD)
    : xchacha20poly1305(key, nonce);
  const ct = cipher.encrypt(plain);
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}

function makePlain(n: number) {
  const u = new Uint8Array(n);
  for (let i = 0; i < n; i++) u[i] = (i * 23 + 9) & 0xff;
  return u;
}

describe('XChaCha20-Poly1305 legacy AAD fallback', () => {
  it('reads legacy header-only AAD (unpadded) under legacy auto policy', async () => {
    const { x, keyBytes } = await newX();
    const header = te.encode('XHDR');
    const pt = makePlain(55);

    const ct = xchachaLegacyEncrypt(keyBytes, header, pt);

    x.setAAD(header);
    x.setPaddingScheme(new Magic48VerCrc8Padding());
    x.setPaddingAADMode('require');
    x.setLegacyAADFallback({ enabled: true, policy: 'auto', tryEmptyAAD: false });

    const out = await x.decryptChunk(ct);
    expect(out).toEqual(pt);
  });

  it('reads legacy header-only AAD (padded) and strips trailer under legacy auto policy', async () => {
    const { x, keyBytes } = await newX();
    const header = te.encode('XHDR');
    const padder = new Magic48VerCrc8Padding();
    const rng = (n: number) => nodeProvider.getRandomValues(new Uint8Array(n));

    const orig = makePlain(128);
    const padded = padder.pad(orig.slice(), rng, 8);
    const ct = xchachaLegacyEncrypt(keyBytes, header, padded);

    x.setAAD(header);
    x.setPaddingScheme(new Magic48VerCrc8Padding());
    x.setPaddingAADMode('require');
    x.setLegacyAADFallback({ enabled: true, policy: 'auto' });

    const out = await x.decryptChunk(ct);
    expect(out).toEqual(orig);
  });
});