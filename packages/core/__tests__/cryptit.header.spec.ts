import { Cryptit }      from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

describe('Cryptit.headerDecode / isEncrypted helpers', () => {
  const crypt = new Cryptit(nodeProvider, { chunkSize: 1024 });

  it('extracts meta-data from a Base64 payload', async () => {
    const cipher = await crypt.encryptText('meta-probe', 'pw');
    const meta   = await Cryptit.headerDecode(cipher.uint8array);

    expect(meta).toMatchObject({
      scheme    : crypt.getScheme(),
      difficulty: crypt.getDifficulty(),
    });
    expect(meta.saltLength).toBeGreaterThan(0);
  });

  it('detects & decodes header embedded in a Blob', async () => {
    const blob  = await crypt.encryptFile(new Blob([Uint8Array.of(1, 2)]), 'pw');
    expect(await Cryptit.isEncrypted(blob)).toBe(true);

    const meta = await Cryptit.headerDecode(blob);
    expect(meta.scheme).toBe(crypt.getScheme());
    expect(meta.saltLength).toBeGreaterThan(0);
  });
});