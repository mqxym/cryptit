import { Cryptit }      from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

describe('Cryptit.decodeData (payload inspector)', () => {
  const crypt = new Cryptit(nodeProvider);

  it('extracts IV + auth-tag from an encryptText payload', async () => {
    const cipher = await crypt.encryptText('peek-iv', 'pw');

    const meta = await Cryptit.decodeData(cipher);
    expect(meta.isChunked).toBe(false);
    if (!meta.isChunked) {
      expect(meta.params.iv.byteLength).toBe(12);   // AES-GCM IV length
      expect(meta.params.tag.byteLength).toBe(16);  // 128-bit auth-tag
      expect(meta.payloadLength).toBeGreaterThan(12 + 16);
    }
  });

  it('reports chunk statistics for an encrypted 2 MiB file', async () => {
    const plain = new Blob([crypto.getRandomValues(new Uint8Array(2_097_152))]); // 2 MiB
    const enc   = await crypt.encryptFile(plain, 'pw');

    const info = await Cryptit.decodeData(enc);
    expect(info.isChunked).toBe(true);
    if (info.isChunked) {
      expect(info.chunks.chunkSize).toBeGreaterThan(crypt.getChunkSize());
      expect(info.chunks.count).toBeGreaterThanOrEqual(4);
      expect(info.chunks.totalPayload).toBeGreaterThanOrEqual(plain.size);
    }
  });
});