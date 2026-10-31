import { Cryptit }      from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { SchemeRegistry } from '../src/config/SchemeRegistry.js';
import { SCHEMES } from './setup.js';

describe('Cryptit.decodeData (payload inspector)', () => {
  const crypt = new Cryptit(nodeProvider);

  it('extracts IV + auth-tag from an encryptText payload', async () => {
    const cipher = (await crypt.encryptText('peek-iv', 'pw'));

    const meta = await Cryptit.decodeData(cipher.uint8array);
    expect(meta.isChunked).toBe(false);
    if (!meta.isChunked) {
      expect(meta.params.iv.byteLength).toBe(12);   // AES-GCM IV length
      expect(meta.params.tag.byteLength).toBe(16);  // 128-bit auth-tag
      expect(meta.payloadLength).toBe(16); // padded data
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

import { encodeHeader } from '../src/header/encoder.js';
import { InvalidHeaderError } from '../src/errors/index.js';

describe('Cryptit.decodeData - empty & too-short payloads', () => {
  it('returns zero-chunk stats for authenticated empty containers', async () => {
    const crypt = new Cryptit(nodeProvider, { difficulty: 'low', saltStrength: 'low' });
    const emptyBlob = await crypt.encryptFile(new Blob([]), 'pw');
    const info = await Cryptit.decodeData(emptyBlob);
    expect(info.isChunked).toBe(true);
    if (info.isChunked) {
      expect(info.chunks.count).toBe(0);
      expect(info.chunks.totalPayload).toBe(0);
    }
  });

  it('throws on non-chunked payload shorter than IV+TAG', async () => {
    const crypt = new Cryptit(nodeProvider, { scheme: 0, difficulty: 'low', saltStrength: 'low' });
    // Create a valid header then append 10 bytes, which is < IV(12)+TAG(16)
    const salt = new Uint8Array(12).fill(1);
    const header = encodeHeader(crypt.getScheme(), 'low', 'low', salt);
    const bad = new Uint8Array(header.length + 10);
    bad.set(header);
    bad.fill(0xAA, header.length);

    await expect(Cryptit.decodeData(bad)).rejects.toThrow(InvalidHeaderError);
  });
});

describe('Cryptit.decodeData - bounded inspection', () => {
  it.each(SCHEMES)('reads only metadata from large scheme %i text payloads', async scheme => {
    const header = encodeHeader(scheme, 'low', 'low', new Uint8Array(12));
    const length = 1024 ** 3;
    const reads: number[] = [];
    const source = {
      length,
      async read(offset: number, size: number): Promise<Uint8Array> {
        reads.push(size);
        if (size > 256) throw new Error('Inspection attempted a whole-payload read');
        const bytes = new Uint8Array(size).fill(0xff);
        if (offset === 0) bytes.set(header);
        if (offset + size > length - 16) {
          bytes.fill(0xa5, Math.max(0, length - 16 - offset));
        }
        return bytes;
      },
    };

    const result = await Cryptit.decodeData(source);
    expect(result.isChunked).toBe(false);
    if (result.isChunked) throw new Error('Expected a text payload');
    const ivLength = SchemeRegistry.get(scheme).cipher.IV_LENGTH;
    expect(result.params.iv).toEqual(new Uint8Array(ivLength).fill(0xff));
    expect(result.params.tag).toEqual(new Uint8Array(16).fill(0xa5));
    expect(result.payloadLength).toBe(length - header.length - ivLength - 16);
    expect(Math.max(...reads)).toBeLessThanOrEqual(256);
  });

  it.each([1, 2, 3])('rejects a %i-byte payload with a typed header error', async length => {
    const header = encodeHeader(0, 'low', 'low', new Uint8Array(12));
    const container = new Uint8Array(header.length + length);
    container.set(header);
    await expect(Cryptit.decodeData(container)).rejects.toThrow(InvalidHeaderError);
  });
});