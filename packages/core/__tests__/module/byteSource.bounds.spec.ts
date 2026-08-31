/* ------------------------------------------------------------------
   ByteSource - out‑of‑bounds & zero‑length slices
   ------------------------------------------------------------------ */
import { ByteSource, FileByteSource } from '../../src/util/ByteSource.js';
import { base64Encode } from '../../src/util/bytes.js';
import { DecodingError } from '../../src/errors/index.js';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SAMPLE = crypto.getRandomValues(new Uint8Array(256));

const SOURCES: Array<[string, Blob | Uint8Array | string]> = [
  ['Uint8Array', SAMPLE],
  ['Blob',       new Blob([SAMPLE])],
  ['Base64',     base64Encode(SAMPLE)],
];

describe.each(SOURCES)('ByteSource (%s)', (_label, input) => {

  const bs = new ByteSource(input as any);

  it('throws RangeError when slice exceeds bounds', async () => {
    await expect(bs.read(200, 100)).rejects.toThrow(RangeError);
  });

  it('returns 0‑byte slice at EOF', async () => {
    const tail = await bs.read(bs.length, 0);
    expect(tail.byteLength).toBe(0);
  });
});

describe('FileByteSource short reads', () => {
  it('rejects when a file is truncated after opening', async () => {
    const dir = await fs.mkdtemp(join(tmpdir(), 'cryptit-byte-source-'));
    const path = join(dir, 'input.bin');
    await fs.writeFile(path, SAMPLE);
    const source = await FileByteSource.open(path);

    try {
      await fs.truncate(path, 8);
      await expect(source.read(0, SAMPLE.length)).rejects.toThrow(DecodingError);
    } finally {
      await source.close();
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});