/* ------------------------------------------------------------------
   ByteSource - out‑of‑bounds & zero‑length slices
   ------------------------------------------------------------------ */
import { ByteSource }   from '../../src/util/ByteSource.js';
import { base64Encode } from '../../src/util/bytes.js';

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