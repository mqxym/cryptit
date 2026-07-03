/* ------------------------------------------------------------------
   File encryption edge cases: chunk-boundary payload sizes and
   header-driven scheme auto-detection on decrypt.
   ------------------------------------------------------------------ */
import { makeCrypt, randomBytes } from './test.constants.js';

describe('Cryptit file chunk-boundary sizes', () => {
  const CHUNK = 4096;

  it.each([CHUNK - 1, CHUNK, CHUNK + 1])(
    'round-trips a %i-byte Blob across the chunk boundary',
    async size => {
      const crypt = makeCrypt({ chunkSize: CHUNK, difficulty: 'low' });
      const data  = randomBytes(size);
      const blob  = new Blob([data]);

      const enc = await crypt.encryptFile(blob, 'pw');
      const dec = await crypt.decryptFile(enc, 'pw');

      expect(new Uint8Array(await dec.arrayBuffer())).toEqual(data);
    },
  );
});

describe('Cryptit file scheme auto-detection', () => {
  it('decrypts a scheme-1 file with a reader configured for scheme 0', async () => {
    const writer = makeCrypt({ scheme: 1, difficulty: 'low' });
    const data   = randomBytes(20_000);
    const enc    = await writer.encryptFile(new Blob([data]), 'pw');

    // Reader defaults to scheme 0; the header must drive engine selection.
    const reader = makeCrypt({ scheme: 0, difficulty: 'low' });
    const dec    = await reader.decryptFile(enc, 'pw');

    expect(new Uint8Array(await dec.arrayBuffer())).toEqual(data);
  });
});
