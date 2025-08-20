/* ------------------------------------------------------------------
   Header tampering causes authentication failure (schemes 0 & 1)
   ------------------------------------------------------------------ */
import { Cryptit } from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { base64Decode, base64Encode } from '../src/util/bytes.js';
import { DecryptionError } from '../src/errors/index.js';
import { SCHEMES } from './test.constants.js';
import { collectStream as collect } from '../src/util/stream.js';

function flipBit(buf: Uint8Array, byteIndex = 1, mask = 0x01): Uint8Array {
  // default: flip a low bit in the info byte (difficulty LSB)
  const out = buf.slice();
  out[byteIndex] ^= mask;
  return out;
}

describe.each(SCHEMES)('Cryptit - header tampering (scheme %i)', scheme => {
  let crypt: Cryptit;

  beforeEach(() => {
    crypt = new Cryptit(nodeProvider, { scheme, difficulty: 'low', saltStrength: 'low' });
  });

  it('decryptText() ⇒ throws DecryptionError when header info byte is tampered', async () => {
    const b64   = await crypt.encryptText('hdr-check', 'pw');
    const raw   = base64Decode(b64.base64);

    // Flip a bit in the header's info byte (index 1) without touching the body
    const tampered = flipBit(raw, 1, 0x01);

    await expect(crypt.decryptText(base64Encode(tampered), 'pw'))
      .rejects.toThrow(DecryptionError);
  });

  it('decryptFile() ⇒ throws DecryptionError when header is tampered', async () => {
    const plain = new Blob([Uint8Array.of(1, 2, 3, 4)]);
    const enc   = await crypt.encryptFile(plain, 'pw');

    const buf       = new Uint8Array(await enc.arrayBuffer());
    const tampered  = flipBit(buf, 1, 0x04); // flip another bit in the info byte

    await expect(crypt.decryptFile(new Blob([tampered as BufferSource]), 'pw'))
      .rejects.toThrow(DecryptionError);
  });

  it('streaming decrypt ⇒ throws DecryptionError when header is tampered', async () => {
    const { header, writable, readable } = await crypt.createEncryptionStream('pw');

    // write a small payload
    const w = writable.getWriter();
    w.write(Uint8Array.of(9, 8, 7, 6));
    w.close();

    // tamper the header (keep body intact)
    const body      = await collect(readable);
    const badHeader = flipBit(header, 1, 0x02);

    const full = new Uint8Array(badHeader.length + body.length);
    full.set(badHeader);
    full.set(body, badHeader.length);

    const decTs = await crypt.createDecryptionStream('pw');
    const rs    = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(full); c.close(); },
    }).pipeThrough(decTs);

    await expect(collect(rs)).rejects.toThrow(DecryptionError);
  });
});