import { Cryptit } from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { base64Decode, base64Encode } from '../src/util/bytes.js';
import { decodeHeader } from '../src/header/decoder.js';
import { DecryptionError } from '../src/errors/index.js';
import { SCHEMES } from './test.constants.js';

function flipBit(buf: Uint8Array, i = 0): Uint8Array {
  const out = buf.slice();
  out[i] ^= 0x80;
  return out;
}
import { collectStream as collect } from '../src/util/stream.js';

describe.each(SCHEMES)('Cryptit - ciphertext integrity guard (scheme %i)', scheme => {
  let crypt: Cryptit;

  beforeEach(() => {
    crypt = new Cryptit(nodeProvider, { chunkSize: 8_192, scheme });
  });

  it('decryptText() ⇒ throws DecryptionError on flipped payload bit', async () => {
    const b64   = await crypt.encryptText('tamper -probe', 'pw');
    const raw   = base64Decode(b64.base64);
    const { headerLen } = decodeHeader(raw);
    const bad   = flipBit(raw, headerLen + 3);
    await expect(crypt.decryptText(base64Encode(bad), 'pw'))
      .rejects.toThrow(DecryptionError);
  });

  it('decryptFile() ⇒ throws DecryptionError on modified Blob data', async () => {
    const plain = new Blob([Uint8Array.of(1, 2, 3, 4, 5, 6)]);
    const enc   = await crypt.encryptFile(plain, 'pw');
    const buf   = new Uint8Array(await enc.arrayBuffer());
    const { headerLen } = decodeHeader(buf);
    const tampered = flipBit(buf, headerLen + 1);
    await expect(crypt.decryptFile(new Blob([tampered as BufferSource]), 'pw'))
      .rejects.toThrow(DecryptionError);
  });

  it('streaming decrypt ⇒ throws DecryptionError when body corrupted', async () => {
    /* build a valid ciphertext stream */
    const { header, writable, readable } = await crypt.createEncryptionStream('pw');
    const w = writable.getWriter();
    w.write(Uint8Array.of(9, 8, 7, 6, 5, 4, 3, 2));
    w.close();

    /* concatenate header + body */
    const body = await collect(readable);
    const full = new Uint8Array(header.length + body.length);
    full.set(header);
    full.set(body, header.length);

    /* flip a byte *after* the header */
    const { headerLen } = decodeHeader(full);
    const bad = flipBit(full, headerLen + 10);

    /* pipe through a fresh decryption stream */
    const decTs = await crypt.createDecryptionStream('pw');
    const rs    = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(bad); c.close(); },
    }).pipeThrough(decTs);

    await expect(collect(rs)).rejects.toThrow(DecryptionError);
  });
});