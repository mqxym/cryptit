/* ------------------------------------------------------------------
   T -02 - Tampering detection across helpers
   ------------------------------------------------------------------ */
import { Cryptit } from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { base64Decode, base64Encode } from '../src/util/bytes.js';
import { decodeHeader } from '../src/header/decoder.js';
import { DecryptionError } from '../src/errors/index.js';

function flipBit(buf: Uint8Array, i = 0): Uint8Array {
  const out = buf.slice();
  out[i] ^= 0x80;               // toggle MSB
  return out;
}

async function collect(rs: ReadableStream<Uint8Array>) {
  const r = rs.getReader(); const parts: Uint8Array[] = [];
  for (;;) { const { done, value } = await r.read(); if (done) break; parts.push(value); }
  return Uint8Array.from(parts.flatMap(b => [...b]));
}

describe('Cryptit - ciphertext integrity guard -rails', () => {

  const crypt = new Cryptit(nodeProvider, { chunkSize: 8_192 });

  it('decryptText() ⇒ DecryptionError on flipped payload bit', async () => {
    const b64   = await crypt.encryptText('tamper -probe', 'pw');
    const raw   = base64Decode(b64);
    const { headerLen } = decodeHeader(raw);          // keep header intact
    const bad   = flipBit(raw, headerLen + 3);
    await expect(crypt.decryptText(base64Encode(bad), 'pw'))
      .rejects.toThrow(DecryptionError);
  });

  it('decryptFile() ⇒ DecryptionError on modified Blob data', async () => {
    const plain = new Blob([Uint8Array.of(1, 2, 3, 4, 5, 6)]);
    const enc   = await crypt.encryptFile(plain, 'pw');
    const buf   = new Uint8Array(await enc.arrayBuffer());
    const { headerLen } = decodeHeader(buf);
    const tampered = flipBit(buf, headerLen + 1);
    await expect(crypt.decryptFile(new Blob([tampered]), 'pw'))
      .rejects.toThrow(DecryptionError);
  });

  it('streaming decrypt ⇒ DecryptionError when body corrupted', async () => {
    /* 1 ► build a valid ciphertext stream */
    const { header, writable, readable } = await crypt.createEncryptionStream('pw');
    const w = writable.getWriter();
    w.write(Uint8Array.of(9, 8, 7, 6, 5, 4, 3, 2));
    w.close();

    /* 2 ► concatenate header + body */
    const body = await collect(readable);
    const full = new Uint8Array(header.length + body.length);
    full.set(header); full.set(body, header.length);

    /* 3 ► flip a byte *after* the header */
    const { headerLen } = decodeHeader(full);
    const bad = flipBit(full, headerLen + 10);

    /* 4 ► pipe through a fresh decryption stream */
    const decTs = await crypt.createDecryptionStream('pw');
    const rs    = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(bad); c.close(); },
    }).pipeThrough(decTs);

    await expect(collect(rs)).rejects.toThrow(DecryptionError);
  });
});