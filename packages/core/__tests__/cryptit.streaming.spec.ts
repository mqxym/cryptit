import { Cryptit }      from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

// jest.setTimeout(20_000);

/* ------------------------------------------------------------------ */
/*  Helper: collect full stream into a single Uint8Array               */
/* ------------------------------------------------------------------ */
async function collect(rs: ReadableStream<Uint8Array>) {
  const rd   = rs.getReader();
  const out: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await rd.read();
    if (done) break;
    out.push(value);
  }
  return Uint8Array.from(out.flatMap(c => [...c]));
}

/* ------------------------------------------------------------------ */
/*  Tests                                                              */
/* ------------------------------------------------------------------ */
describe('Cryptit streaming | Scheme 1 encrypt ↔ decrypt pipeline', () => {
    
  const crypt = new Cryptit(nodeProvider, {
    chunkSize : 16_384,   
    difficulty: 'low', 
    scheme: 1,
  });

  it('pipes through encrypt→decrypt streams with 65 kB input', async () => {
    const plain = crypto.getRandomValues(new Uint8Array(65_000));

    /* —— encrypt —— */
    const { header, writable, readable } = await crypt.createEncryptionStream('pw');
    const w = writable.getWriter();
    w.write(plain.slice(0, 32_000));   // each write ≤ 65 536 B
    w.write(plain.slice(32_000));
    w.close();

    const body = await collect(readable);
    const cipher = new Uint8Array(header.length + body.length);
    cipher.set(header);
    cipher.set(body, header.length);

    /* —— decrypt —— */
    const decStream = await crypt.createDecryptionStream('pw');
    const rsPlain   = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(cipher); c.close(); },
    }).pipeThrough(decStream);

    const roundtrip = await collect(rsPlain);
    expect(roundtrip).toEqual(plain);
  });
});

describe('Cryptit streaming | Scheme 0 encrypt ↔ decrypt pipeline', () => {
    
  const crypt = new Cryptit(nodeProvider, {
    chunkSize : 16_384,   
    difficulty: 'low', 
    scheme: 0,
  });

  it('pipes through encrypt→decrypt streams with 65 kB input', async () => {
    const plain = crypto.getRandomValues(new Uint8Array(65_000));

    /* —— encrypt —— */
    const { header, writable, readable } = await crypt.createEncryptionStream('pw');
    const w = writable.getWriter();
    w.write(plain.slice(0, 32_000));   // each write ≤ 65 536 B
    w.write(plain.slice(32_000));
    w.close();

    const body = await collect(readable);
    const cipher = new Uint8Array(header.length + body.length);
    cipher.set(header);
    cipher.set(body, header.length);

    /* —— decrypt —— */
    const decStream = await crypt.createDecryptionStream('pw');
    const rsPlain   = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(cipher); c.close(); },
    }).pipeThrough(decStream);

    const roundtrip = await collect(rsPlain);
    expect(roundtrip).toEqual(plain);
  });
});