import { Cryptit } from '../src/index.js';
import { decodeHeader } from '../src/header/decoder.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { collectStream } from '../src/util/stream.js';
import { SCHEMES, randomBytes } from './test.constants.js';

const CHUNK_SIZE = 32;
const TERMINAL_FLAG = 0x80000000;
const LENGTH_MASK = 0x7fffffff;

function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function splitRecords(container: Uint8Array): {
  header: Uint8Array;
  records: Uint8Array[];
} {
  const { headerLen } = decodeHeader(container);
  const records: Uint8Array[] = [];
  let offset = headerLen;

  while (offset < container.length) {
    if (container.length - offset < 4) throw new Error('Incomplete frame word in test fixture');
    const word = new DataView(container.buffer, container.byteOffset + offset, 4)
      .getUint32(0, false);
    const length = word & LENGTH_MASK;
    const end = offset + 4 + length;
    if (end > container.length) throw new Error('Incomplete frame body in test fixture');
    records.push(container.slice(offset, end));
    offset = end;
  }

  return { header: container.slice(0, headerLen), records };
}

async function encryptStream(crypt: Cryptit, plain: Uint8Array): Promise<Uint8Array> {
  const { header, writable, readable } = await crypt.createEncryptionStream('pw');
  const writer = writable.getWriter();
  const bodyPromise = collectStream(readable);
  await writer.write(plain);
  await writer.close();
  return concat(header, await bodyPromise);
}

async function decryptStream(crypt: Cryptit, container: Uint8Array): Promise<Uint8Array> {
  const transform = await crypt.createDecryptionStream('pw');
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(container);
      controller.close();
    },
  });
  return collectStream(source.pipeThrough(transform));
}

describe.each(SCHEMES)('authenticated streaming integrity | scheme %i', scheme => {
  const makeCrypt = () => new Cryptit(nodeProvider, {
    scheme,
    difficulty: 'low',
    chunkSize: CHUNK_SIZE,
  });

  it('marks the default stream format and emits a terminal record', async () => {
    const container = await encryptStream(makeCrypt(), new Uint8Array(0));
    const { header, records } = splitRecords(container);
    const terminalWord = new DataView(
      records[0].buffer,
      records[0].byteOffset,
      4,
    ).getUint32(0, false);

    expect(header[1] & 0x08).toBe(0x08);
    expect(records).toHaveLength(1);
    expect((terminalWord & TERMINAL_FLAG) >>> 0).toBe(TERMINAL_FLAG);
    expect(await decryptStream(makeCrypt(), container)).toEqual(new Uint8Array(0));
  });

  it.each([
    ['deletes a complete middle record', (records: Uint8Array[]) => [records[0], ...records.slice(2)]],
    ['reorders complete records', (records: Uint8Array[]) => [records[1], records[0], ...records.slice(2)]],
    ['duplicates a complete record', (records: Uint8Array[]) => [records[0], records[0], ...records.slice(1)]],
    ['removes the terminal record', (records: Uint8Array[]) => records.slice(0, -1)],
    ['appends data after the terminal record', (records: Uint8Array[]) => [...records, records[0]]],
  ])('rejects when an attacker %s', async (_label, mutate) => {
    const crypt = makeCrypt();
    const container = await encryptStream(crypt, randomBytes(CHUNK_SIZE * 3));
    const { header, records } = splitRecords(container);
    expect(records.length).toBeGreaterThanOrEqual(4);

    const tampered = concat(header, ...mutate(records));
    await expect(decryptStream(makeCrypt(), tampered)).rejects.toThrow();
  });

  it('rejects a stream truncated to its header', async () => {
    const container = await encryptStream(makeCrypt(), randomBytes(CHUNK_SIZE));
    const { header } = splitRecords(container);
    await expect(decryptStream(makeCrypt(), header)).rejects.toThrow();
  });

  it('retains explicit legacy stream writes for older readers', async () => {
    const legacyWriter = new Cryptit(nodeProvider, {
      scheme,
      difficulty: 'low',
      chunkSize: CHUNK_SIZE,
      streamFormat: 'legacy',
    });
    const plain = randomBytes(CHUNK_SIZE * 3);
    const container = await encryptStream(legacyWriter, plain);
    const { header, records } = splitRecords(container);

    expect(header[1] & 0x08).toBe(0);
    expect(records).toHaveLength(3);
    expect(await decryptStream(makeCrypt(), container)).toEqual(plain);
  });

  it('continues to read legacy header-only empty files', async () => {
    const legacyWriter = new Cryptit(nodeProvider, {
      scheme,
      difficulty: 'low',
      streamFormat: 'legacy',
    });
    const encrypted = await legacyWriter.encryptFile(new Blob([]), 'pw');
    const decrypted = await makeCrypt().decryptFile(encrypted, 'pw');

    expect(encrypted.size).toBe(decodeHeader(new Uint8Array(await encrypted.arrayBuffer())).headerLen);
    expect(decrypted.size).toBe(0);
  });
});