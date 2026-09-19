import { Cryptit } from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { collectStream } from '../src/util/stream.js';
import { SCHEMES, randomBytes } from './test.constants.js';

function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

async function writeAndCollect(
  stream: Awaited<ReturnType<Cryptit['createEncryptionStream']>>,
  plain: Uint8Array,
): Promise<Uint8Array> {
  const bodyPromise = collectStream(stream.readable);
  const writer = stream.writable.getWriter();
  await writer.write(plain);
  await writer.close();
  return concat(stream.header, await bodyPromise);
}

async function feedAndCollect(
  transform: TransformStream<Uint8Array, Uint8Array>,
  cipher: Uint8Array,
): Promise<Uint8Array> {
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(cipher);
      controller.close();
    },
  });
  return collectStream(source.pipeThrough(transform));
}

describe.each(SCHEMES)('concurrent operation isolation | scheme %i', scheme => {
  it('keeps overlapping text encryptions from one instance independent', async () => {
    const crypt = new Cryptit(nodeProvider, { scheme, difficulty: 'low' });
    const [firstCipher, secondCipher] = await Promise.all([
      crypt.encryptText('first plaintext', 'first-password'),
      crypt.encryptText('second plaintext', 'second-password'),
    ]);

    const [firstPlain, secondPlain] = await Promise.all([
      new Cryptit(nodeProvider).decryptText(firstCipher.uint8array, 'first-password'),
      new Cryptit(nodeProvider).decryptText(secondCipher.uint8array, 'second-password'),
    ]);
    expect(firstPlain.text).toBe('first plaintext');
    expect(secondPlain.text).toBe('second plaintext');
  });

  it('keeps overlapping file encryptions from one instance independent', async () => {
    const crypt = new Cryptit(nodeProvider, { scheme, difficulty: 'low', chunkSize: 64 });
    const firstPlain = randomBytes(150);
    const secondPlain = randomBytes(170);
    const [firstCipher, secondCipher] = await Promise.all([
      crypt.encryptFile(new Blob([firstPlain]), 'first-password'),
      crypt.encryptFile(new Blob([secondPlain]), 'second-password'),
    ]);

    const [firstResult, secondResult] = await Promise.all([
      new Cryptit(nodeProvider).decryptFile(firstCipher, 'first-password'),
      new Cryptit(nodeProvider).decryptFile(secondCipher, 'second-password'),
    ]);
    expect(new Uint8Array(await firstResult.arrayBuffer())).toEqual(firstPlain);
    expect(new Uint8Array(await secondResult.arrayBuffer())).toEqual(secondPlain);
  });

  it('keeps overlapping encryption streams from one instance independent', async () => {
    const crypt = new Cryptit(nodeProvider, { scheme, difficulty: 'low', chunkSize: 64 });
    const firstPlain = randomBytes(150);
    const secondPlain = randomBytes(170);

    const firstStream = await crypt.createEncryptionStream('first-password');
    const secondStream = await crypt.createEncryptionStream('second-password');
    const [firstCipher, secondCipher] = await Promise.all([
      writeAndCollect(firstStream, firstPlain),
      writeAndCollect(secondStream, secondPlain),
    ]);

    const firstReader = new Cryptit(nodeProvider, { difficulty: 'low' });
    const secondReader = new Cryptit(nodeProvider, { difficulty: 'low' });
    const firstDecrypt = await firstReader.createDecryptionStream('first-password');
    const firstRoundTrip = await feedAndCollect(firstDecrypt, firstCipher);
    const secondDecrypt = await secondReader.createDecryptionStream('second-password');
    const secondRoundTrip = await feedAndCollect(secondDecrypt, secondCipher);

    expect(firstRoundTrip).toEqual(firstPlain);
    expect(secondRoundTrip).toEqual(secondPlain);
  });

  it('keeps overlapping decryption streams sharing a provider independent', async () => {
    const firstWriter = new Cryptit(nodeProvider, { scheme, difficulty: 'low', chunkSize: 64 });
    const secondWriter = new Cryptit(nodeProvider, { scheme, difficulty: 'low', chunkSize: 64 });
    const firstPlain = randomBytes(150);
    const secondPlain = randomBytes(170);

    const firstCipher = await writeAndCollect(
      await firstWriter.createEncryptionStream('first-password'),
      firstPlain,
    );
    const secondCipher = await writeAndCollect(
      await secondWriter.createEncryptionStream('second-password'),
      secondPlain,
    );

    const firstDecrypt = await new Cryptit(nodeProvider).createDecryptionStream('first-password');
    const secondDecrypt = await new Cryptit(nodeProvider).createDecryptionStream('second-password');
    const [firstRoundTrip, secondRoundTrip] = await Promise.all([
      feedAndCollect(firstDecrypt, firstCipher),
      feedAndCollect(secondDecrypt, secondCipher),
    ]);

    expect(firstRoundTrip).toEqual(firstPlain);
    expect(secondRoundTrip).toEqual(secondPlain);
  });
});