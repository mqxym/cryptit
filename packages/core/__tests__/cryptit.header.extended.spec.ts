import { beforeAll, describe, expect, it, spyOn } from 'bun:test';
import { Cryptit } from '../src/index.js';
import { SchemeRegistry } from '../src/config/SchemeRegistry.js';
import { decodeHeader, decodeHeaderPrefix } from '../src/header/decoder.js';
import { encodeHeader } from '../src/header/encoder.js';
import { HEADER_RESERVED_MASK } from '../src/header/constants.js';
import { concat } from '../src/util/bytes.js';
import { collectStream } from '../src/util/stream.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

const EXTENDED_SCHEMES = [8, 15, 16, 63, 64, 119, 127];

beforeAll(() => {
  for (const id of EXTENDED_SCHEMES) {
    const base = SchemeRegistry.get(id >= 119 ? 1 : 0);
    SchemeRegistry.register({ ...base, id });
  }
});

describe('extended header layout', () => {
  it('decodes all 128 scheme IDs from their independent wire representation', () => {
    for (let scheme = 0; scheme <= 127; scheme++) {
      const extended = scheme > 7;
      const info = ((scheme % 8) << 5) | (extended ? 0x10 : 0);
      const prefix = Uint8Array.from(extended
        ? [0x01, info, Math.floor(scheme / 8)]
        : [0x01, info]);
      expect(decodeHeaderPrefix(prefix)).toEqual({
        scheme,
        saltStrength: 'low',
        prefixLength: extended ? 3 : 2,
      });
    }
  });

  it.each(EXTENDED_SCHEMES)('round-trips every flag combination for scheme %i', scheme => {
    for (const [difficultyCode, difficulty] of (['low', 'middle', 'high'] as const).entries()) {
      for (const saltStrength of ['low', 'high'] as const) {
        for (const streamFormat of ['legacy', 'authenticated-v1'] as const) {
          const salt = new Uint8Array(saltStrength === 'high' ? 16 : 12).fill(0xa5);
          const header = encodeHeader(scheme, difficulty, saltStrength, salt, undefined, streamFormat);
          const info = ((scheme % 8) << 5) | 0x10
            | (saltStrength === 'high' ? 0x04 : 0)
            | (streamFormat === 'authenticated-v1' ? 0x08 : 0)
            | difficultyCode;
          expect(Array.from(header)).toEqual([0x01, info, Math.floor(scheme / 8), ...salt]);
          expect(header[1] & HEADER_RESERVED_MASK).toBe(0x10);
          expect(header[2] & 0xf0).toBe(0);
          expect(decodeHeader(header)).toEqual({
            scheme, difficulty, saltStrength, salt, streamFormat, headerLen: 3 + salt.length,
          });
        }
      }
    }
  });

  it('rejects every nonzero combination of second-byte reserved bits', () => {
    for (let reserved = 1; reserved <= 15; reserved++) {
      const header = encodeHeader(127, 'low', 'low', new Uint8Array(12));
      header[2] |= reserved << 4;
      expect(() => decodeHeader(header)).toThrow('Unsupported second info byte flags.');
    }
  });

  it('rejects a missing second info byte and every truncated extended header', () => {
    const header = encodeHeader(8, 'low', 'high', new Uint8Array(16));
    expect(() => decodeHeaderPrefix(header.subarray(0, 2))).toThrow('Second info byte missing.');
    for (let length = 0; length < header.length; length++) {
      expect(() => decodeHeader(header.subarray(0, length))).toThrow();
    }
  });

  it('rejects unregistered extended schemes and invalid difficulty codes', () => {
    const unknown = Uint8Array.from([0x01, 0xb0, 0x0f, ...new Uint8Array(12)]);
    expect(() => decodeHeader(unknown)).toThrow('Unknown scheme: 125');
    const header = encodeHeader(127, 'low', 'low', new Uint8Array(12));
    header[1] |= 0x03;
    expect(() => decodeHeader(header)).toThrow('Unsupported difficulty code.');
  });

  it('authenticates both info bytes and the salt, excluding payload bytes', () => {
    const cipher = new (SchemeRegistry.current.cipher)(nodeProvider);
    const setAAD = spyOn(cipher, 'setAAD');
    try {
      const header = encodeHeader(8, 'low', 'low', new Uint8Array(12).fill(9), cipher);
      expect(setAAD).toHaveBeenLastCalledWith(header);
      const decoded = decodeHeader(concat(header, Uint8Array.of(1, 2, 3)), cipher);
      expect(decoded.headerLen).toBe(15);
      expect(setAAD).toHaveBeenLastCalledWith(header);
    } finally {
      setAAD.mockRestore();
    }
  });
});

describe.each([8, 127])('extended scheme integration | scheme %i', scheme => {
  const makeCrypt = (streamFormat: 'legacy' | 'authenticated-v1' = 'authenticated-v1') =>
    new Cryptit(nodeProvider, {
      scheme, difficulty: 'low', saltStrength: 'low', chunkSize: 32, streamFormat,
    });

  it('round-trips text and exposes the extended scheme through inspection', async () => {
    const encrypted = await makeCrypt().encryptText('extended header', 'pw');
    expect((await Cryptit.decodeHeader(encrypted.uint8array)).scheme).toBe(scheme);
    expect((await makeCrypt().decryptText(encrypted.uint8array, 'pw')).text).toBe('extended header');
    const tampered = encrypted.uint8array.slice();
    // Keep a valid scheme ID and identical cipher/KDF settings to isolate header authentication.
    const alternate = scheme === 8 ? 16 : 119;
    tampered[2] = Math.floor(alternate / 8);
    await expect(makeCrypt().decryptText(tampered, 'pw')).rejects.toThrow();
  });

  it.each(['legacy', 'authenticated-v1'] as const)('round-trips %s files and split streams', async format => {
    const crypt = makeCrypt(format);
    const plain = Uint8Array.from({ length: 65 }, (_, index) => index);
    const file = await crypt.encryptFile(new Blob([plain as BufferSource]), 'pw');
    const container = new Uint8Array(await file.arrayBuffer());
    const { headerLen } = decodeHeader(container);
    expect(headerLen).toBe(15);
    expect(new Uint8Array(await (await crypt.decryptFile(file, 'pw')).arrayBuffer())).toEqual(plain);
    expect(await Cryptit.decodeData(container)).toMatchObject({ format, isChunked: true });

    for (let split = 1; split < headerLen + 4; split++) {
      const source = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(container.subarray(0, split));
          controller.enqueue(container.subarray(split));
          controller.close();
        },
      });
      const transform = await crypt.createDecryptionStream('pw');
      expect(await collectStream(source.pipeThrough(transform))).toEqual(plain);
    }
  });

  it('rejects reserved bits and missing extension bytes in streams', async () => {
    const crypt = makeCrypt();
    const header = encodeHeader(scheme, 'low', 'low', new Uint8Array(12));
    for (const input of [header.subarray(0, 2), Uint8Array.of(0x01, header[1], header[2] | 0x10)]) {
      const source = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(input);
          controller.close();
        },
      });
      const transform = await crypt.createDecryptionStream('pw');
      await expect(collectStream(source.pipeThrough(transform))).rejects.toThrow();
    }
  });
});
