import { describe, expect, it } from 'bun:test';
import { VERSION_1_DIFFICULTIES } from '../../src/config/defaults.js';
import { SchemeRegistry } from '../../src/config/SchemeRegistry.js';
import { nodeProvider } from '../../../node-runtime/src/provider.js';
import { browserProvider } from '../../../browser-runtime/src/provider.js';
import { asArrayBufferView } from '../../src/util/bytes.js';

describe('scheme 2 defaults', () => {
  it('combines scheme 0 cipher settings with unchanged scheme 1 difficulties', () => {
    const v0 = SchemeRegistry.get(0);
    const v1 = SchemeRegistry.get(1);
    const v2 = SchemeRegistry.get(2);
    expect(v2.cipher).toBe(v0.cipher);
    expect(v2.difficulties).toBe(v1.difficulties);
    expect(v2.difficulties).toBe(VERSION_1_DIFFICULTIES);
    expect(v2.difficulties).toEqual({
      low: { time: 5, mem: 65536, parallelism: 2 },
      middle: { time: 10, mem: 98304, parallelism: 4 },
      high: { time: 20, mem: 98304, parallelism: 4 },
    });
    expect(v2.saltLengths).toEqual(v0.saltLengths);
    expect(v2.defaultChunkSize).toBe(v0.defaultChunkSize);
    expect(v2.kdf.name).toBe('argon2id');
    expect(SchemeRegistry.current).toBe(v0);
  });

  it.each([nodeProvider, browserProvider])(
    'derives the scheme 1 key material but keeps scheme 2 keys non-extractable (%j)',
    async provider => {
      const salt = new Uint8Array(16).fill(9);
      const v1Key = await SchemeRegistry.get(1).kdf.derive('scheme-2-test', salt, 'low', provider);
      const v2Key = await SchemeRegistry.get(2).kdf.derive('scheme-2-test', salt, 'low', provider);
      expect(v2Key.extractable).toBe(false);
      await expect(provider.subtle.exportKey('raw', v2Key)).rejects.toThrow();
      const raw = new Uint8Array(await provider.subtle.exportKey('raw', v1Key));
      try {
        const referenceKey = await provider.subtle.importKey(
          'raw', asArrayBufferView(raw), 'AES-GCM', false, ['encrypt', 'decrypt'],
        );
        const iv = new Uint8Array(12);
        const data = Uint8Array.of(1, 2, 3);
        const expected = await provider.subtle.encrypt({ name: 'AES-GCM', iv }, referenceKey, data);
        const actual = await provider.subtle.encrypt({ name: 'AES-GCM', iv }, v2Key, data);
        expect(new Uint8Array(actual)).toEqual(new Uint8Array(expected));
      } finally {
        raw.fill(0);
      }
    },
  );
});
