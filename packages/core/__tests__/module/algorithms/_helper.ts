import { webcrypto, randomFillSync } from 'crypto';
import type { CryptoProvider } from '../../../src/providers/CryptoProvider.js';

export const nodeProvider: CryptoProvider = {
  subtle: webcrypto.subtle as unknown as SubtleCrypto,
  getRandomValues(buf: Uint8Array) {
    randomFillSync(buf);
    return buf;
  },
  isNode: true,
};

// Helper: import a raw 32-byte key into WebCrypto (extractable) for XChaCha tests
export async function importExtractableRawKey(bytes: Uint8Array): Promise<CryptoKey> {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new TypeError('Need 32 bytes for XChaCha20-Poly1305 test key');
  }
  return nodeProvider.subtle.importKey(
    'raw',
    bytes as BufferSource,
    { name: 'AES-GCM' },   // just a container algo so WebCrypto will accept & export
    true,                  // extractable so setKey() can export raw
    ['encrypt', 'decrypt'] // any non-empty usages are fine
  );
}

// Helper: generate AES-GCM key
export async function generateAesGcmKey(): Promise<CryptoKey> {
  return nodeProvider.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable (handy in some tests)
    ['encrypt', 'decrypt']
  ) as Promise<CryptoKey>;
}