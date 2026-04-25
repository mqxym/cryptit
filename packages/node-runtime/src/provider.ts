import { webcrypto, randomFillSync } from 'node:crypto';
import type { CryptoProvider } from '../../core/src/providers/CryptoProvider.js';

export const nodeProvider: CryptoProvider = {
  subtle: webcrypto.subtle as SubtleCrypto,
  getRandomValues(buf: Uint8Array): Uint8Array {
    randomFillSync(buf);
    return buf;
  },
  isNode: true,
};