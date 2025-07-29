import { webcrypto, randomFillSync } from 'node:crypto';
import type { CryptoProvider } from '../../core/src/providers/CryptoProvider.js';

export const nodeProvider: CryptoProvider = {
  // cast is safe: Node’s SubtleCrypto is a superset of the browser spec
  subtle: webcrypto.subtle as unknown as SubtleCrypto,
  getRandomValues(buf) {
    randomFillSync(buf);
    return buf;
  },
  isNode: true,
};
