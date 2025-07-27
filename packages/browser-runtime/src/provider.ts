// packages/browser-runtime/src/provider.ts
import type { CryptoProvider } from "../../core/src/providers/CryptoProvider.js";

/**
 * Crypto shim for modern browsers (and Bun when used in “browser” code-paths).
 */
export const browserProvider: CryptoProvider = {
  subtle: globalThis.crypto.subtle,
  getRandomValues(buf) {
    return globalThis.crypto.getRandomValues(buf);
  },
  isNode: false             // <- distinguishes from nodeProvider
};