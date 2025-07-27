// packages/browser-runtime/src/index.ts
import { Cryptit, type EncryptionConfig } from "../../core/src/index.js";
import { browserProvider } from "./provider.js";

/**
 * Factory that mirrors the one in node-runtime, but wired to the
 * browser provider.  Usage in web apps:
 *
 *   import { createCryptit } from "@mqxym/cryptit/browser";
 *   const crypt = createCryptit({ difficulty: "middle" });
 */
export function createCryptit(cfg?: EncryptionConfig): Cryptit {
  return new Cryptit(browserProvider, cfg);
}

/* Re-export the low-level class in case advanced users want it */
export { Cryptit } from "../../core/src/index.js";