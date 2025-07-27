import { Cryptit, type EncryptionConfig } from "../../core/src/index.js";
/**
 * Factory that mirrors the one in node-runtime, but wired to the
 * browser provider.  Usage in web apps:
 *
 *   import { createCryptit } from "@mqxym/cryptit/browser";
 *   const crypt = createCryptit({ difficulty: "middle" });
 */
export declare function createCryptit(cfg?: EncryptionConfig): Cryptit;
export { Cryptit } from "../../core/src/index.js";
//# sourceMappingURL=index.d.ts.map