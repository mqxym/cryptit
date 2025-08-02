// packages/core/src/algorithms/argon2.ts
/**
 * Environment-agnostic Argon2-id wrapper.
 *  • Node / Bun  → native `argon2` addon (fastest)
 *  • Browser     → antelle/argon2-browser (WASM)
 */

import * as Argon2Browser from "argon2-browser";

import { KeyDerivationError } from "../../errors/index.js";

/** Minimal subset of tuning parameters we expose */
export interface Argon2Tuning {
  time: number;        // iterations
  mem: number;         // kibibytes
  parallelism: number; // lanes
}

export type ArgonHash = { hash: Uint8Array };

type Argon2HashResult = {
  // raw bytes of the derived key
  hash: Uint8Array;
  // hex-encoded string of the derived key
  hashHex: string;
  // the full Argon2 encoded string (salt, params, hash)
  encoded: string;
};
/**
 * Derive a 32-byte hash with Argon2-id.
 *
 * @param password   UTF-8 string or raw bytes
 * @param salt       random salt
 * @param opts       memory/time/parallelism
 * @param env        'node' (incl. Bun) or 'browser'
 */
export async function argon2id(
  password: Uint8Array | string,
  salt: Uint8Array,
  opts: Argon2Tuning,
  env: "node" | "browser",
): Promise<ArgonHash> {
  // ————————————————————————————  Node / Bun  ————————————————————————————
  if (env === "node") {
    const argon2 = await import("argon2");
    const pwdBuf =
      typeof password === "string" ? Buffer.from(password, "utf8")
                                   : Buffer.from(password);

    const saltBuf = Buffer.from(salt);

    const raw: Buffer = await argon2.hash(pwdBuf, {
      salt       : saltBuf,
      timeCost    : opts.time,
      memoryCost  : opts.mem,
      parallelism : opts.parallelism,
      hashLength  : 32,
      raw         : true,
      type        : argon2.argon2id,
    });

    return { hash: new Uint8Array(raw) };

  }

  // ————————————————————————————  Browser  ————————————————————————————
if (env === "browser") {
  
    if (!("loadArgon2WasmBinary" in globalThis)) {
      ;(globalThis as any).loadArgon2WasmBinary = () =>
        fetch("argon2.wasm")
          .then(res => {
            if (!res.ok) throw new Error("Failed to load argon2.wasm");
            return res.arrayBuffer();
          })
          .then(buf => new Uint8Array(buf));
    }

 return Argon2Browser.hash({
    pass        : password,
    salt        : salt,
    time        : opts.time,
    mem         : opts.mem,
    parallelism : opts.parallelism,
    hashLen     : 32,
    type        : Argon2Browser.ArgonType.Argon2id,
  })
  .then((result: Argon2HashResult) => {
    if (!result || !result.hash) {
      throw new Error('Failed to produce key derivation');
    }
    return { hash: result.hash };
  })
  .catch((error: unknown) => {
    // Narrow the error to extract a message
    const message =
      error instanceof Error
        ? error.message
        : typeof error === 'string'
        ? error
        : 'Unknown error';

    throw new KeyDerivationError(`argon2-browser failure: ${message}`);
  });
}

  throw new Error(`Unsupported environment: ${env}`);
}