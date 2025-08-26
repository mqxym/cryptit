// packages/core/src/algorithms/argon2.ts
/**
 * Environment-agnostic Argon2-id wrapper.
 *  • Node / Bun  → native `argon2` addon (fastest)
 *  • Browser     → antelle/argon2-browser (WASM)
 */

import * as Argon2Browser from 'argon2-browser';

import { KeyDerivationError } from '../../errors/index.js';

/** Minimal subset of tuning parameters we expose */
export interface Argon2Tuning {
  time: number; // iterations
  mem: number; // kibibytes
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

// needed for crossover tests
async function ensureArgon2ModuleHook(): Promise<void> {
  // Only needed in non-browser test runners (Node/Bun). In real browsers we let the default work.
  if (typeof window !== 'undefined') return;

  if ((globalThis as any).loadArgon2WasmModule) return;

  try {
    const { createRequire } = await import('node:module');
    const { readFile }      = await import('node:fs/promises');
    const require           = createRequire(import.meta.url);

    const jsPath   = require.resolve('argon2-browser/dist/argon2.js');
    const wasmPath = require.resolve('argon2-browser/dist/argon2.wasm');

    (globalThis as any).loadArgon2WasmModule = async () => {

      const wasmBinary = new Uint8Array(await readFile(wasmPath));

    
      (globalThis as any).Module = {
        wasmBinary,
        // Also provide locateFile as a fallback for any internal lookups
        locateFile: (p: string) =>
          p === 'argon2.wasm' ? wasmPath : p,
      };
        return require(jsPath);
    
    };
  } catch {
  }
}

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
  env: 'node' | 'browser'
): Promise<ArgonHash> {
  // ————————————————————————————  Node / Bun  ————————————————————————————
  if (env === 'node') {
    const argon2 = await import("@node-rs/argon2");
    const pwdBuf = typeof password === 'string' ? Buffer.from(password, 'utf8') : Buffer.from(password);


    const hashString: string = await argon2.hash(pwdBuf, {
      salt,
      timeCost: opts.time,
      memoryCost: opts.mem,
      parallelism: opts.parallelism,
      outputLen: 32,
      algorithm: argon2.Algorithm.Argon2id,
    });

    const digestBase64 = hashString.split("$").pop();
    if (!digestBase64) throw new Error("Unexpected argon2 hash format");

    const raw = Buffer.from(digestBase64, "base64");
    
    pwdBuf.fill(0);

    return { hash: new Uint8Array(raw) };
  }

  // ————————————————————————————  Browser  ————————————————————————————
  if (env === 'browser') {
    await ensureArgon2ModuleHook();

    return Argon2Browser.hash({
      pass: password,
      salt: salt,
      time: opts.time,
      mem: opts.mem,
      parallelism: opts.parallelism,
      hashLen: 32,
      type: Argon2Browser.ArgonType.Argon2id,
    })
      .then((result: Argon2HashResult) => {
        if (!result || !result.hash) {
          throw new KeyDerivationError('Failed to produce key derivation');
        }
        return { hash: result.hash };
      })
      .catch((error: unknown) => {
        // Narrow the error to extract a message
        const message = error instanceof Error ? error.message : typeof error === 'string' ? error : 'Unknown error';

        throw new KeyDerivationError(`argon2-browser failure: ${message}`);
      });
  }

  throw new Error(`Unsupported environment: ${env}`);
}
