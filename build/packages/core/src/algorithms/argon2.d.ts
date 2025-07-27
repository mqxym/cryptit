/**
 * Environment-agnostic Argon2-id wrapper.
 *  • Node / Bun  → native `argon2` addon (fastest)
 *  • Browser     → antelle/argon2-browser (WASM)
 */
/** Minimal subset of tuning parameters we expose */
export interface Argon2Tuning {
    time: number;
    mem: number;
    parallelism: number;
}
export type ArgonHash = {
    hash: Uint8Array;
};
/**
 * Derive a 32-byte hash with Argon2-id.
 *
 * @param password   UTF-8 string or raw bytes
 * @param salt       random salt
 * @param opts       memory/time/parallelism
 * @param env        'node' (incl. Bun) or 'browser'
 */
export declare function argon2id(password: Uint8Array | string, salt: Uint8Array, opts: Argon2Tuning, env: "node" | "browser"): Promise<ArgonHash>;
//# sourceMappingURL=argon2.d.ts.map