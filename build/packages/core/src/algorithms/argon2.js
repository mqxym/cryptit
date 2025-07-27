// packages/core/src/algorithms/argon2.ts
/**
 * Environment-agnostic Argon2-id wrapper.
 *  • Node / Bun  → native `argon2` addon (fastest)
 *  • Browser     → antelle/argon2-browser (WASM)
 */
import * as Argon2Browser from "argon2-browser";
/**
 * Derive a 32-byte hash with Argon2-id.
 *
 * @param password   UTF-8 string or raw bytes
 * @param salt       random salt
 * @param opts       memory/time/parallelism
 * @param env        'node' (incl. Bun) or 'browser'
 */
export async function argon2id(password, salt, opts, env) {
    // ————————————————————————————  Node / Bun  ————————————————————————————
    if (env === "node") {
        const argon2 = await import("argon2");
        const pwdBuf = typeof password === "string" ? Buffer.from(password, "utf8")
            : Buffer.from(password);
        const saltBuf = Buffer.from(salt);
        const raw = await argon2.hash(pwdBuf, {
            salt: saltBuf,
            timeCost: opts.time,
            memoryCost: opts.mem,
            parallelism: opts.parallelism,
            hashLength: 32,
            raw: true,
            type: argon2.argon2id,
        });
        return { hash: new Uint8Array(raw) };
    }
    // ————————————————————————————  Browser  ————————————————————————————
    if (env === "browser") {
        const { hash } = await Argon2Browser.hash({
            pass: password,
            salt,
            time: opts.time,
            mem: opts.mem,
            parallelism: opts.parallelism,
            hashLen: 32,
            type: Argon2Browser.ArgonType.Argon2id,
        });
        return { hash };
    }
    throw new Error(`Unsupported environment: ${env}`);
}
//# sourceMappingURL=argon2.js.map