import { mock } from 'bun:test';
import { fileURLToPath } from 'node:url';
import type { Cryptit, CryptitOptions } from '../src/index.js';

const encoder = new TextEncoder();

interface DigestOptions {
  time: number;
  mem: number;
  hashLen: number;
  parallelism: number;
  type: number;
}

function encodeHash(hash: Uint8Array, salt: Uint8Array, opts: DigestOptions): string {
  const base64 = (bytes: Uint8Array): string =>
    Buffer.from(bytes).toString('base64').replace(/=+$/, '');
  return `$argon2id$v=19$m=${opts.mem},t=${opts.time},p=${opts.parallelism}$${base64(salt)}$${base64(hash)}`;
}

async function kdfLikeDigest(
  password: string | Uint8Array,
  salt: Uint8Array,
  opts: DigestOptions,
): Promise<Uint8Array> {
  if (
    (typeof password !== 'string' && !(password instanceof Uint8Array)) ||
    !(salt instanceof Uint8Array) ||
    salt.length < 8 ||
    ![opts.time, opts.mem, opts.hashLen, opts.parallelism].every(
      value => Number.isSafeInteger(value) && value > 0,
    ) ||
    opts.type !== 2
  ) {
    throw new Error('argon2 mock: invalid inputs');
  }

  const header = encoder.encode(
    `time=${opts.time}|mem=${opts.mem}|len=${opts.hashLen}|par=${opts.parallelism}|type=${opts.type}|`,
  );
  const passBytes = typeof password === 'string' ? encoder.encode(password) : password;
  const base = new Uint8Array(header.length + passBytes.length + salt.length);
  base.set(header);
  base.set(passBytes, header.length);
  base.set(salt, header.length + passBytes.length);

  let seed = new Uint8Array(await crypto.subtle.digest('SHA-256', base));
  const out = new Uint8Array(opts.hashLen);
  let offset = 0;
  let counter = 0;

  while (offset < out.length) {
    const blockIn = new Uint8Array(seed.length + 4);
    blockIn.set(seed);
    new DataView(blockIn.buffer).setUint32(seed.length, counter);
    const block = new Uint8Array(await crypto.subtle.digest('SHA-256', blockIn));
    const take = Math.min(block.length, out.length - offset);
    out.set(block.subarray(0, take), offset);
    offset += take;
    counter++;
    seed = block;
  }

  return out;
}

// Fixed compatibility fixtures must exercise real Argon2 in an isolated process.
if (process.env.CRYPTIT_TEST_REAL_ARGON2 !== '1') {
  mock.module('argon2-browser', () => ({
    ArgonType: { Argon2id: 2 },
    hash: async (args: DigestOptions & { pass: string | Uint8Array; salt: Uint8Array }) => {
      const hash = await kdfLikeDigest(args.pass, args.salt, args);
      return {
        hash,
        hashHex: Buffer.from(hash).toString('hex'),
        encoded: encodeHash(hash, args.salt, args),
      };
    },
  }));

  mock.module('@node-rs/argon2', () => ({
    Algorithm: { Argon2id: 2 },
    hash: async (
      password: string | Uint8Array,
      opts: {
        salt: Uint8Array;
        timeCost: number;
        memoryCost: number;
        outputLen: number;
        parallelism: number;
        algorithm: number;
      },
    ) => {
      const tuning = {
        time: opts.timeCost,
        mem: opts.memoryCost,
        hashLen: opts.outputLen,
        parallelism: opts.parallelism,
        type: opts.algorithm,
      };
      const hash = await kdfLikeDigest(password, opts.salt, tuning);
      return encodeHash(hash, opts.salt, tuning);
    },
  }));
}

const { Cryptit: CryptitConstructor } = await import('../src/index.js');
const { nodeProvider } = await import('../../node-runtime/src/provider.js');

export const CLI_PRELOAD = ['--preload', fileURLToPath(import.meta.url)];
export const SCHEMES = [0, 1, 2];
export const randomBytes = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));
export const makeCrypt = (opt: CryptitOptions = {}): Cryptit =>
  new CryptitConstructor(nodeProvider, opt);
