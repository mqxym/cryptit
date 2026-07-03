import { Cryptit }      from '../src/index.js';
import type { CryptitOptions } from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

/** Cipher schemes exercised by the parametrised suites. */
export const SCHEMES = [0, 1];

/** Cryptographically-random bytes helper for tests. */
export const randomBytes = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));

/** Construct a Cryptit instance bound to the Node crypto provider. */
export const makeCrypt = (opt: CryptitOptions = {}): Cryptit =>
  new Cryptit(nodeProvider, opt);