// packages/node-runtime/src/index.ts
import { Cryptit, type CryptitOptions } from '../../core/src/index.js';
import { nodeProvider }                from './provider.js';

export function createCryptit(cfg?: CryptitOptions): Cryptit {
  return new Cryptit(nodeProvider, cfg);
}

export type { CryptitOptions } from '../../core/src/index.js';