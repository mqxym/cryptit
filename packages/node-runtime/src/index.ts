// packages/node-runtime/src/index.ts
import { Cryptit, type CryptitOptions } from '../../core/src/index.js';
import { nodeProvider } from './provider.js';

/**
 * Factory for Node.js (and Bun) environments.
 *
 * Usage:
 *   import { createCryptit } from '@your-org/cryptit/node';
 *   const crypt = createCryptit({ saltStrength: 'low' });
 */
export function createCryptit(cfg?: CryptitOptions): Cryptit {
  return new Cryptit(nodeProvider, cfg);
}

export type { CryptitOptions } from '../../core/src/index.js';