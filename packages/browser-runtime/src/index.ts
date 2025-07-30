// packages/browser-runtime/src/index.ts
import { Cryptit, type CryptitOptions } from '../../core/src/index.js';
import { browserProvider } from './provider.js';

/**
 * Factory for browser environments.  
 * Usage:
 *   import { createCryptit } from '@your-org/cryptit/browser';
 *   const crypt = createCryptit({ difficulty: 'high' });
 */
export function createCryptit(cfg?: CryptitOptions): Cryptit {
  return new Cryptit(browserProvider, cfg);
}

/** Low-level façade in case advanced users need direct control */
export { Cryptit } from '../../core/src/index.js';
export type { CryptitOptions } from '../../core/src/index.js';