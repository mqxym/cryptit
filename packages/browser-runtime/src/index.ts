import { Cryptit, type CryptitOptions } from '../../core/src/index.js';
import { browserProvider }              from './provider.js';

export function createCryptit(cfg?: CryptitOptions): Cryptit {
  return new Cryptit(browserProvider, cfg);
}

export { Cryptit }         from '../../core/src/index.js';
export type { CryptitOptions } from '../../core/src/index.js';