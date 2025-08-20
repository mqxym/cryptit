import { Cryptit, type CryptitOptions } from '../../core/src/index.js';
import { browserProvider } from './provider.js';
export function createCryptit(cfg?: CryptitOptions): Cryptit {
  return new Cryptit(browserProvider, cfg);
}
export { Cryptit, type CryptitOptions } from '../../core/src/index.js';
export { ConvertibleInput, ConvertibleOutput } from '../../core/src/util/Convertible.js';