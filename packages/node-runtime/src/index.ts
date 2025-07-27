import { Cryptit, EncryptionConfig } from '../../core/src/index.js';
import { nodeProvider } from './provider.js';
export function createCryptit(cfg?: EncryptionConfig) {
  return new Cryptit(nodeProvider, cfg);
}