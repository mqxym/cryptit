import { SchemeRegistry } from '../config/SchemeRegistry.js';
import type {
  SchemeDescriptor,
  EncryptionAlgorithm,
  KeyDerivation,
} from '../types/index.js';
import type { CryptoProvider } from '../providers/CryptoProvider.js';
import { KeyDerivationError } from '../errors/index.js';
import { secureOverwriteString } from '../util/bytes.js';

export interface Engine {
  desc      : SchemeDescriptor;
  cipher    : EncryptionAlgorithm;
  kdf       : KeyDerivation;
  chunkSize : number;
  provider  : CryptoProvider;
}

const _cache = new WeakMap<CryptoProvider, Map<number, Engine>>();

export class EngineManager {
  static getEngine(provider: CryptoProvider, schemeId: number): Engine {
    let perProvider = _cache.get(provider);
    if (!perProvider) {
      perProvider = new Map<number, Engine>();
      _cache.set(provider, perProvider);
    }

    let engine = perProvider.get(schemeId);
    if (engine) return engine;

    const desc   = SchemeRegistry.get(schemeId);
    engine = {
      desc,
      cipher   : new desc.cipher(provider),
      kdf      : desc.kdf,
      chunkSize: desc.defaultChunkSize,
      provider,
    };
    perProvider.set(schemeId, engine);
    return engine;
  }

  static async deriveKey(
    engine : Engine,
    pass   : string,
    salt   : Uint8Array,
    diff   : string,
  ): Promise<void> {
    try {
      const key = await engine.kdf.derive(pass, salt, diff as any, engine.provider);
      
      pass = secureOverwriteString(pass);
      pass = null as any;
      
      await engine.cipher.setKey(key);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new KeyDerivationError(msg);
    }
  }
}