import { VersionRegistry } from '../config/VersionRegistry.js';
import type {
  VersionDescriptor,
  EncryptionAlgorithm,
  KeyDerivation,
} from '../types/index.js';
import type { CryptoProvider } from '../providers/CryptoProvider.js';
import { KeyDerivationError } from '../errors/index.js';

export interface Engine {
  desc      : VersionDescriptor;
  cipher    : EncryptionAlgorithm;
  kdf       : KeyDerivation;
  chunkSize : number;
  provider  : CryptoProvider;
}

const _cache = new Map<number, Engine>();

export class EngineManager {
  static getEngine(
    provider : CryptoProvider,
    versionId: number,
  ): Engine {
    let e = _cache.get(versionId);
    if (e) return e;

    const desc      = VersionRegistry.get(versionId);
    const cipher    = new desc.cipher(provider);
    const kdf       = desc.kdf;
    const chunkSize = desc.defaultChunkSize;

    e = { desc, cipher, kdf, chunkSize, provider };
    _cache.set(versionId, e);
    return e;
  }

  static async deriveKey(
    engine : Engine,
    pass   : string,
    salt   : Uint8Array,
    diff   : string,
  ): Promise<void> {
    try {
      const key = await engine.kdf.derive(pass, salt, diff as any, engine.provider);
      (engine.cipher as any).setKey(key);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new KeyDerivationError(msg);
    }
  }
}