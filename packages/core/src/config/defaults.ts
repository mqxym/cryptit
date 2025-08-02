import { VersionRegistry } from './VersionRegistry.js';
import { AESGCM } from '../algorithms/encryption/aes-gmc/AESGCM.js';
import { XChaCha20Poly1305 } from '../algorithms/encryption/xchacha20poly1305/XChaCha20-Poly1305.js';
import { Argon2KDF } from '../algorithms/kdf/Argon2.js';
import { VersionDescriptor } from '../types/index.js';

export const DEFAULT_DIFFICULTIES = {
  low   : { time:  5, mem:  64 * 1024, parallelism: 1 },
  middle: { time: 20, mem:  64 * 1024, parallelism: 1 },
  high  : { time: 40, mem:  64 * 1024, parallelism: 1 },
} as const;

const v0: VersionDescriptor = {
  id: 0,
  cipher: AESGCM,
  kdf: new Argon2KDF(DEFAULT_DIFFICULTIES),
  saltLengths: { low: 12, high: 16 },
  difficulties: DEFAULT_DIFFICULTIES,
  defaultChunkSize: 512 * 1024,
};

VersionRegistry.register(v0);

export const VERSION_1_DIFFICULTIES = {
  low   : { time:  5, mem:  64 * 1024, parallelism: 2 }, //Browser has no parallelism effect
  middle: { time: 10, mem:  96 * 1024, parallelism: 4 }, //Browser has no parallelism effect
  high  : { time: 20, mem:  96 * 1024, parallelism: 4 }, //Browser has no parallelism effect
} as const;

const v1: VersionDescriptor = {
  id: 1,
  cipher: XChaCha20Poly1305,
  kdf: new Argon2KDF(VERSION_1_DIFFICULTIES, true),
  saltLengths: { low: 12, high: 16 },
  difficulties: VERSION_1_DIFFICULTIES,
  defaultChunkSize: 512 * 1024,
};

VersionRegistry.register(v1);

export type SaltStrength = 'low' | 'high';
export type Difficulty = keyof typeof DEFAULT_DIFFICULTIES;