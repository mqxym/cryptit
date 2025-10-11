import type { CryptoProvider } from '../providers/CryptoProvider.js';
import type { PaddingScheme } from '../algorithms/padding/magic48ver-crc8.js';
import type { PaddingAADMode } from '../algorithms/encryption/base/BaseAEADWithPadAAD.js';
import { CryptoKeyLike } from './crypto-key-like.js';

/* ------------------------- Encryption engine ------------------------- */
export interface EncryptionAlgorithm {
  encryptChunk(plain : Uint8Array): Promise<Uint8Array>;
  decryptChunk(cipher: Uint8Array): Promise<Uint8Array>;
  setKey(k: CryptoKeyLike): Promise<void>;
  zeroKey(): void;
  setAAD(aadData: Uint8Array): void; //set additional data (header)
  readonly IV_LENGTH: number;
  readonly TAG_LENGTH: number;
}

export interface PaddingAwareEncryptionAlgorithm extends EncryptionAlgorithm {
  setPaddingScheme(s: PaddingScheme | null): void;
  setPaddingAADMode(mode: PaddingAADMode): void;
  setPaddingAlign(n: number): void;
  setLegacyAADFallback(opts: {
    enabled?: boolean;
    policy?: PaddingAADMode;
    tryEmptyAAD?: boolean
  }): void
}

/* ------------------------- Key derivation ---------------------------- */
export interface KeyDerivation<D extends string = string> {
  readonly name: string;
  derive(
    passphrase : Uint8Array | string,
    salt       : Uint8Array,
    difficulty : D,
    provider   : CryptoProvider,
  ): Promise<CryptoKeyLike>;
}

export interface CipherConstructor {
  /* static */ readonly IV_LENGTH: number;
  /* static */ readonly TAG_LENGTH: number
  new (p: CryptoProvider): PaddingAwareEncryptionAlgorithm;
}

/* ---------------------------------------------------------------------
   Generic descriptor of one “format scheme".

   S = salt-strength keys  (e.g. "low" | "high")
   D = difficulty presets  (e.g. "low" | "middle" | "high")
--------------------------------------------------------------------- */
export interface SchemeDescriptor<
  S extends string = string,
  D extends string = string,
> {
  readonly id: number;                                          // 3-bit header field
  readonly cipher: CipherConstructor;
  readonly kdf: KeyDerivation<D>;

  readonly saltLengths : Record<S, number>;                     // e.g. { low: 12, high: 16 }
  readonly difficulties : Record<D, unknown>;                   // free-form KDF presets
  readonly defaultChunkSize: number;
}

export type Secret = {
  value: string;
};
