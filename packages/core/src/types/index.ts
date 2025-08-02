import type { CryptoProvider } from '../providers/CryptoProvider.js';

/* ------------------------- Encryption engine ------------------------- */
export interface EncryptionAlgorithm {
  encryptChunk(plain : Uint8Array): Promise<Uint8Array>;
  decryptChunk(cipher: Uint8Array): Promise<Uint8Array>;
  setKey(k: CryptoKey): Promise<void>;
}

/* ------------------------- Key derivation ---------------------------- */
export interface KeyDerivation<D extends string = string> {
  readonly name: string;
  derive(
    passphrase : Uint8Array | string,
    salt       : Uint8Array,
    difficulty : D,
    provider   : CryptoProvider,
  ): Promise<CryptoKey>;
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
  readonly cipher: new (p: CryptoProvider) => EncryptionAlgorithm;
  readonly kdf: KeyDerivation<D>;

  readonly saltLengths : Record<S, number>;                     // e.g. { low: 12, high: 16 }
  readonly difficulties : Record<D, unknown>;                   // free-form KDF presets
  readonly defaultChunkSize: number;
}