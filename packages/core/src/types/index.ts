import { CryptoProvider } from "../providers/CryptoProvider.js";

export interface VersionDescriptor {
  /** 3-bit header field: 0 … 7 */
  readonly id: number;
  readonly cipher: new (p: CryptoProvider) => EncryptionAlgorithm;
  readonly kdf: KeyDerivation;
  readonly saltLengths: Record<'low' | 'high', number>;
  readonly difficulties: Record<string, unknown>;
  readonly defaultChunkSize: number;
}

export interface EncryptionAlgorithm {
  encryptChunk(plain: Uint8Array): Promise<Uint8Array>;
  decryptChunk(cipher: Uint8Array): Promise<Uint8Array>;
}

export interface KeyDerivation {
  derive(
    passphrase: Uint8Array | string,
    salt: Uint8Array,
    difficulty: string,
    provider: CryptoProvider
  ): Promise<CryptoKey>;
}