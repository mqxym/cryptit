/**
 * Minimal contract the stream layer needs from a crypto engine.
 * AESGCMEncryption already satisfies this.
 */
export interface IEncryptionAlgorithm {
  encryptChunk(chunk: Uint8Array): Promise<Uint8Array>;
  decryptChunk(chunk: Uint8Array): Promise<Uint8Array>;
}