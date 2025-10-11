export interface CryptoProvider {
  subtle: SubtleCrypto | import('node:crypto').webcrypto.SubtleCrypto;
  getRandomValues(buf: Uint8Array): Uint8Array;
  isNode?: boolean;
}