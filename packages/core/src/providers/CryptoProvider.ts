export interface CryptoProvider {
  subtle: SubtleCrypto;
  getRandomValues(buf: Uint8Array): Uint8Array;
  isNode?: boolean;
}