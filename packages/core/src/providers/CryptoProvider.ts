export interface CryptoProvider {
  // Node’s @types/node ships its own widened SubtleCrypto; the union avoids
  // the overload-mismatch error without any `as unknown` in callers.
  subtle: SubtleCrypto | import("crypto").webcrypto.SubtleCrypto;
  getRandomValues(buf: Uint8Array): Uint8Array;
  isNode?: boolean;
}