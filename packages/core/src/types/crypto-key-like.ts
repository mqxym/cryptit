// packages/core/src/types/crypto-key-like.ts
export type CryptoKeyLike =
  | globalThis.CryptoKey
  | import('node:crypto').webcrypto.CryptoKey;