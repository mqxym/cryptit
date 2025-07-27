export interface CryptoProvider {
    subtle: SubtleCrypto | import("crypto").webcrypto.SubtleCrypto;
    getRandomValues(buf: Uint8Array): Uint8Array;
    isNode?: boolean;
}
//# sourceMappingURL=CryptoProvider.d.ts.map