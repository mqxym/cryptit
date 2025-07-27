export declare function decodeHeader(bytes: Uint8Array): {
    version: number;
    difficulty: "low" | "middle" | "high";
    saltStrength: string;
    salt: Uint8Array<ArrayBuffer>;
    headerLen: number;
};
//# sourceMappingURL=decoder.d.ts.map