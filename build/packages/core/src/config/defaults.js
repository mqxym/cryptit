// packages/core/src/config/defaults.ts
export const DefaultConfig = {
    saltLengths: { low: 8, high: 16 },
    argon: {
        low: { time: 1, mem: 32 * 1024, parallelism: 1 },
        middle: { time: 20, mem: 64 * 1024, parallelism: 1 },
        high: { time: 20, mem: 128 * 1024, parallelism: 2 }
    },
    chunkSize: 512 * 1024 // 512 KiB
};
//# sourceMappingURL=defaults.js.map