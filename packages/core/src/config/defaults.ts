// packages/core/src/config/defaults.ts
export const DefaultConfig = {
  saltLengths: { low: 12, high: 16 } as const,
  argon: {
    low:    { time: 5, mem:  64 * 1024, parallelism: 1 },
    middle: { time: 20, mem:  64 * 1024, parallelism: 1 },
    high:   { time: 40, mem: 64 * 1024, parallelism: 1 }
  },
  chunkSize: 512 * 1024 // 512 KiB
};
export type Difficulty = keyof typeof DefaultConfig.argon;
export type SaltStrength = keyof typeof DefaultConfig.saltLengths;