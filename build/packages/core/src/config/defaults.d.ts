export declare const DefaultConfig: {
    saltLengths: {
        readonly low: 8;
        readonly high: 16;
    };
    argon: {
        low: {
            time: number;
            mem: number;
            parallelism: number;
        };
        middle: {
            time: number;
            mem: number;
            parallelism: number;
        };
        high: {
            time: number;
            mem: number;
            parallelism: number;
        };
    };
    chunkSize: number;
};
export type Difficulty = keyof typeof DefaultConfig.argon;
export type SaltStrength = keyof typeof DefaultConfig.saltLengths;
//# sourceMappingURL=defaults.d.ts.map