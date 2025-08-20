export declare const DEFAULT_DIFFICULTIES: {
    readonly low: {
        readonly time: 5;
        readonly mem: number;
        readonly parallelism: 1;
    };
    readonly middle: {
        readonly time: 20;
        readonly mem: number;
        readonly parallelism: 1;
    };
    readonly high: {
        readonly time: 40;
        readonly mem: number;
        readonly parallelism: 1;
    };
};
export declare const VERSION_1_DIFFICULTIES: {
    readonly low: {
        readonly time: 5;
        readonly mem: number;
        readonly parallelism: 2;
    };
    readonly middle: {
        readonly time: 10;
        readonly mem: number;
        readonly parallelism: 4;
    };
    readonly high: {
        readonly time: 20;
        readonly mem: number;
        readonly parallelism: 4;
    };
};
export type SaltStrength = 'low' | 'high';
export type Difficulty = keyof typeof DEFAULT_DIFFICULTIES;
