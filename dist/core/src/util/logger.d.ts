export type Verbosity = 0 | 1 | 2 | 3 | 4;
export interface Logger {
    level: Verbosity;
    log(lvl: Verbosity, msg: string): void;
}
export declare function createLogger(level?: Verbosity, sink?: (msg: string) => void): Logger;
