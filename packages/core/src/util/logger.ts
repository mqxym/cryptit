/* ------------------------------------------------------------------
   Tiny, dependency-free logger with five verbosity levels
   ------------------------------------------------------------------ */
export type Verbosity = 0 | 1 | 2 | 3 | 4;  // 0 = errors only … 4 = trace

export interface Logger {
  level : Verbosity;
  log(lvl: Verbosity, msg: string): void;
}

export function createLogger(
  level: Verbosity = 0,
  sink : (msg: string) => void = console.info,
): Logger {
  return {
    level,
    log(lvl, msg) {
      if (lvl <= level) sink(`${lvl}| ${msg}`);
    },
  };
}
/*
const loggerSingleton: Logger = createLogger();

export default loggerSingleton;*/