import { createLogger } from '../src/util/logger.js';

describe('tiny logger', () => {
  it('obeys verbosity levels', () => {
    const sink: string[] = [];
    const log = createLogger(2, m => sink.push(m));

    log.log(3, 'low-prio');   // should be ignored
    log.log(1, 'important');
    expect(sink).toEqual(['1| important']);
  });
});