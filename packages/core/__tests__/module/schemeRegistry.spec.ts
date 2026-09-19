import '../../src/config/defaults.js';
import { SchemeRegistry } from '../../src/config/SchemeRegistry.js';
import { SchemeError }    from '../../src/errors/index.js';

describe('SchemeRegistry', () => {
  it('returns current (v0) descriptor', () => {
    expect(SchemeRegistry.current.id).toBe(0);
  });

  it('throws on unknown scheme', () => {
    expect(() => SchemeRegistry.get(7)).toThrow(SchemeError);
  });

  it('prevents duplicate registration', () => {
    const dup = SchemeRegistry.current;
    expect(() => SchemeRegistry.register(dup)).toThrow(SchemeError);
  });

  it('rejects ids that cannot be represented in the header', () => {
    const current = SchemeRegistry.current;
    expect(() => SchemeRegistry.register({ ...current, id: -1 })).toThrow(SchemeError);
    expect(() => SchemeRegistry.register({ ...current, id: 8 })).toThrow(SchemeError);
    expect(() => SchemeRegistry.register({ ...current, id: 1.5 })).toThrow(SchemeError);
  });
});