import { VersionRegistry } from '../src/config/VersionRegistry.js';
import { VersionError }    from '../src/errors/index.js';

describe('VersionRegistry', () => {
  it('returns current (v0) descriptor', () => {
    expect(VersionRegistry.current.id).toBe(0);
  });

  it('throws on unknown version', () => {
    expect(() => VersionRegistry.get(7)).toThrow(VersionError);
  });

  it('prevents duplicate registration', () => {
    const dup = VersionRegistry.current;
    expect(() => VersionRegistry.register(dup)).toThrow(VersionError);
  });
});