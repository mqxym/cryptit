import { EngineManager } from '../src/engine/EngineManager.js';
import { nodeProvider }  from '../../node-runtime/src/provider.js';

describe('EngineManager', () => {
  it('caches engines per version', () => {
    const e1 = EngineManager.getEngine(nodeProvider, 0);
    const e2 = EngineManager.getEngine(nodeProvider, 0);
    expect(e1).toBe(e2);
  });
});