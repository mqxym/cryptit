import { EngineManager } from '../../src/engine/EngineManager.js';
import { nodeProvider }  from '../../../node-runtime/src/provider.js';

describe('EngineManager', () => {
  it('caches engines per scheme', () => {
    const e1 = EngineManager.getEngine(nodeProvider, 0);
    const e2 = EngineManager.getEngine(nodeProvider, 0);
    expect(e1).toBe(e2);
  });

  it('caches engines per provider instance only', () => {
    const otherProvider = { ...nodeProvider }; // new identity
    const e1 = EngineManager.getEngine(nodeProvider, 0);
    const e2 = EngineManager.getEngine(otherProvider as any, 0);
    expect(e1).not.toBe(e2);
  });

  it('deriveKey primes cipher so encrypt/decrypt round-trip works', async () => {
    const engine = EngineManager.getEngine(nodeProvider, 0);
    const salt   = nodeProvider.getRandomValues(new Uint8Array(16));

    const secret = { value: "pw"}

    await EngineManager.deriveKey(engine, secret, salt, 'middle');

    const src        = Uint8Array.of(7, 8, 9);
    const srcCopy    = Uint8Array.from(src);           // encryptChunk zeroises input
    const cipherUnit = await engine.cipher.encryptChunk(src);
    const plainUnit  = await engine.cipher.decryptChunk(cipherUnit);

    expect(plainUnit).toEqual(srcCopy);
  });

  it('deriveKey zeroizes the provided secret', async () => {
    const engine = EngineManager.getEngine(nodeProvider, 0);
    const salt   = nodeProvider.getRandomValues(new Uint8Array(16));
    const secret = { value: 'super-secret' };

    await EngineManager.deriveKey(engine, secret, salt, 'middle');

    // All characters replaced with NULs (\0)
    expect(secret.value).toHaveLength('super-secret'.length);
    expect([...secret.value].every(ch => ch === '\0')).toBe(true);
  });
});