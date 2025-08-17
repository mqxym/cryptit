/* ------------------------------------------------------------------
   Runtime‑configuration edge cases
   ------------------------------------------------------------------ */
import { Cryptit }      from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

describe('Cryptit configuration guards', () => {

  const crypt = new Cryptit(nodeProvider);

  /* ── chunk‑size validation ─────────────────────────────────────── */
  it.each([0, -1, 3.14, NaN, Infinity])(
    'setChunkSize(%p) → throws',
    bad => {
      // force a cast so the compiler still allows the call
      expect(() => crypt.setChunkSize(bad as unknown as number))
        .toThrow(Error);
    },
  );

  /* ── scheme switching must not break legacy ciphertexts ────────── */
  it('decrypts old scheme‑0 ciphertext after scheme switch', async () => {
    const cipher = await crypt.encryptText('legacy', 'pw');   // scheme 0
    crypt.setScheme(1);                                       // switch
    const plain = await crypt.decryptText(cipher, 'pw');
    expect(plain).toBe('legacy');
  });
});