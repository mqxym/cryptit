/* ------------------------------------------------------------------
   T -05 - Edge -case payloads (≤ 1 byte) for both schemes
   ------------------------------------------------------------------ */
import { Cryptit } from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { SCHEMES } from './test.constants.js';

const SINGLE_BYTE = new Blob([Uint8Array.of(0xA5)]);

describe('Cryptit - tiny payload round -trips', () => {

  it.each(SCHEMES)('single -byte Blob | scheme %i', async scheme => {
    const crypt = new Cryptit(nodeProvider, { scheme });
    const enc   = await crypt.encryptFile(SINGLE_BYTE, 'pw');
    const dec   = await crypt.decryptFile(enc, 'pw');
    expect(await dec.arrayBuffer()).toEqual(await SINGLE_BYTE.arrayBuffer());
  });

  it('single ASCII char encryptText round -trip (scheme 1)', async () => {
    const crypt = new Cryptit(nodeProvider, { scheme: 1 });
    const ciph  = await crypt.encryptText('X', 'pw');
    expect(await crypt.decryptText(ciph, 'pw')).toBe('X');
  });
});