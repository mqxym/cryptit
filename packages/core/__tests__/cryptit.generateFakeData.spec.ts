import { Cryptit } from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';

describe('Cryptit.generateFakeData', () => {
  const crypt = new Cryptit(nodeProvider, { difficulty: 'low', saltStrength: 'low' });

  it('emits a valid header with zero-length payload', async () => {
    const data = crypt.generateFakeData(0);
    expect(await Cryptit.isEncrypted(data)).toBe(true);
    const meta = await Cryptit.decodeHeader(data);
    expect(meta.scheme).toBe(crypt.getScheme());
    expect(meta.saltLength).toBeGreaterThan(0);
  });

  it('rounds payload to 8 bytes when usePadding=true', async () => {
    const data = crypt.generateFakeData(1, true);
    const hdr  = await Cryptit.decodeHeader(data);
    const total = data.byteLength;
    expect((total - hdr.saltLength - 2) % 8).toBe(0); // (headerLen) multiple of 8
    expect(total - (2 + hdr.saltLength)).toBeGreaterThanOrEqual(16);
  });

  it('throws RangeError on negative length', () => {
    expect(() => crypt.generateFakeData(-1 as unknown as number)).toThrow(RangeError);
  });
});