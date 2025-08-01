import { Cryptit }      from '../src/index.js';
import { nodeProvider } from '../../node-runtime/src/provider.js';
import { DecryptionError } from '../src/errors/index.js';

describe('Cryptit text helpers', () => {
  const crypt = new Cryptit(nodeProvider);

  it('encrypts & decrypts a UTF-8 string', async () => {
    const secret = await crypt.encryptText('héllo 🌍', 'pw');
    expect(typeof secret).toBe('string');
    expect(secret).toMatch(/^[A-Za-z0-9+/]+=*$/);

    const plain = await crypt.decryptText(secret, 'pw');
    expect(plain).toBe('héllo 🌍');
  });

  it('fails with wrong passphrase', async () => {
    const cipher = await crypt.encryptText('test', 'a');
    await expect(crypt.decryptText(cipher, 'b')).rejects.toThrow(DecryptionError);
  });

  it('isEncrypted() detects Cryptit payloads', async () => {
    const cipher = await crypt.encryptText('abc', 'x');
    expect(await Cryptit.isEncrypted(cipher)).toBe(true);
    expect(await Cryptit.isEncrypted('plain')).toBe(false);
  });
});