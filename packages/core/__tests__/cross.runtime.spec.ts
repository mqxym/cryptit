/**
 * CLI ↔ browser-runtime interoperability
 * Runs only under Node (same approach as existing CLI E2E tests).
 */

import { join, resolve } from 'path';
import { execa } from 'execa';
import { Cryptit } from '../../core/src/index.js';
import { promises as fs }  from 'fs';
import { browserProvider } from '../../browser-runtime/src/provider.js';
import { SCHEMES } from './test.constants.js';

const CLI     = resolve(join(__dirname, '..', '..', 'node-runtime', 'src', 'cli.ts'));

const isBun = typeof Bun !== 'undefined' || !!process.env.BUN;
const NODE_LOADER = 'ts-node/esm';      // keep for Node path

async function runCli(args: string[]): Promise<string> {
  const bin   = isBun ? 'bun' : 'node';
  const extra = isBun ? [] : ['--loader', NODE_LOADER];
  return execa(bin, [...extra, CLI, ...args], { encoding: 'utf8' })
    .then(res => res.stdout.trim());
}


describe.each(SCHEMES)('cryptit CLI ↔ browser-runtime (scheme %i)', scheme => {
  it('`encrypt-text` (CLI) → decryptText (browser)', async () => {
    // pass the scheme through to the CLI
    const cipher = await runCli([
      'encrypt-text', 'interop',
      '--pass', 'pw',
      '--scheme', scheme.toString(),
    ]);

    // mirror the same scheme in the browser-runtime
    const crypt  = new Cryptit(browserProvider, { scheme });
    const plain  = await crypt.decryptText(cipher, 'pw');
    expect(plain.text).toBe('interop');
  });

  it('browser encrypt → `decrypt-text` (CLI)', async () => {
    const crypt  = new Cryptit(browserProvider, { scheme });
    const cipher = await crypt.encryptText('cli-roundtrip', 'pw');

    // pass the scheme through to the CLI
    const plain  = await runCli([
      'decrypt-text', cipher.base64,
      '--pass', 'pw',
      '--scheme', scheme.toString(),
    ]);
    expect(plain).toBe('cli-roundtrip');
  });

  it('round-trips a 64 MiB binary', async () => {
    const dir   = await fs.mkdtemp(join(__dirname, 'cryptit-xrt-'));
    const plain = join(dir, 'plain.bin');
    const enc   = join(dir, 'enc.bin');

    const srcBytes = crypto.getRandomValues(new Uint8Array(65_536));
    await fs.writeFile(plain, srcBytes);

    await runCli(['encrypt', plain, '--pass', 'pw', '--out', enc, '--scheme', String(scheme)]);

    const encBuf = await fs.readFile(enc);
    const browserCrypt = new Cryptit(browserProvider, { scheme });
    const decBlob      = await browserCrypt.decryptFile(new Blob([encBuf as BufferSource]), 'pw');
    const decBytes     = new Uint8Array(await decBlob.arrayBuffer());

    expect(decBytes).toEqual(srcBytes);

    await fs.rm(dir, { recursive: true, force: true });
  });
});