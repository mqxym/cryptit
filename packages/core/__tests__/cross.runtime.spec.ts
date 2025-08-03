/**
 * CLI ↔ browser-runtime interoperability
 * Runs only under Node (same approach as existing CLI E2E tests).
 */

import { join, resolve } from 'path';
import { execa } from 'execa';
import { Cryptit } from '../../core/src/index.js';
import { browserProvider } from '../../browser-runtime/src/provider.js';
import type { CryptoProvider } from '../../core/src/providers/CryptoProvider.js';

const CLI     = resolve(join(__dirname, '..', '..', 'node-runtime', 'src', 'cli.ts'));

const isBun = typeof Bun !== 'undefined' || !!process.env.BUN;
const NODE_LOADER = 'ts-node/esm';      // keep for Node path

async function runCli(args: string[]): Promise<string> {
  const bin   = isBun ? 'bun' : 'node';
  const extra = isBun ? [] : ['--loader', NODE_LOADER];
  return execa(bin, [...extra, CLI, ...args], { encoding: 'utf8' })
    .then(res => res.stdout.trim());
}

describe('cryptit CLI ↔ browser-runtime', () => {
  it('`encrypt-text` (CLI) → decryptText (browser)', async () => {
    const cipher = await runCli(['encrypt-text', 'interop', '--pass', 'pw']);
    const crypt  = new Cryptit(browserProvider as CryptoProvider);
    const plain  = await crypt.decryptText(cipher, 'pw');
    expect(plain).toBe('interop');
  });

  it('browser encrypt → `decrypt-text` (CLI)', async () => {
    const crypt  = new Cryptit(browserProvider as CryptoProvider);
    const cipher = await crypt.encryptText('cli-roundtrip', 'pw');
    const plain  = await runCli(['decrypt-text', cipher, '--pass', 'pw']);
    expect(plain).toBe('cli-roundtrip');
  });
});