/* ------------------------------------------------------------------
   T -04 - CLI path -traversal defence
   ------------------------------------------------------------------ */
import { join, resolve } from 'path';
import { tmpdir } from 'os';
import { promises as fs } from 'fs';
import { randomBytes } from 'crypto';
import { execa } from 'execa';

const CLI  = resolve(join(__dirname, '..', 'src', 'cli.ts'));
const isBun = typeof Bun !== 'undefined' || !!process.env.BUN;
const NODE_LOADER = 'ts-node/esm';
const run = (args: string[]) => {
  const bin   = isBun ? 'bun' : 'node';
  const extra = isBun ? [] : ['--loader', NODE_LOADER];
  return execa(bin, [...extra, CLI, ...args], {
    encoding: 'utf8',
    reject: false,          // do not throw on exitCode ≠ 0
  });
};

describe('cryptit CLI - assertWritable blocks “../” traversal', () => {
  it('refuses to write above cwd', async () => {
    const dir  = await fs.mkdtemp(`${tmpdir()}/cryptit -`);
    const src  = join(dir, 'in.bin');
    await fs.writeFile(src, randomBytes(8));

    const res = await run(['encrypt', src, '--pass', 'pw', '--out', '../evil.enc']);
    expect(res.exitCode).not.toBe(0);
    expect(res.stderr).toMatch(/Refusing to write outside/);

    const evilPath = resolve(dir, '..', 'evil.enc');
    await expect(fs.access(evilPath)).rejects.toThrow();
    await fs.rm(dir, { recursive: true, force: true });
  });
});