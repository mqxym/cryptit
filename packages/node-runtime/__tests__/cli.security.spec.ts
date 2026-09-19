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
const run = (args: string[], cwd?: string) => {
  const bin   = isBun ? 'bun' : 'node';
  const extra = isBun ? [] : ['--loader', NODE_LOADER];
  return execa(bin, [...extra, CLI, ...args], {
    encoding: 'utf8',
    reject: false,          // do not throw on exitCode ≠ 0
    cwd,
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

  it('refuses to write to a non-existent output directory with a friendly error', async () => {
    const dir = await fs.mkdtemp(`${tmpdir()}/cryptit-`);
    const src = join(dir, 'in.bin');
    await fs.writeFile(src, randomBytes(32));

    const outDir = join(dir, 'no-such-dir');             // does not exist
    const res = await run(['encrypt', src, '--pass', 'pw', '--out', join(outDir, 'x.enc')]);

    expect(res.exitCode).not.toBe(0);
    expect(res.stderr).toMatch(/Output directory does not exist/);

    await fs.rm(dir, { recursive: true, force: true });
  });
});

describe('cryptit CLI - transactional output', () => {
  it('replaces an output symlink without modifying its referent', async () => {
    const dir = await fs.mkdtemp(`${tmpdir()}/cryptit-output-`);
    const src = join(dir, 'plain.bin');
    const victim = join(dir, 'victim.bin');
    const out = join(dir, 'result.enc');
    const victimContents = Buffer.from('must remain unchanged');
    await fs.writeFile(src, randomBytes(64));
    await fs.writeFile(victim, victimContents);
    await fs.symlink(victim, out);

    try {
      const res = await run(['encrypt', 'plain.bin', '--pass', 'pw', '--out', 'result.enc'], dir);
      expect(res.exitCode).toBe(0);
      expect(await fs.readFile(victim)).toEqual(victimContents);
      expect((await fs.lstat(out)).isSymbolicLink()).toBe(false);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('preserves an existing destination when decryption fails late', async () => {
    const dir = await fs.mkdtemp(`${tmpdir()}/cryptit-output-`);
    const src = join(dir, 'plain.bin');
    const encrypted = join(dir, 'cipher.bin');
    const out = join(dir, 'restored.bin');
    const sentinel = Buffer.from('existing destination');
    await fs.writeFile(src, randomBytes(256));
    await fs.writeFile(out, sentinel);

    try {
      const encryptedResult = await run(
        ['encrypt', 'plain.bin', '--pass', 'pw', '--out', 'cipher.bin'],
        dir,
      );
      expect(encryptedResult.exitCode).toBe(0);

      const cipher = await fs.readFile(encrypted);
      cipher[cipher.length - 1] ^= 0x01;
      await fs.writeFile(encrypted, cipher);

      const decryptedResult = await run(
        ['decrypt', 'cipher.bin', '--pass', 'pw', '--out', 'restored.bin'],
        dir,
      );
      expect(decryptedResult.exitCode).not.toBe(0);
      expect(await fs.readFile(out)).toEqual(sentinel);
      expect((await fs.readdir(dir)).some(name => name.includes('.cryptit-tmp-'))).toBe(false);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});

describe('cryptit CLI - passphrase files', () => {
  it('round-trips without placing the passphrase in argv', async () => {
    const dir = await fs.mkdtemp(`${tmpdir()}/cryptit-pass-file-`);
    await fs.writeFile(join(dir, 'plain.bin'), randomBytes(64));
    await fs.writeFile(join(dir, 'pass.txt'), 'file-secret\n', { mode: 0o600 });

    try {
      const encrypted = await run([
        'encrypt', 'plain.bin', '--pass-file', 'pass.txt', '--out', 'cipher.bin',
      ], dir);
      expect(encrypted.exitCode).toBe(0);

      const decrypted = await run([
        'decrypt', 'cipher.bin', '--pass-file', 'pass.txt', '--out', 'restored.bin',
      ], dir);
      expect(decrypted.exitCode).toBe(0);
      expect(await fs.readFile(join(dir, 'restored.bin')))
        .toEqual(await fs.readFile(join(dir, 'plain.bin')));
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});