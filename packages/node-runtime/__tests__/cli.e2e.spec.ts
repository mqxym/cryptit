import { join, resolve } from 'path';
import { execa } from 'execa';

/* ------------------------------------------------------------------ */
/*  Paths & runtime selector                                           */
/* ------------------------------------------------------------------ */
const CLI     = resolve(join(__dirname, '..', 'src', 'cli.ts'));
const isBun   = typeof Bun !== 'undefined' || !!process.env.BUN;

// When running under Node, we tell it to use ts-node as an ESM loader:
const NODE_LOADER = 'ts-node/esm';
const run = (args: string | string[], input?: string | Buffer) => {
  const arr = Array.isArray(args) ? args : [args];
  if (isBun) {
    // Bun supports TS out of the box
    return execa('bun', [CLI, ...arr], { input, encoding: 'utf8' });
  } else {
    // Node needs the loader flag for ESM TS
    return execa('node', ['--loader', NODE_LOADER, CLI, ...arr], {
      input,
      encoding: 'utf8',
      stdio: 'pipe',
    });
  }
};

/* ------------------------------------------------------------------ */
/*  Tests                                                              */
/* ------------------------------------------------------------------ */
describe('cryptit (CLI)', () => {
  it('encrypt-text | decrypt-text round-trip', async () => {
    const enc = await run(['encrypt-text', 'hello', '--pass', 'pw']);
    expect(enc.stdout).toMatch(/^[A-Za-z0-9+/]+=*$/);

    const dec = await run(['decrypt-text', enc.stdout, '--pass', 'pw']);
    expect(dec.stdout).toBe('hello');
  });

  it('decode detects header meta-data', async () => {
      const { stdout: cipher } = await run(['encrypt-text', 'a', '--pass', 'p']);

      const { stdout } = await run(['decode', '-'], cipher.trim());

      const meta = JSON.parse(stdout);
      expect(meta).toMatchObject({
          scheme: 0,
          difficulty: 'middle',
      });
  });

  it('fails cleanly on wrong password', async () => {
    const { stdout: cipher } = await run(['encrypt-text', 'x', '--pass', 'good']);
    const child = run(['decrypt-text', '--pass', 'bad'], cipher.trim());


    await child.then(
        proc => {
        // Bun path: promise fulfilled but exitCode = 1
        expect(proc.exitCode).not.toBe(0);
        expect(proc.stderr).toMatch(/Error \[DecryptionError]/);
        },
        err => {
        // Node path: promise rejected with ExecaError
        expect(err.stderr).toMatch(/Error \[DecryptionError]/);
        },
    );
  });
    
});