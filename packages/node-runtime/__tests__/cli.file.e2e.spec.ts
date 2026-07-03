import { join, resolve } from 'path';
import { promises as fs } from 'fs';
import { randomBytes } from 'crypto';
import { execa } from 'execa';
import { SCHEMES } from '../../core/__tests__/test.constants';

const CLI  = resolve(join(__dirname, '..', 'src', 'cli.ts'));
const isBun = typeof Bun !== 'undefined' || !!process.env.BUN;
const NODE_LOADER = 'ts-node/esm';
const run = (args: string[]) => {
  const bin   = isBun ? 'bun' : 'node';
  const extra = isBun ? [] : ['--loader', NODE_LOADER];
  return execa(bin, [...extra, CLI, ...args], { encoding: 'utf8' });
};

describe('cryptit CLI - file round-trip', () => {
  let dir: string, plain: string, enc: string, dec: string;

  beforeAll(async () => {
    // create temp directory under node-runtime package for guaranteed write permissions
    const prefix = join(__dirname, '..', 'cryptit-');
    dir   = await fs.mkdtemp(prefix);
    plain = join(dir, 'plain.bin');
   enc   = join(dir, 'enc.bin');
    dec   = join(dir, 'dec.bin');
    // create the files so createWriteStream.realpath succeeds
    await fs.writeFile(plain, randomBytes(32 * 1024));     // 32 KB
    await fs.writeFile(enc, Buffer.alloc(0));              // pre-create encrypt target
    await fs.writeFile(dec, Buffer.alloc(0));              // pre-create decrypt target
  });

  afterAll(() => fs.rm(dir, { recursive: true, force: true }));

  it.each(SCHEMES)('scheme %i', async scheme => {
    await run(['encrypt', plain, '--pass', 'pw', '--out', enc, '--scheme', String(scheme)]);
    await run(['decrypt', enc,   '--pass', 'pw', '--out', dec]);

    const [orig, back] = await Promise.all([fs.readFile(plain), fs.readFile(dec)]);
    expect(back.equals(orig)).toBe(true);
  });
});

describe('cryptit CLI - special-character filenames', () => {
  let dir: string;

  beforeAll(async () => {
    dir = await fs.mkdtemp(join(__dirname, '..', 'cryptit-'));
  });

  afterAll(() => fs.rm(dir, { recursive: true, force: true }));

  it('round-trips a file whose name contains spaces and unicode', async () => {
    const src = join(dir, 'pläin file (1).bin');
    const enc = join(dir, 'encrypted out.bin');
    const dec = join(dir, 'décodé résult.bin');
    const data = randomBytes(4 * 1024);

    await fs.writeFile(src, data);
    await fs.writeFile(enc, Buffer.alloc(0));
    await fs.writeFile(dec, Buffer.alloc(0));

    await run(['encrypt', src, '--pass', 'pw', '--out', enc]);
    await run(['decrypt', enc, '--pass', 'pw', '--out', dec]);

    const back = await fs.readFile(dec);
    expect(back.equals(data)).toBe(true);
  });
});