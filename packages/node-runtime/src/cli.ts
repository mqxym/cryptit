#!/usr/bin/env node
// packages/node-runtime/src/cli.ts
import { Command } from 'commander';
import { createReadStream, createWriteStream } from 'node:fs';
import { stdin, stdout, stderr, exit as processExit } from 'node:process';
import { Readable as NodeReadable, Writable as NodeWritable } from 'node:stream';
import { createCryptit } from './index.js';

const PKG_VERSION = '0.2.1'; // sync with root package.json

async function promptPass(): Promise<string> {
  if (!stdin.isTTY) throw new Error('STDIN not a TTY; use --pass');
  stderr.write('Passphrase: ');
  stdin.setRawMode?.(true);
  stdin.resume();
  stdin.setEncoding('utf8');

  let buf = '';
  return new Promise(resolve => {
    function done() {
      stdin.setRawMode?.(false);
      stdin.pause();
      stderr.write('\n');
      stdin.off('data', onData);
      resolve(buf);
    }
    function onData(ch: string) {
      if (ch === '\u0003') processExit(130);
      if (ch === '\r' || ch === '\n') return done();
      if (ch === '\u0008' || ch === '\u007F') {
        buf = buf.slice(0, -1);
        return;
      }
      buf += ch;
    }
    stdin.on('data', onData);
  });
}

function nodeToWeb(reader: typeof stdin | import('node:fs').ReadStream) {
  return (NodeReadable as any).toWeb(reader) as ReadableStream<Uint8Array>;
}
function nodeToWebW(writer: typeof stdout | import('node:fs').WriteStream) {
  return (NodeWritable as any).toWeb(writer) as WritableStream<Uint8Array>;
}

async function readAllFromStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

const program = new Command()
  .name('cryptit')
  .version(PKG_VERSION)
  .description('AES-GCM / Argon2 encryption utility')
  .option('-p, --pass <passphrase>', 'passphrase (prompt if omitted)')
  .option('-d, --difficulty <level>', 'argon2 difficulty low|middle|high', 'middle')
  .option('-s, --salt-strength <low|high>', 'salt length variant', 'high')
  .option('-c, --chunk-size <bytes>', 'chunk size in bytes', (v) => Number(v), 512 * 1024)
  .option('-v, --verbose', 'increase verbosity', (_v, prev) => (prev ?? 0) + 1, 0);

program
  .command('encrypt <src>')
  .description('Encrypt file; use - for STDIN, --out - for STDOUT')
  .option('-o, --out <file>', 'output file (default STDOUT)', '-')
  .action(async (src, cmd) => {
    const opts = program.opts();
    const crypt = createCryptit({
      difficulty: opts.difficulty,
      saltStrength: opts.saltStrength,
      chunkSize: opts.chunkSize,
    });
    const pass =
      opts.pass ??
      (stdin.isTTY ? await promptPass() : (() => {
        stderr.write('Use --pass when piping via STDIN\n');
        processExit(1);
      })());
    const inStream  = src  === '-' ? stdin  : createReadStream(src);
    const outStream = cmd.out === '-' ? stdout : createWriteStream(cmd.out);

    const { header, writable, readable } = await crypt.createEncryptionStream(pass);
    const webIn  = nodeToWeb(inStream);
    const webOut = nodeToWebW(outStream);

    // 1) Write header
    const w = webOut.getWriter();
    await w.write(header);
    w.releaseLock();

    // 2) Pipe the rest
    await Promise.all([
      webIn.pipeTo(writable),
      readable.pipeTo(webOut),
    ]);
  });

program
  .command('decrypt <src>')
  .description('Decrypt file; use - for STDIN, --out - for STDOUT')
  .option('-o, --out <file>', 'output file (default STDOUT)', '-')
  .action(async (src, cmd) => {
    const opts = program.opts();
    const crypt = createCryptit({
      difficulty: opts.difficulty,
      saltStrength: opts.saltStrength,
      chunkSize: opts.chunkSize,
    });
    const pass = opts.pass ?? await promptPass();
    const inStream  = src  === '-' ? stdin  : createReadStream(src);
    const outStream = cmd.out === '-' ? stdout : createWriteStream(cmd.out);

    const webIn  = nodeToWeb(inStream);
    const webOut = nodeToWebW(outStream);
    const ts     = await crypt.createDecryptionStream(pass);

    await Promise.all([
      webIn.pipeTo(ts.writable),
      ts.readable.pipeTo(webOut),
    ]);
  });

program
  .command('encrypt-text [text]')
  .description('Encrypt plaintext; omit arg to read from STDIN')
  .action(async (text) => {
    const opts  = program.opts();
    const crypt = createCryptit({
      difficulty: opts.difficulty,
      saltStrength: opts.saltStrength,
    });
    const pass =
      opts.pass ??
      (stdin.isTTY ? await promptPass() : (() => {
        stderr.write('Use --pass when piping via STDIN\n');
        processExit(1);
      })());
    const plain = text ?? (await readAllFromStdin());
    const cipher = await crypt.encryptText(plain, pass);
    stdout.write(cipher + '\n');
  });

program
  .command('decrypt-text [b64]')
  .description('Decrypt Base64 ciphertext; omit arg to read from STDIN')
  .action(async (b64) => {
    const opts  = program.opts();
    const crypt = createCryptit({
      difficulty: opts.difficulty,
      saltStrength: opts.saltStrength,
    });
    const pass = opts.pass ?? await promptPass();
    const data = b64 ?? (await readAllFromStdin()).trim();
    const plain = await crypt.decryptText(data, pass);
    stdout.write(plain + '\n');
  });

program.parse();