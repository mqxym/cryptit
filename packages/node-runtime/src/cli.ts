#!/usr/bin/env node
// packages/node-runtime/src/cli.ts
import { Command } from 'commander';
import { createReadStream, createWriteStream, ReadStream, WriteStream } from 'node:fs';
import { stdin, stdout, stderr, exit as processExit } from 'node:process';
import { Readable as NodeReadable, Writable as NodeWritable } from 'node:stream';
import { createCryptit } from './index.js';

const PKG_VERSION = '0.2.0'; // keep in sync with root package.json

// ──────────────────────────────────────────────────────────────
//  ── Helper: silent pass-prompt ───────────────────────────────
// ──────────────────────────────────────────────────────────────
async function promptPass(): Promise<string> {
  if (!stdin.isTTY) throw new Error('STDIN not a TTY; --pass required');

  stderr.write('Passphrase: ');
  stdin.setRawMode?.(true);
  stdin.resume();
  stdin.setEncoding('utf8');

  let buf = '';
  return new Promise((resolve) => {
    function done() {
      stdin.setRawMode?.(false);
      stdin.pause();
      stderr.write('\n');
      stdin.off('data', onData);
      resolve(buf);
    }
    function onData(ch: string) {
      if (ch === '\u0003') processExit(130); // Ctrl-C
      if (ch === '\r' || ch === '\n') return done();
      if (ch === '\u0008' || ch === '\u007F') {
        // Backspace
        buf = buf.slice(0, -1);
        return;
      }
      buf += ch;
    }
    stdin.on('data', onData);
  });
}

function nodeToWeb(reader: ReadStream | typeof stdin) {
  return (NodeReadable as any).toWeb(reader) as ReadableStream<Uint8Array>;
}
function nodeToWebW(writer: WriteStream | typeof stdout) {
  return (NodeWritable as any).toWeb(writer) as WritableStream<Uint8Array>;
}

async function readAllFromStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

// ──────────────────────────────────────────────────────────────
//  ── CLI definition ───────────────────────────────────────────
// ──────────────────────────────────────────────────────────────
const program = new Command()
  .name('cryptit')
  .description('AES-GCM / Argon2 encryption utility')
  .version(PKG_VERSION)
  .option('-p, --pass <passphrase>', 'passphrase (prompt if omitted)')
  .option('-d, --difficulty <level>', 'argon2 difficulty low|middle|high', 'middle')
  .option('-s, --salt-strength <low|high>', 'salt length difficulty', 'high')
  .option('-c, --chunk-size <bytes>', 'chunk size (bytes)', (v) => Number(v), 512 * 1024)
  .option('-v, --verbose', 'increase verbosity', (_v, prev) => (prev ?? 0) + 1, 0);

// -----------------------------------------------------------------------------
// FILE encrypt / decrypt  (streaming, constant memory)
// -----------------------------------------------------------------------------

program
  .command('encrypt <src>')
  .description('encrypt file; use - for STDIN, --out - for STDOUT')
  .option('-o, --out <file>', 'output file (default STDOUT)', '-')
  .action(async (src, cmd) => {
    const g = program.opts();
    const crypt = createCryptit({
      difficulty: g.difficulty,
      saltStrength: g.saltStrength,
      chunkSize: g.chunkSize,
    });

    const pass =
      g.pass ??
      (stdin.isTTY
        ? await promptPass()
        : (() => {
            // <-- add this IIFE
            stderr.write('Use --pass when piping data via STDIN\n');
            processExit(1);
          })());
    const rs = src === '-' ? stdin : createReadStream(src);
    const ws = cmd.out === '-' ? stdout : createWriteStream(cmd.out);
    const { header, writable, readable } = await crypt.createEncryptionStream(pass);

    const webRS = nodeToWeb(rs);
    const webWS = nodeToWebW(ws);

    /* 1) write header once */
    const writer = webWS.getWriter();
    await writer.write(header);
    writer.releaseLock();

    /* 2) pipe payload */
    await Promise.all([
      webRS.pipeTo(writable),   // Readable → cipher-writable
      readable.pipeTo(webWS)    // cipher-readable → Writable
    ]);
  });

program
  .command('decrypt <src>')
  .description('decrypt file; use - for STDIN, --out - for STDOUT')
  .option('-o, --out <file>', 'output file (default STDOUT)', '-')
  .action(async (src, cmd) => {
    const g = program.opts();
    const crypt = createCryptit({
      difficulty: g.difficulty,
      saltStrength: g.saltStrength,
      chunkSize: g.chunkSize,
    });

    const pass = g.pass ?? (await promptPass());
    const rs = src === '-' ? stdin : createReadStream(src);
    const ws = cmd.out === '-' ? stdout : createWriteStream(cmd.out);

    const webRS = nodeToWeb(rs);
    const webWS = nodeToWebW(ws);
    const tf = await crypt.createDecryptionStream(pass);

    await Promise.all([webRS.pipeTo(tf.writable), tf.readable.pipeTo(webWS)]);

  });

// -----------------------------------------------------------------------------
// TEXT encrypt / decrypt  (entire payload in memory)
// -----------------------------------------------------------------------------
program
  .command('encrypt-text [text]')
  .description('encrypt plaintext; omit arg to read from STDIN')
  .action(async (text) => {
    const g = program.opts();
    const crypt = createCryptit({
      difficulty: g.difficulty,
      saltStrength: g.saltStrength,
    });
    const pass =
      g.pass ??
      (stdin.isTTY
        ? await promptPass()
        : (() => {
            // <-- add this IIFE
            stderr.write('Use --pass when piping data via STDIN\n');
            processExit(1);
          })());
    const plain = text ?? (await readAllFromStdin());
    const cipher = await crypt.encryptText(plain, pass);
    stdout.write(cipher + '\n');
  });

program
  .command('decrypt-text [b64]')
  .description('decrypt Base64 ciphertext; omit arg to read from STDIN')
  .action(async (b64) => {
    const g = program.opts();
    const crypt = createCryptit({
      difficulty: g.difficulty,
      saltStrength: g.saltStrength,
    });
    const pass = g.pass ?? (await promptPass());
    const data = b64 ?? (await readAllFromStdin()).trim();
    const plain = await crypt.decryptText(data, pass);
    stdout.write(plain + '\n');
  });

program.parse();
