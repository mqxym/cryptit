#!/usr/bin/env node
// packages/node-runtime/src/cli.ts
import { Command, Option } from 'commander';
import { existsSync, accessSync, constants as fsConstants} from 'node:fs';
import { createReadStream, createWriteStream } from 'node:fs';
import { stdin, stdout, stderr, exit as processExit } from 'node:process';
import { Readable as NodeReadable, Writable as NodeWritable } from 'node:stream';
import { open as openFile } from 'node:fs/promises';  
import { createCryptit } from './index.js';
import { Cryptit } from '../../core/src/index.js';
import { dirname , resolve, sep, isAbsolute} from 'node:path';


const PKG_VERSION = '0.2.12'; // sync with root package.json

const DEFAULT_ROOT = process.cwd();

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



function assertWritable(out: string, root: string = DEFAULT_ROOT) {
  if (out === '-') return;

  const absRoot = resolve(root);
  const absOut  = isAbsolute(out) ? resolve(out) : resolve(absRoot, out);

  if (!absOut.startsWith(absRoot + sep)) {
    throw new Error("Refusing to write outside of root directory.");
  }

  const targetDir = dirname(absOut);
  if (!existsSync(targetDir)) {
    throw new Error(`Output directory does not exist: ${targetDir}`);
  }

  try {
    accessSync(targetDir, fsConstants.W_OK);
  } catch {
    throw new Error(`Output directory is not writeable`);
  }
  

  return absOut;
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

const program = new Command();

program
  .name('cryptit')
  .version(PKG_VERSION)
  .description('Text and File Encryption Utility\n' + 'Scheme 0: AES-GCM / Argon2id (Single Thread)\n' +'Scheme 1: XChaCha20-Poly1305 / Argon2id (Parallel)')

  .addOption(
    new Option('-S, --scheme <0-1>', 'encryption scheme version')
      .argParser((v) => {
        const n = Number(v);
        if (!Number.isInteger(n) || n < 0 || n > 7) {
          throw new Error('Version size must be a integer between 0 and 7');
        }
        return n;
      })
      .default(0, '0')
  )

  // passphrase (hidden from --help if you want)
  .addOption(
    new Option('-p, --pass <passphrase>', 'passphrase (prompt if omitted)')
      .hideHelp()            // if you don’t want it listed in help
      .argParser((v) => {
        if (!v.trim()) throw new Error('Passphrase cannot be empty');
        return v;
      })
  )

  // difficulty
  .addOption(
    new Option('-d, --difficulty <level>', 'argon2 difficulty')
      .choices(['low', 'middle', 'high'] as const)
      .default('middle', 'middle')
  )

  // salt-strength
  .addOption(
    new Option('-s, --salt-strength <variant>', 'salt length variant')
      .choices(['low', 'high'] as const)
      .default('high', 'high')
  )

  // chunk-size
  .addOption(
    new Option('-c, --chunk-size <bytes>', 'chunk size in bytes')
      .argParser((v) => {
        const n = Number(v);
        if (!Number.isInteger(n) || n <= 0) {
          throw new Error('Chunk size must be a positive integer');
        }
        return n;
      })
      .default(512 * 1024, '512*1024')
  )

  // verbosity (repeatable)
  .addOption(
    new Option('-v, --verbose', 'increase verbosity (use multiple times)')
      .default(0)
      .argParser((_, previous) => {
        // previous is typed as unknown, so cast to number
        return (previous as number) + 1;
      })
  );


process.on('uncaughtException', err => {
  if (err instanceof Error) {
    const name = err.constructor.name;
    const msg = err.message;
    stderr.write(`Error [${name}]: ${msg}\n`);
  } else {
    stderr.write(`Error [Unknown]: ${String(err)}\n`);
  }
  processExit(1);
});

process.on('unhandledRejection', (err: unknown) => {
  if (err instanceof Error) {
    const name = err.constructor.name;
    const msg = err.message;
    stderr.write(`Error [${name}]: ${msg}\n`);
  } else {
    stderr.write(`Error [Unknown]: ${String(err)}\n`);
  }
  processExit(1);
});


async function readAllStdin(): Promise<Buffer> {
  const bufs: Buffer[] = [];
  for await (const chunk of stdin) bufs.push(chunk as Buffer);
  return Buffer.concat(bufs);
}

program
  .command('decode [src]')
  .description(
    'Show Cryptit header information plus payload details; omit arg or use - to read from STDIN',
  )
  .action(async (src?: string) => {
    const { verbose } = program.opts();
    const logSink     = (msg: string) => stderr.write(msg);
    const crypt       = createCryptit({ verbose, logger: logSink });

    const useStdin = !src || src === '-';

    /** 
     * Inspect a Buffer or Base64 string: 
     * feed only up to 256 bytes into headerDecode, then let decodeData handle the rest.
     */
    async function decodeBinary(buf: Uint8Array): Promise<Record<string, unknown>> {
      if (buf.length < 2) throw new Error('Input too short for header');

      // slice up to 256 bytes for header parsing
      const headSlice = buf.subarray(0, Math.min(256, buf.length));
      const headerMeta = await Cryptit.headerDecode(headSlice);

      const dataMeta = await Cryptit.decodeData(buf);

      if (dataMeta.isChunked) {
        const { chunkSize, count, totalPayload } = dataMeta.chunks;
        return { ...headerMeta, isChunked: true, chunks: { chunkSize, count, totalPayload } };
      } else {
        const ivB64  = Buffer.from(dataMeta.params.iv).toString('base64');
        const tagB64 = Buffer.from(dataMeta.params.tag).toString('base64');
        return { ...headerMeta, isChunked: false, payloadLength: dataMeta.payloadLength, params: { iv: ivB64, tag: tagB64 } };
      }
    }

    if (!useStdin && src) {
      // file path mode: read entire file as buffer once (only for payload; header is limited above)
      const fd    = await openFile(src, 'r');
      const { size } = await fd.stat();
      const whole = Buffer.alloc(size);
      await fd.read(whole, 0, size, 0);
      await fd.close();

      const meta = await decodeBinary(new Uint8Array(whole));
      stdout.write(JSON.stringify(meta, null, 2) + '\n');
      return;
    }

    const buf = useStdin
      ? await readAllStdin()
      : Buffer.from(src!, 'utf8');
    const text = buf.toString('utf8').trim();
    const isB64 = /^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length % 4 === 0;

    try {
      if (isB64) {
        // for Base64 text, decode once to Uint8Array
        const data = Buffer.from(text, 'base64');
        const meta = await decodeBinary(new Uint8Array(data));
        stdout.write(JSON.stringify(meta, null, 2) + '\n');
      } else {
        // literal binary
        const meta = await decodeBinary(new Uint8Array(buf));
        stdout.write(JSON.stringify(meta, null, 2) + '\n');
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      stderr.write(`Error: ${msg}\n`);
      processExit(1);
    }
  });

program
  .command('encrypt <src>')
  .description('Encrypt file; use - for STDIN, --out - for STDOUT')
  .option('-o, --out <file>', 'output file (default STDOUT)', '-')
  .action(async (src, cmd) => {
    if (src !== '-' && !existsSync(src)) {
      stderr.write(`Error: input file not found: ${src}\n`);
      processExit(1);
    }
    const opts = program.opts();
    const crypt = createCryptit({
      difficulty: opts.difficulty,
      saltStrength: opts.saltStrength,
      chunkSize: opts.chunkSize,
      verbose: opts.verbose,
      scheme: opts.scheme,
    });
    const pass =
      opts.pass ??
      (stdin.isTTY ? await promptPass() : (() => {
        stderr.write('Use --pass when piping via STDIN\n');
        processExit(1);
      })());
    

    try {
      assertWritable(cmd.out);
    } catch (err: any) {
      stderr.write(`Error: ${err.message}\n`);
      processExit(1);
    }

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
    
    if (src !== '-' && !existsSync(src)) {
      stderr.write(`Error: input file not found: ${src}\n`);
      processExit(1);
    }

    const opts = program.opts();
    const crypt = createCryptit({
      difficulty: opts.difficulty,
      saltStrength: opts.saltStrength,
      chunkSize: opts.chunkSize,
      verbose: opts.verbose,
      scheme: opts.scheme,
    });

    try {
      assertWritable(cmd.out);
    } catch (err: any) {
      stderr.write(`Error: ${err.message}\n`);
      processExit(1);
    }


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
      verbose: opts.verbose,
      scheme: opts.scheme,
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
      verbose: opts.verbose,
      scheme: opts.scheme,
    });
    const pass = opts.pass ?? await promptPass();
    const data = b64 ?? (await readAllFromStdin()).trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(data)) {
      stderr.write('Error: ciphertext does not look like Base64\n');
      processExit(1);
    }
    const plain = await crypt.decryptText(data, pass);
    stdout.write(plain + '\n');
  });

program.parse();