#!/usr/bin/env node
// packages/node-runtime/src/cli.ts
import { Command, Option } from 'commander';
import { existsSync, accessSync, constants as fsConstants, realpathSync} from 'node:fs';
import { createReadStream, createWriteStream } from 'node:fs';
import { stdin, stdout, stderr, exit as processExit } from 'node:process';
import { FilesystemError } from '../../core/src/errors/index.js';
import { FileByteSource } from '../../core/src/util/ByteSource.js';
import { createCryptit } from './index.js';
import { Cryptit } from '../../core/src/index.js';
import { dirname , resolve, sep, isAbsolute} from 'node:path';
import { toWebReadable, toWebWritable } from './streamAdapter.js';


const PKG_VERSION = '2.1.2'; // sync with root package.json

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

  const absRoot   = realpathSync(root);

  const absOut    = isAbsolute(out)
                  ? resolve(out)
                  : resolve(absRoot, out);

  const targetDir  = dirname(absOut);
  const realTarget = realpathSync(targetDir);

  if (!realTarget.startsWith(absRoot + sep)) {
    throw new FilesystemError('Refusing to write outside of root directory.');
  }
  if (!existsSync(targetDir)) {
    throw new FilesystemError(`Output directory does not exist: ${targetDir}`);
  }

  try {
    accessSync(targetDir, fsConstants.W_OK);
  } catch {
    throw new FilesystemError(`Output directory is not writeable`);
  }
  

  return absOut;
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
  .description('Text and File Encryption Utility\n' + 'Scheme 0: AES-GCM (Native) / Argon2id (Single Thread)\n' +'Scheme 1: XChaCha20-Poly1305 (JS Engine) / Argon2id (Parallel)')

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


/* ------------------------------------------------------------------ */
/*  Decode command (stream-safe)                                       */
/* ------------------------------------------------------------------ */
;
import { promises as fsp } from 'fs';
import * as os   from 'os';
import * as path from 'path';

program
  .command('decode [src]')
  .description(
    'Show Cryptit header information plus payload details; omit arg or use - to read from STDIN',
  )
  .action(async (src?: string) => {
    const useStdin = !src || src === '-';

    /* -------------------------------------------------------------- */
    /*  Helpers                                                       */
    /* -------------------------------------------------------------- */

    /** Inspect an in-memory buffer or Base-64 string */
    async function decodeBinary(buf: Uint8Array): Promise<Record<string, unknown>> {
      if (buf.length < 2) throw new Error('Input too short for header');

      const headSlice  = buf.subarray(0, Math.min(256, buf.length));
      const headerMeta = await Cryptit.decodeHeader(headSlice);

      const dataMeta   = await Cryptit.decodeData(buf);

      if (dataMeta.isChunked) {
        const { chunkSize, count, totalPayload } = dataMeta.chunks;
        return {
          ...headerMeta,
          isChunked: true,
          chunks: { chunkSize, count, totalPayload },
        };
      }

      const ivB64  = Buffer.from(dataMeta.params.iv).toString('base64');
      const tagB64 = Buffer.from(dataMeta.params.tag).toString('base64');
      return {
        ...headerMeta,
        isChunked: false,
        payloadLength: dataMeta.payloadLength,
        params: { iv: ivB64, ivLength: dataMeta.params.ivLength, tag: tagB64, tagLength: dataMeta.params.tagLength },
      };
    }

    /** Decode via random-access source (file or temp file) */
    async function decodeFromSource(src: FileByteSource): Promise<Record<string, unknown>> {
      const head        = await src.read(0, Math.min(256, src.length));
      const headerMeta  = await Cryptit.decodeHeader(head);
      const dataMeta    = await Cryptit.decodeData(src);

      if (dataMeta.isChunked) {
        const { chunkSize, count, totalPayload } = dataMeta.chunks;
        return {
          ...headerMeta,
          isChunked: true,
          chunks: { chunkSize, count, totalPayload },
        };
      }

      const ivB64  = Buffer.from(dataMeta.params.iv).toString('base64');
      const tagB64 = Buffer.from(dataMeta.params.tag).toString('base64');
      return {
        ...headerMeta,
        isChunked: false,
        payloadLength: dataMeta.payloadLength,
        params: { iv: ivB64, tag: tagB64 },
      };
    }

    /** Stream STDIN to a temporary file and return its absolute path */
    async function stdinToTempFile(): Promise<string> {
      // Default 1 GiB limit; allow override via env (bytes)
      const envLimit = Number(process.env.CRYPTIT_STDIN_MAX_BYTES);
      const MAX_BYTES = Number.isFinite(envLimit) && envLimit > 0
        ? Math.floor(envLimit)
        : 10_073_741_824; // 10 GiB

      const dir     = await fsp.mkdtemp(path.join(os.tmpdir(), 'cryptit-'));
      const tmpPath = path.join(dir, 'stdin.bin');
      const out     = createWriteStream(tmpPath, { flags: 'w' });

      let written = 0;

      try {
        for await (const chunk of process.stdin) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as any);
          written += buf.length;

          if (written > MAX_BYTES) {
            // Stop writing, remove partial file/dir, and error out
            out.destroy();
            await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
            throw new FilesystemError(
              `STDIN exceeds maximum allowed size (${MAX_BYTES} bytes). Aborting.`
            );
          }

          if (!out.write(buf)) {
            await new Promise<void>(resolve => out.once('drain', resolve));
          }
        }

        await new Promise<void>((resolve, reject) => {
          out.end(() => resolve());
          out.on('error', reject);
        });

        return tmpPath;
      } catch (err) {
        // Best-effort cleanup on any failure
        out.destroy();
        await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
        throw err;
      }
    }

    /* -------------------------------------------------------------- */
    /*  File-path input (streamed)                                     */
    /* -------------------------------------------------------------- */
    if (!useStdin && src) {
      const fileSrc = await FileByteSource.open(src);
      try {
        const meta = await decodeFromSource(fileSrc);
        stdout.write(JSON.stringify(meta, null, 2) + '\n');
      } finally {
        await fileSrc.close();
      }
      return;
    }

    /* -------------------------------------------------------------- */
    /*  STDIN input (stream-to-temp, then decode)                      */
    /* -------------------------------------------------------------- */
    if (useStdin) {
      const tmpPath = await stdinToTempFile();
      const fileSrc = await FileByteSource.open(tmpPath);

      try {
        /* Attempt to parse as raw Cryptit binary first */
        try {
          const meta = await decodeFromSource(fileSrc);
          stdout.write(JSON.stringify(meta, null, 2) + '\n');
          return;
        } catch {
          /* fall through – maybe it’s Base-64 text */
        }
      } finally {
        await fileSrc.close();
      }

      /* Reload temp file as UTF-8 text and attempt Base-64 path */
      const text = (await fsp.readFile(tmpPath, { encoding: 'utf8' })).trim();
      await fsp.unlink(tmpPath);

      const isB64 = /^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length % 4 === 0;
      if (!isB64) {
        stderr.write('Error: Input neither valid Cryptit binary nor Base-64 text\n');
        processExit(1);
      }

      const data = Buffer.from(text, 'base64');
      const meta = await decodeBinary(new Uint8Array(data));
      stdout.write(JSON.stringify(meta, null, 2) + '\n');
      return;
    }

    /* -------------------------------------------------------------- */
    /*  Literal string argument (Base-64 or raw binary)                */
    /* -------------------------------------------------------------- */
    const buf   = Buffer.from(src!, 'utf8');
    const text  = buf.toString('utf8').trim();
    const isB64 = /^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length % 4 === 0;

    try {
      if (isB64) {
        const data = Buffer.from(text, 'base64');
        const meta = await decodeBinary(new Uint8Array(data));
        stdout.write(JSON.stringify(meta, null, 2) + '\n');
      } else {
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
    const webIn  = toWebReadable(inStream);
    const webOut = toWebWritable(outStream);

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

    const webIn  = toWebReadable(inStream);
    const webOut = toWebWritable(outStream);
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
    stdout.write(cipher.base64 + '\n');
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
    stdout.write(plain.text + '\n');
  });

program.parse();