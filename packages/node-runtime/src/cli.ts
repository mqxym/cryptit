#!/usr/bin/env node
// packages/node-runtime/src/cli.ts
import { Command, Option } from 'commander';
import { existsSync, promises as fsp, realpathSync } from 'node:fs';
import { createReadStream, createWriteStream } from 'node:fs';
import { stdin, stdout, stderr, exit as processExit } from 'node:process';
import { randomUUID } from 'node:crypto';
import type { Writable } from 'node:stream';
import { finished } from 'node:stream/promises';
import { FilesystemError } from '../../core/src/errors/index.js';
import { FileByteSource } from '../../core/src/util/ByteSource.js';
import { createCryptit } from './index.js';
import { Cryptit } from '../../core/src/index.js';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { toWebReadable, toWebWritable } from './streamAdapter.js';


const PKG_VERSION = '2.4.0'; // sync with root package.json

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

type PassOptions = { pass?: string; passFile?: string };

function redactPassArg(secret: string): void {
  for (let index = 1; index < process.argv.length; index++) {
    if (
      process.argv[index] === secret &&
      (process.argv[index - 1] === '--pass' || process.argv[index - 1] === '-p')
    ) {
      process.argv[index] = '[REDACTED]';
    }
  }
}

async function resolvePassphrase(
  options: PassOptions,
  canPrompt: boolean,
): Promise<string> {
  if (options.pass !== undefined && options.passFile !== undefined) {
    throw new Error('Use either --pass or --pass-file, not both');
  }
  if (options.pass !== undefined) {
    redactPassArg(options.pass);
    return options.pass;
  }
  if (options.passFile !== undefined) {
    const stat = await fsp.stat(options.passFile);
    const maxBytes = 64 * 1024;
    if (!stat.isFile() || stat.size > maxBytes) {
      throw new Error(`Passphrase file must be a regular file no larger than ${maxBytes} bytes`);
    }
    const value = (await fsp.readFile(options.passFile, 'utf8')).replace(/\r?\n$/, '');
    if (!value) throw new Error('Passphrase file cannot be empty');
    return value;
  }
  if (canPrompt) return promptPass();
  throw new Error('Use --pass-file or --pass when piping via STDIN');
}



interface OutputTransaction {
  stream: Writable;
  commit(): Promise<void>;
  rollback(): Promise<void>;
}

async function openOutputTransaction(
  out: string,
  root: string = DEFAULT_ROOT,
): Promise<OutputTransaction> {
  if (out === '-') {
    return {
      stream: stdout,
      async commit() {},
      async rollback() {},
    };
  }

  const absRoot = realpathSync(root);
  const absOut = isAbsolute(out) ? resolve(out) : resolve(absRoot, out);
  const targetDir = dirname(absOut);
  if (!existsSync(targetDir)) {
    throw new FilesystemError(`Output directory does not exist: ${targetDir}`);
  }

  const realTarget = realpathSync(targetDir);
  const fromRoot = relative(absRoot, realTarget);
  if (fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
    throw new FilesystemError('Refusing to write outside of root directory.');
  }

  const tempPath = resolve(
    realTarget,
    `.${basename(absOut)}.cryptit-tmp-${randomUUID()}`,
  );
  const stream = createWriteStream(tempPath, { flags: 'wx', mode: 0o600 });
  await new Promise<void>((resolveOpen, rejectOpen) => {
    const onOpen = () => {
      stream.off('error', onError);
      resolveOpen();
    };
    const onError = (err: Error) => {
      stream.off('open', onOpen);
      rejectOpen(err);
    };
    stream.once('open', onOpen);
    stream.once('error', onError);
  });

  let settled = false;
  return {
    stream,
    async commit() {
      if (settled) return;
      await finished(stream);
      try {
        await fsp.rename(tempPath, absOut);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== 'EEXIST' && code !== 'EPERM') throw err;
        await fsp.unlink(absOut);
        await fsp.rename(tempPath, absOut);
      }
      settled = true;
    },
    async rollback() {
      if (settled) return;
      settled = true;
      stream.destroy();
      await fsp.rm(tempPath, { force: true }).catch(() => {});
    },
  };
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
  .showHelpAfterError()
  .showSuggestionAfterError()

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

  .addOption(
    new Option('--pass-file <file>', 'read passphrase from a bounded file')
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
      delete (headerMeta as any).saltBytes;

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

      delete (headerMeta as any).saltBytes;

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
      // Default 10 GiB limit; allow override via env (bytes)
      const envLimit = Number(process.env.CRYPTIT_STDIN_MAX_BYTES);
      const TEN_GIB = 10 * 1024 * 1024 * 1024; // 10_737_418_240
      const MAX_BYTES = Number.isFinite(envLimit) && envLimit > 0
        ? Math.floor(envLimit)
        : TEN_GIB; // 10 GiB

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
      try {
        const fileSrc = await FileByteSource.open(tmpPath);
        try {
          try {
            const meta = await decodeFromSource(fileSrc);
            stdout.write(JSON.stringify(meta, null, 2) + '\n');
            return;
          } catch {
            /* fall through - maybe it’s Base-64 text */
          }
        } finally {
          await fileSrc.close();
        }

        const text = (await fsp.readFile(tmpPath, { encoding: 'utf8' })).trim();

        const isB64 = /^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length % 4 === 0;
        if (!isB64) {
          stderr.write('Error: Input neither valid Cryptit binary nor Base-64 text\n');
          processExit(1);
        }

        const data = Buffer.from(text, 'base64');
        const meta = await decodeBinary(new Uint8Array(data));
        stdout.write(JSON.stringify(meta, null, 2) + '\n');
        return;
      } finally {
        await fsp.rm(dirname(tmpPath), { recursive: true, force: true }).catch(() => {});
      }
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
  .option('-p, --pass <passphrase>', 'passphrase (prompt if omitted)')
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
    const pass = await resolvePassphrase(opts, stdin.isTTY);
    

    let output: OutputTransaction;
    try {
      output = await openOutputTransaction(cmd.out);
    } catch (err: any) {
      stderr.write(`Error: ${err.message}\n`);
      processExit(1);
    }

    const inStream  = src  === '-' ? stdin  : createReadStream(src);
    try {
      const { header, writable, readable } = await crypt.createEncryptionStream(pass);
      const webIn  = toWebReadable(inStream);
      const webOut = toWebWritable(output.stream);

      const w = webOut.getWriter();
      await w.write(header);
      w.releaseLock();

      await Promise.all([
        webIn.pipeTo(writable),
        readable.pipeTo(webOut),
      ]);
      await output.commit();
    } catch (err) {
      await output.rollback();
      throw err;
    }
  });

program
  .command('decrypt <src>')
  .description('Decrypt file; use - for STDIN, --out - for STDOUT')
  .option('-p, --pass <passphrase>', 'passphrase (prompt if omitted)')
  .option('-o, --out <file>', 'output file (default STDOUT)', '-')
  .option('--legacy', 'Enable text decryption of version < 1.0.0', false)
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
      acceptUnauthenticatedHeader: cmd.legacy,
    });

    let output: OutputTransaction;
    try {
      output = await openOutputTransaction(cmd.out);
    } catch (err: any) {
      stderr.write(`Error: ${err.message}\n`);
      processExit(1);
    }


    const pass = await resolvePassphrase(opts, stdin.isTTY);
    const inStream  = src  === '-' ? stdin  : createReadStream(src);
    try {
      const webIn  = toWebReadable(inStream);
      const webOut = toWebWritable(output.stream);
      const ts     = await crypt.createDecryptionStream(pass);

      await Promise.all([
        webIn.pipeTo(ts.writable),
        ts.readable.pipeTo(webOut),
      ]);
      await output.commit();
    } catch (err) {
      await output.rollback();
      throw err;
    }
  });

program
  .command('encrypt-text [text]')
  .description('Encrypt plaintext; omit arg to read from STDIN')
  .option('-p, --pass <passphrase>', 'passphrase (prompt if omitted)')
  .action(async (text) => {
    const opts  = program.opts();
    const crypt = createCryptit({
      difficulty: opts.difficulty,
      saltStrength: opts.saltStrength,
      verbose: opts.verbose,
      scheme: opts.scheme,
    });
    const pass = await resolvePassphrase(opts, stdin.isTTY);
    const plain = text ?? (await readAllFromStdin());
    const cipher = await crypt.encryptText(plain, pass);
    stdout.write(cipher.base64 + '\n');
  });

program
  .command('decrypt-text [b64]')
  .description('Decrypt Base64 ciphertext; omit arg to read from STDIN')
  .option('-p, --pass <passphrase>', 'passphrase (prompt if omitted)')
  .option('--legacy', 'Enable text decryption of version < 1.0.0', false)
  .action(async (b64, options: {legacy?: boolean}) => {
    const opts  = program.opts();
    const crypt = createCryptit({
      difficulty: opts.difficulty,
      saltStrength: opts.saltStrength,
      verbose: opts.verbose,
      scheme: opts.scheme,
      acceptUnauthenticatedHeader: options.legacy,
    });
    const pass = await resolvePassphrase(opts, stdin.isTTY);
    const data = b64 ?? (await readAllFromStdin()).trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(data)) {
      stderr.write('Error: ciphertext does not look like Base64\n');
      processExit(1);
    }
    const plain = await crypt.decryptText(data, pass);
    stdout.write(plain.text + '\n');
  });

program
  .command('fake-data <length>')
  .description('Emit a valid Cryptit header followed by <length> random bytes')
  .option('-o, --out <file>', 'output file (default STDOUT)', '-')
  .option('--base64', 'encode output as Base64 text (adds trailing newline)')
  .option('--use-padding', "rounds <length> to the nearest 8 bytes to allow for realistic text-payloads.", false)
  .action(async (lengthArg: string, cmd: { out: string; base64?: boolean; usePadding: boolean }) => {
    const len = Number(lengthArg);
    if (!Number.isInteger(len) || len < 0) {
      stderr.write('Error: <length> must be a non-negative integer\n');
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

    let output: OutputTransaction;
    try {
      output = await openOutputTransaction(cmd.out);
    } catch (err: any) {
      stderr.write(`Error: ${err.message}\n`);
      processExit(1);
    }

    // Generate header + random payload
    const data = crypt.generateFakeData(len, cmd.usePadding);
    const buf  = Buffer.from(data);

    const payload = cmd.base64
      ? Buffer.from(buf.toString('base64') + '\n', 'utf8')
      : buf;
    try {
      if (cmd.out === '-') {
        stdout.write(payload);
      } else {
        await new Promise<void>((resolveWrite, rejectWrite) => {
          output.stream.once('error', rejectWrite);
          output.stream.end(payload, resolveWrite);
        });
      }
      await output.commit();
    } catch (err) {
      await output.rollback();
      throw err;
    }
  });

if (process.argv.length <= 2) {
  program.outputHelp();
  process.exit(1);
}

program.parse();