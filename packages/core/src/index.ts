// packages/core/src/index.ts

import './config/defaults.js';

import type { CryptoProvider }    from './providers/CryptoProvider.js';
import { Difficulty, SaltStrength } from './config/defaults.js';
import { encodeHeader }             from './header/encoder.js';
import { decodeHeader }             from './header/decoder.js';
import {
  EncryptionAlgorithm,
  KeyDerivation,
  SchemeDescriptor,
  Secret
} from './types/index.js';
import { SchemeRegistry }          from './config/SchemeRegistry.js';
import { base64Encode, base64Decode, concat, zeroizeString } from './util/bytes.js';
import { StreamProcessor }          from './stream/StreamProcessor.js';
import { EncryptTransform }         from './stream/EncryptTransform.js';
import { DecryptTransform }         from './stream/DecryptTransform.js';

import {
  createLogger,
  type Verbosity,
  type Logger,
} from './util/logger.js';
import { ByteSource }          from './util/ByteSource.js';

import {
  EncryptionError,
  DecryptionError,
  KeyDerivationError,
  InvalidHeaderError,
  HeaderDecodeError,
  DecodingError,
} from './errors/index.js';

import { EngineManager, type Engine } from './engine/EngineManager.js';

// ────────────────────────────────────────────────────────────────────────────
//  Public configuration shape
// ────────────────────────────────────────────────────────────────────────────

/**
 * Result of creating an encryption stream: header and paired streams.
 */
export interface EncryptStreamResult {
  /** Binary header for decryption initialization */
  header   : Uint8Array;
  /** Writable stream to feed plaintext data */
  writable : WritableStream<Uint8Array>;
  /** Readable stream emitting ciphertext data */
  readable : ReadableStream<Uint8Array>;
}

/**
 * Options for configuring Cryptit instance behavior.
 */
export interface CryptitOptions {
  /** Version identifier (0…7) to use; defaults to registry's current scheme */
  scheme?      : number;
  /** Salt strength: 'low' | 'middle' | 'high'; defaults to descriptor's default */
  saltStrength? : SaltStrength;
  /** Key derivation difficulty; defaults to descriptor's default */
  difficulty?   : Difficulty;
  /** Chunk size for streaming operations; defaults to descriptor's default */
  chunkSize?    : number;
  /** Verbosity level 0-4 for logging (0 = errors only) */
  verbose?      : Verbosity;
  /** Optional custom logger callback (receives formatted messages) */
  logger?       : (msg: string) => void;
}

export type DecodeDataResult =
  | { isChunked: true;  chunks: { chunkSize: number; count: number; totalPayload: number } }
  | { isChunked: false; payloadLength: number; params: { iv: Uint8Array; tag: Uint8Array } };

/**
 * Cryptit provides high-level encryption/decryption utilities for text, blobs, and streams.
 */
export class Cryptit {
  // — runtime-mutable --------------------------------------------------------
  private v          : SchemeDescriptor;
  private cipher     : EncryptionAlgorithm;
  private kdf        : KeyDerivation;
  private chunkSize  : number;
  private stream     : StreamProcessor;

  private difficulty   : Difficulty;
  private saltStrength : SaltStrength;

  private readonly engines = new Map<number, Engine>();

  // — diagnostics ------------------------------------------------------------
  private readonly log : Logger;

  /**
   * Create a new Cryptit instance with given crypto provider and options.
   * @param provider - Underlying crypto provider for key derivation and randomness
   * @param opt - Configuration options for scheme, salts, logging, etc.
   */
  constructor(
    private readonly provider: CryptoProvider,
    opt: CryptitOptions = {},
  ) {
    this.v          = SchemeRegistry.get(opt.scheme ?? SchemeRegistry.current.id);
    this.cipher     = new this.v.cipher(provider);
    this.kdf        = this.v.kdf;
    this.chunkSize  = this.setChunkSize(opt.chunkSize ?? this.v.defaultChunkSize);
    this.stream     = new StreamProcessor(this.cipher, this.chunkSize);

    this.difficulty     = opt.difficulty   ?? 'middle';
    this.saltStrength   = opt.saltStrength ?? 'high';

    this.log = createLogger(opt.verbose ?? 0, opt.logger);
  }

  // ════════════════════════════════════════════════════════════════════════
  //  PUBLIC  - Informational helpers
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Check if the provided input contains a valid Cryptit header.
   * @param input - Base64 string, Uint8Array, or Blob to inspect
   * @returns True if header is valid; false otherwise
   */
  static async isEncrypted(
    input: string | Uint8Array | Blob,
  ): Promise<boolean> {
    try {
      await Cryptit.peekHeader(input);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Decode the Cryptit header and return readable metadata.
   * @param input - Base64 string, Uint8Array, or Blob to decode
   * @returns Object containing scheme, difficulty, salt (Base64), and salt length
   */
  static async headerDecode(
    input: string | Uint8Array | Blob,
  ): Promise<{ scheme: number; difficulty: Difficulty; salt: string; saltLength: number; }> {
    const hdr = await Cryptit.peekHeader(input);
    const h   = decodeHeader(hdr);
    return {
      scheme    : h.scheme,
      difficulty : h.difficulty,
      salt       : base64Encode(h.salt),
      saltLength : h.salt.byteLength,
    };
  }

  /**
   * Inspect an encrypted payload and return either:
   *   • chunk statistics for file/stream containers
   *   • IV/nonce & auth‑tag for single‑block text containers
   *
   * This never decrypts – it merely parses framing bytes.
   */
  static async decodeData(
    input: string | Uint8Array | Blob,
  ): Promise<DecodeDataResult> {
    // Read up to 256 B to validate header
    const src       = new ByteSource(input);
    const headSlice = await src.read(0, Math.min(256, src.length));
    const header    = await Cryptit.peekHeader(headSlice);
    const { scheme, headerLen } = decodeHeader(header);

    // Compute remaining payload length
    const totalLen  = src.length;
    const remain    = totalLen - headerLen;
    if (remain <= 0) {
      throw new InvalidHeaderError('Payload is empty');
    }

    const first4   = await src.read(headerLen, 4);
    const firstLen = new DataView(first4.buffer, first4.byteOffset, 4)
                      .getUint32(0, false);

    const looksChunked =
      firstLen + 4 <= remain &&  // frame fits
      firstLen >= 28;            // at least IV+tag

    if (looksChunked) {
      // ——— chunked container ———
      const chunkSize = firstLen;
      let offset = headerLen;
      let count  = 0;
      let total  = 0;

      while (offset + 4 <= totalLen) {
        const lenBuf = await src.read(offset, 4);
        const len    = new DataView(lenBuf.buffer, lenBuf.byteOffset, 4)
                          .getUint32(0, false);
        if (len === 0 || offset + 4 + len > totalLen) break;
        count++;
        total += len;
        offset += 4 + len;
      }

      return {
        isChunked: true,
        chunks: {
          chunkSize,
          count,
          totalPayload: total,
        },
      };
    }

    // ——— single-block (encryptText) ———
    const cipher      = await src.read(headerLen, remain);
    const ivLen       = SchemeRegistry.get(scheme).cipher.IV_LENGTH;
    if (cipher.length < ivLen + 16) {
      throw new InvalidHeaderError('Ciphertext too short for IV & tag');
    }

    return {
      isChunked: false,
      // full encrypted payload length (including IV+cipher+tag)
      payloadLength: remain,
      params: {
        iv : cipher.slice(0, ivLen),
        tag: cipher.slice(cipher.length - 16),
      },
    } as const;
  }

  // ════════════════════════════════════════════════════════════════════════
  //  PUBLIC  - Setters / getters for run-time flexibility
  // ════════════════════════════════════════════════════════════════════════
  /** Set the difficulty level for subsequent operations. */
  setDifficulty(d: Difficulty): void         { this.difficulty = d; }
  /** Get the current difficulty setting. */
  getDifficulty(): Difficulty                { return this.difficulty; }

  /**
   * Change the protocol scheme for future encrypt/decrypt actions.
   * @param id - Version identifier from registry
   */
  setScheme(id: number): void {
    this.v       = SchemeRegistry.get(id);
    this.cipher  = new this.v.cipher(this.provider);
    this.kdf     = this.v.kdf;
    this.stream  = new StreamProcessor(this.cipher, this.chunkSize);
  }
  /** Retrieve the active protocol scheme identifier. */
  getScheme(): number                       { return this.v.id; }

  /**
   * Override salt length (in bytes) for new operations (advanced use).
   * @param len - Custom salt length in bytes
   */
  setSaltDifficulty(d: SaltStrength): void           { this.saltStrength = d; }
  /** Get the effective salt length for the current strength. */
  getSaltDifficulty(): SaltStrength {
    return this.saltStrength;
  }

  /**
   * Configure chunk size (bytes) for streaming transforms.
   * @param bytes - Desired chunk size in bytes
   */
  setChunkSize(bytes: number): number {
     
    const rawSize = bytes;
    let size: number;

    if (rawSize == null) {
      size = this.v.defaultChunkSize;
    } else {
      size = Number(rawSize);
      if (!Number.isInteger(size) || size < 1) {
        throw new Error(
          `Invalid chunkSize: ${rawSize}. Must be a positive integer.`
        );
      }
    }

    // finally assign
    this.chunkSize = size;
    this.stream    = new StreamProcessor(this.cipher, this.chunkSize);
    return size;
  }
  /** Retrieve the current streaming chunk size. */
  getChunkSize(): number                     { return this.chunkSize; }

  /**
   * Adjust verbosity level of internal logger at runtime.
   * @param level - Logger verbosity (0-4)
   */
  setVerbose(level: Verbosity): void         { (this.log as any).level = level; }
  /** Get the current logger verbosity setting. */
  getVerbose(): Verbosity                    { return this.log.level; }

  // ════════════════════════════════════════════════════════════════════════
  //  TEXT convenience
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Encrypt plaintext (string or Uint8Array) and return Base64-encoded result.
   * @param plain - Data to encrypt (text or bytes)
   * @param pass - Passphrase for key derivation
   * @returns Base64 string containing header and ciphertext
   * @throws EncryptionError on failure
   */
  async encryptText(plain: string | Uint8Array, pass: string): Promise<string> {
    const secret = { value: pass };

    try {
      this.log.log(1, `Start text encryption, scheme: ${this.getScheme()}`);
      this.log.log(2, 'Deriving key for text encryption');
      const salt = this.genSalt();
      await this.deriveKey(secret, salt);
      
      zeroizeString(secret);
      pass = null as any;
      
      this.log.log(3, `Salt generated: ${base64Encode(salt)}, KDF difficulty: ${this.difficulty}`);

      this.log.log(2, 'Encrypting text data');
      const cipher = await this.cipher.encryptChunk(
        typeof plain === 'string' ? new TextEncoder().encode(plain) : plain,
      );
      this.cipher.zeroKey();
      this.log.log(3, 'Encoding header');
      const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt);
      this.log.log(3, 'Encoding text');
      const result = base64Encode(header, cipher);
      this.log.log(1, 'Decryption finished');
      return result;

    } catch (err) {
      throw new EncryptionError(
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  /**
   * Decrypt a Base64-encoded ciphertext string using the provided passphrase.
   * @param b64 - Base64 string containing header and ciphertext
   * @param pass - Passphrase for key derivation
   * @returns Decrypted plaintext string
   * @throws DecryptionError on failure or invalid header
   */
  async decryptText(b64: string, pass: string): Promise<string> {
    const secret = { value: pass };
    try {
      this.log.log(1, `Start text decryption, Version ${this.getScheme()}`);
      this.log.log(3, 'Start text decoding');
      const data   = base64Decode(b64);
      this.log.log(3, 'Start header decoding');

      await Cryptit.peekHeader(b64);
      const hdr    = decodeHeader(data);

      this.log.log(3, 'Trying to get engine');

      const engine = EngineManager.getEngine(this.provider, hdr.scheme);

      this.log.log(2, `Deriving key via engine for scheme: ${hdr.scheme}`);
      this.log.log(3, `Salt use: ${base64Encode(hdr.salt)}, KDF difficulty: ${hdr.difficulty}`);
      
      try {
        await EngineManager.deriveKey(engine, secret, hdr.salt, hdr.difficulty);
      } finally {
        zeroizeString(secret);
         pass = null as any;
      }

      this.log.log(2, 'Decrypting text data');
      const plainBytes = await engine.cipher.decryptChunk(
        data.slice(hdr.headerLen),
      );
      engine.cipher.zeroKey();
      this.log.log(3, 'Decoding text');
      const text = new TextDecoder().decode(plainBytes);
      this.log.log(1, 'Decryption finished');
      return text;

    } catch (err) {
      if (
        err instanceof DecryptionError   ||
        err instanceof InvalidHeaderError||
        err instanceof HeaderDecodeError ||
        err instanceof DecodingError ||
        err instanceof KeyDerivationError
      ) throw err;

      throw new DecryptionError(
        'Decryption failed: wrong passphrase or corrupted ciphertext',
      );
    }
  }

  /* ──────────────────────────────────────────────────────────
     Encrypt a whole Blob and return an opaque binary Blob
     ────────────────────────────────────────────────────────── */
  /**
   * Encrypt a Blob (file) and return a new Blob with embedded header.
   * @param file - Input Blob to encrypt
   * @param pass - Passphrase for key derivation
   * @returns Encrypted Blob (application/octet-stream)
   * @throws EncryptionError on failure
   */
  async encryptFile(file: Blob, pass: string): Promise<Blob> {
    const secret = { value: pass };
    try {

      if (file.size === 0) {
        const salt = this.genSalt();
        await this.deriveKey(secret, salt);

        zeroizeString(secret);
        pass = null as any;

        const header = encodeHeader(
          this.v.id,
          this.difficulty,
          this.saltStrength,
          salt,
        );
        /* nothing to encrypt ⇒ header alone is a valid container */
        return new Blob([header], { type: 'application/octet-stream' });
      }
      this.log.log(2, 'Deriving key for file encryption');
      const salt = this.genSalt();
      await this.deriveKey(secret, salt);

      zeroizeString(secret);
      pass = null as any;

      const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt);

      const cipher = await this.stream.collect(
        file.stream() as ReadableStream<Uint8Array>,
        new EncryptTransform(this.cipher, this.chunkSize).toTransformStream(),
        header,
      );

      return new Blob([cipher], { type: 'application/octet-stream' });

    } catch (err) {
      throw new EncryptionError(
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  /* ──────────────────────────────────────────────────────────
     Decrypt a Blob that carries its own header (any scheme)
     ────────────────────────────────────────────────────────── */
  /**
   * Decrypt an encrypted Blob using the embedded header for parameters.
   * @param file - Encrypted Blob containing header + ciphertext
   * @param pass - Passphrase for key derivation
   * @returns Decrypted Blob (application/octet-stream)
   * @throws DecryptionError on failure or invalid header
   */
  async decryptFile(file: Blob, pass: string): Promise<Blob> {
    const secret = { value: pass };
    try {
      const header = await Cryptit.peekHeader(file);
      const parsed = decodeHeader(header);
      const engine = EngineManager.getEngine(this.provider, parsed.scheme);

      try {
        await EngineManager.deriveKey(engine, secret, parsed.salt, parsed.difficulty);
      } finally {
        zeroizeString(secret);
        pass = null as any;
      }

      // ── 0-byte optimisation ────────────────────────────────────────
      if (file.size === parsed.headerLen) {
        /* container carries header only - nothing to decrypt */
        return new Blob([], { type: 'application/octet-stream' });
      }

      this.log.log(2, 'Decrypting file data');
      const streamProc = new StreamProcessor(engine.cipher, engine.chunkSize);
      const plain = await streamProc.collect(
        file.slice(parsed.headerLen).stream() as ReadableStream<Uint8Array>,
        new DecryptTransform(engine.cipher, engine.chunkSize).toTransformStream(),
      );

      return new Blob([plain], { type: 'application/octet-stream' });

    } catch (err) {
      if (err instanceof DecryptionError) throw err;
      throw new DecryptionError(
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  /* ──────────────────────────────────────────────────────────
     Streaming encryption: returns header + TransformStream
     ────────────────────────────────────────────────────────── */
  /**
   * Initialize streaming encryption, returning header and transform streams.
   * @param pass - Passphrase for key derivation
   * @returns Streams and header for real-time encryption
   */
  async createEncryptionStream(pass: string): Promise<EncryptStreamResult> {
    const secret = { value: pass };

    this.log.log(2, 'Deriving key for stream encryption');
    const salt = this.genSalt();
    await this.deriveKey(secret, salt);

    zeroizeString(secret);
    pass = null as any;

    const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt);
    const tf     = this.stream.encryptionStream();

    return { header, writable: tf.writable, readable: tf.readable };
  }

  /* ──────────────────────────────────────────────────────────
     Streaming decryption (auto-detect header, any scheme)
     ────────────────────────────────────────────────────────── */
  /**
   * Create a TransformStream for decrypting incoming ciphertext with header auto-detection.
   * @param passp - Passphrase for key derivation
   * @returns TransformStream encrypting Uint8Array chunks to Uint8Array plaintext chunks
   */
  async createDecryptionStream(
    pass: string,
  ): Promise<TransformStream<Uint8Array, Uint8Array>> {
    const secret = { value: pass };

    const self = this;
    let   buf: Uint8Array<ArrayBufferLike>  = new Uint8Array(0);
    let   downstream: TransformStream<Uint8Array, Uint8Array> | null = null;

    async function pipeOut(
      readable: ReadableStream<Uint8Array>,
      ctl: TransformStreamDefaultController<Uint8Array>,
    ) {
      const rd = readable.getReader();
      while (true) {
        const { value, done } = await rd.read();
        if (done) break;
        ctl.enqueue(value);
      }
    }

    return new TransformStream<Uint8Array, Uint8Array>({
      async transform(chunk, ctl) {
        if (!downstream) {
          
          buf = concat(buf, chunk);
          if (buf.length < 2) return;

          const header             = buf.slice(0, 30); // Raw estimate
          const { salt, difficulty } = decodeHeader(header);

          const scheme      = buf[1] >> 5;
          const saltStrength = ((buf[1] >> 2) & 1) ? 'high' : 'low';
          const saltLen      = SchemeRegistry.get(scheme).saltLengths[saltStrength];
          const hdrLen       = 2 + saltLen;
          if (buf.length < hdrLen) return;
        
          const engine  = EngineManager.getEngine(self.provider, scheme);

          try {
            await EngineManager.deriveKey(engine, secret, salt, difficulty);
          } finally {
            zeroizeString(secret);
            pass = null as any;
          }

          downstream = new DecryptTransform(engine.cipher, engine.chunkSize).toTransformStream();
          pipeOut(downstream.readable, ctl);

          const remainder = buf.slice(hdrLen);
          if (remainder.length) {
            const w = downstream.writable.getWriter();
            await w.write(remainder);
            w.releaseLock();
          }
          return;
        }

        const writer = downstream.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
      },

      async flush() {
        if (downstream) {
          const writer = downstream.writable.getWriter();
          await writer.close();
          writer.releaseLock();
        }
      },
    });
  }

  // ════════════════════════════════════════════════════════════════════════
  //  Helpers
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Derive cryptographic key from passphrase and salt using configured KDF.
   * @param pass - Passphrase to derive key from
   * @param salt - Random salt value
   * @param diff - Difficulty level for KDF (optional)
   * @throws KeyDerivationError on KDF failure
   */
  private async deriveKey(
    secret: Secret,
    salt: Uint8Array,
    diff: Difficulty = this.difficulty,
  ): Promise<void> {
    const start = performance.now();
    try {
      const key = await this.kdf.derive(secret.value, salt, diff, this.provider);
      zeroizeString(secret);
      
      await this.cipher.setKey(key);
      this.log.log(3, `Key derivation completed in ${(performance.now() - start).toFixed(1)} ms`);
    } catch (err) {
      throw new KeyDerivationError(
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  /** Generate a secure random salt according to configured length. */
  private genSalt(): Uint8Array {
    const len = this.v.saltLengths[this.saltStrength];
    return this.provider.getRandomValues(new Uint8Array(len));
  }

  // ────────────────────────────────────────────────────────────────────
  //  Static helper - read just enough bytes to parse the header
  // ────────────────────────────────────────────────────────────────────
  /**
   * Read minimal bytes to extract and validate Cryptit header.
   * @param input - Base64 string, Uint8Array, or Blob containing header
   * @returns Uint8Array slice of the header bytes
   * @throws HeaderDecodeError or InvalidHeaderError on invalid input
   */

  private static async peekHeader(input: string | Uint8Array | Blob) {
    const buf = await this.readAsUint8(input);

    // Handle raw Uint8Array input
    if (buf instanceof Uint8Array) {
      if (buf.length < 2) throw new InvalidHeaderError('Input too short');
      const { headerLen } = decodeHeader(
        buf.length >= 16 ? buf : Uint8Array.from(buf),
      );
      if (buf.length < headerLen) throw new InvalidHeaderError('Incomplete header');
      return buf.slice(0, headerLen);
    }
    throw new HeaderDecodeError('Unsupported input type');
  }

  private static async readAsUint8(input: string | Uint8Array | Blob): Promise<Uint8Array> {
    if (typeof input === 'string')      return base64Decode(input);
    if (input instanceof Uint8Array)    return input;
    if (input instanceof Blob)          return new Uint8Array(await input.arrayBuffer());
    throw new HeaderDecodeError('Unsupported input type');
  }
}
