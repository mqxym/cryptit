// packages/core/src/index.ts

import './config/defaults.js';

import type { CryptoProvider }    from './providers/CryptoProvider.js';
import { Difficulty, SaltStrength } from './config/defaults.js';
import { encodeHeader }             from './header/encoder.js';
import { decodeHeader }             from './header/decoder.js';
import {
  EncryptionAlgorithm,
  KeyDerivation,
  VersionDescriptor,
} from './types/index.js';
import { VersionRegistry }          from './config/VersionRegistry.js';
import { base64Encode, base64Decode, concat } from './util/bytes.js';
import { StreamProcessor }          from './stream/StreamProcessor.js';
import { EncryptTransform }         from './stream/EncryptTransform.js';
import { DecryptTransform }         from './stream/DecryptTransform.js';

import {
  createLogger,
  type Verbosity,
  type Logger,
} from './util/logger.js';

import {
  EncryptionError,
  DecryptionError,
  KeyDerivationError,
  InvalidHeaderError,
  HeaderDecodeError,
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
  /** Version identifier (0…7) to use; defaults to registry's current version */
  version?      : number;
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

/**
 * Cryptit provides high-level encryption/decryption utilities for text, blobs, and streams.
 */
export class Cryptit {
  // — runtime‑mutable --------------------------------------------------------
  private v          : VersionDescriptor;
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
   * @param opt - Configuration options for version, salts, logging, etc.
   */
  constructor(
    private readonly provider: CryptoProvider,
    opt: CryptitOptions = {},
  ) {
    this.v          = VersionRegistry.get(opt.version ?? VersionRegistry.current.id);
    this.cipher     = new this.v.cipher(provider);
    this.kdf        = this.v.kdf;
    this.chunkSize  = opt.chunkSize ?? this.v.defaultChunkSize;
    this.stream     = new StreamProcessor(this.cipher, this.chunkSize);

    this.difficulty     = opt.difficulty   ?? 'middle';
    this.saltStrength   = opt.saltStrength ?? 'high';

    this.log = createLogger(opt.verbose ?? 0, opt.logger);
  }

  // ════════════════════════════════════════════════════════════════════════
  //  PUBLIC  – Informational helpers
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
   * @returns Object containing version, difficulty, salt (Base64), and salt length
   */
  static async headerDecode(
    input: string | Uint8Array | Blob,
  ): Promise<{ version: number; difficulty: Difficulty; salt: string; saltLength: number; }> {
    const hdr = await Cryptit.peekHeader(input);
    const h   = decodeHeader(hdr);
    return {
      version    : h.version,
      difficulty : h.difficulty,
      salt       : base64Encode(h.salt),
      saltLength : h.salt.byteLength,
    };
  }

  // ════════════════════════════════════════════════════════════════════════
  //  PUBLIC  – Setters / getters for run‑time flexibility
  // ════════════════════════════════════════════════════════════════════════
  /** Set the difficulty level for subsequent operations. */
  setDifficulty(d: Difficulty): void         { this.difficulty = d; }
  /** Get the current difficulty setting. */
  getDifficulty(): Difficulty                { return this.difficulty; }

  /**
   * Change the protocol version for future encrypt/decrypt actions.
   * @param id - Version identifier from registry
   */
  setVersion(id: number): void {
    this.v       = VersionRegistry.get(id);
    this.cipher  = new this.v.cipher(this.provider);
    this.kdf     = this.v.kdf;
    this.stream  = new StreamProcessor(this.cipher, this.chunkSize);
  }
  /** Retrieve the active protocol version identifier. */
  getVersion(): number                       { return this.v.id; }

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
  setChunkSize(bytes: number): void {
    this.chunkSize = bytes;
    this.stream    = new StreamProcessor(this.cipher, this.chunkSize);
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
    try {
      this.log.log(1, 'Start text encryption');
      this.log.log(2, 'Deriving key for text encryption');
      const salt = this.genSalt();
      await this.deriveKey(pass, salt);
      this.log.log(3, `Salt generated: ${base64Encode(salt)}, difficulty: ${this.difficulty}`);

      this.log.log(2, 'Encrypting text data');
      const cipher = await this.cipher.encryptChunk(
        typeof plain === 'string' ? new TextEncoder().encode(plain) : plain,
      );
      this.log.log(3, 'Encoding header');
      const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt);
      this.log.log(3, 'Encoding text');
      return base64Encode(header, cipher);

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
    try {
      this.log.log(1, 'Start text decryption');
      const data   = base64Decode(b64);
      this.log.log(3, 'Start header decoding');
      const hdr    = decodeHeader(data);
      this.log.log(3, 'Trying to get engine');
      const engine = EngineManager.getEngine(this.provider, hdr.version);
      this.log.log(2, 'Deriving key via engine for text decryption');
      await EngineManager.deriveKey(engine, pass, hdr.salt, hdr.difficulty);

      this.log.log(2, 'Decrypting text data');
      const plainBytes = await engine.cipher.decryptChunk(
        data.slice(hdr.headerLen),
      );
      this.log.log(3, 'Decoding text');
      return new TextDecoder().decode(plainBytes);

    } catch (err) {
      if (
        err instanceof DecryptionError   ||
        err instanceof InvalidHeaderError||
        err instanceof HeaderDecodeError ||
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
    try {
      this.log.log(2, 'Deriving key for file encryption');
      const salt = this.genSalt();
      await this.deriveKey(pass, salt);

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
     Decrypt a Blob that carries its own header (any version)
     ────────────────────────────────────────────────────────── */
  /**
   * Decrypt an encrypted Blob using the embedded header for parameters.
   * @param file - Encrypted Blob containing header + ciphertext
   * @param pass - Passphrase for key derivation
   * @returns Decrypted Blob (application/octet-stream)
   * @throws DecryptionError on failure or invalid header
   */
  async decryptFile(file: Blob, pass: string): Promise<Blob> {
    try {
      const header = await Cryptit.peekHeader(file);
      const parsed = decodeHeader(header);
      const engine = EngineManager.getEngine(this.provider, parsed.version);

      await EngineManager.deriveKey(engine, pass, parsed.salt, parsed.difficulty);

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
    this.log.log(2, 'Deriving key for stream encryption');
    const salt = this.genSalt();
    await this.deriveKey(pass, salt);

    const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt);
    const tf     = this.stream.encryptionStream();

    return { header, writable: tf.writable, readable: tf.readable };
  }

  /* ──────────────────────────────────────────────────────────
     Streaming decryption (auto-detect header, any version)
     ────────────────────────────────────────────────────────── */
  /**
   * Create a TransformStream for decrypting incoming ciphertext with header auto-detection.
   * @param passphrase - Passphrase for key derivation
   * @returns TransformStream encrypting Uint8Array chunks to Uint8Array plaintext chunks
   */
  async createDecryptionStream(
    passphrase: string,
  ): Promise<TransformStream<Uint8Array, Uint8Array>> {

    const self = this;
    let   buf  = new Uint8Array(0);
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

          const version      = buf[1] >> 5;
          const saltStrength = ((buf[1] >> 2) & 1) ? 'high' : 'low';
          const saltLen      = VersionRegistry.get(version).saltLengths[saltStrength];
          const hdrLen       = 2 + saltLen;
          if (buf.length < hdrLen) return;
        
          const engine  = EngineManager.getEngine(self.provider, version);
          await EngineManager.deriveKey(engine, passphrase, salt, difficulty);

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
    pass: string,
    salt: Uint8Array,
    diff: Difficulty = this.difficulty,
  ): Promise<void> {
    const start = performance.now();
    try {
      const key = await this.kdf.derive(pass, salt, diff, this.provider);
      (this.cipher as any).key = key;
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
  //  Static helper – read just enough bytes to parse the header
  // ────────────────────────────────────────────────────────────────────
  /**
   * Read minimal bytes to extract and validate Cryptit header.
   * @param input - Base64 string, Uint8Array, or Blob containing header
   * @returns Uint8Array slice of the header bytes
   * @throws HeaderDecodeError or InvalidHeaderError on invalid input
   */
  private static async peekHeader(
    input: string | Uint8Array | Blob,
  ): Promise<Uint8Array> {
    // Handle Base64 text input
    if (typeof input === 'string') {
      return base64Decode(input);
    }

    // Handle raw Uint8Array input
    if (input instanceof Uint8Array) {
      if (input.length < 2) throw new InvalidHeaderError('Input too short');
      const { headerLen } = decodeHeader(
        input.length >= 16 ? input : Uint8Array.from(input),
      );
      if (input.length < headerLen) throw new InvalidHeaderError('Incomplete header');
      return input.slice(0, headerLen);
    }

    // Handle Blob/File input
    if (input instanceof Blob) {
      const first2 = new Uint8Array(await input.slice(0, 2).arrayBuffer());
      if (first2[0] !== 0x01) throw new InvalidHeaderError('Bad magic byte');

      const info        = first2[1];
      const version     = info >> 5;
      const saltStrength= ((info >> 2) & 1) ? 'high' : 'low';
      const saltLen     = VersionRegistry.get(version).saltLengths[saltStrength];

      const header = new Uint8Array(
        await input.slice(0, 2 + saltLen).arrayBuffer(),
      );
      decodeHeader(header); // validate header contents
      return header;
    }

    throw new HeaderDecodeError('Unsupported input type');
  }
}
