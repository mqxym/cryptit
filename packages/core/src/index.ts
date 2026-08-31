// packages/core/src/index.ts

import './config/defaults.js';

import type { CryptoProvider }    from './providers/CryptoProvider.js';
import { Difficulty, SaltStrength } from './config/defaults.js';
import { encodeHeader }             from './header/encoder.js';
import { decodeHeader }             from './header/decoder.js';
import {
  KeyDerivation,
  PaddingAwareEncryptionAlgorithm,
  SchemeDescriptor,
  Secret
} from './types/index.js';
import { SchemeRegistry }          from './config/SchemeRegistry.js';
import { base64Encode, base64Decode, concat, zeroizeString } from './util/bytes.js';
import { StreamProcessor }          from './stream/StreamProcessor.js';
import { EncryptTransform }         from './stream/EncryptTransform.js';
import { DecryptTransform }         from './stream/DecryptTransform.js';
import { ConvertibleInput, ConvertibleOutput } from './util/Convertible.js';

import { Magic48VerCrc8Padding } from './algorithms/padding/magic48ver-crc8.js';

import {
  createLogger,
  type Verbosity,
  type Logger,
} from './util/logger.js';
import {  ByteSource, RandomAccessSource }          from './util/ByteSource.js';

import {
  EncryptionError,
  DecryptionError,
  KeyDerivationError,
  InvalidHeaderError,
  HeaderDecodeError,
  DecodingError,
  SchemeError,
  ConfigError,
} from './errors/index.js';

import { EngineManager, type Engine } from './engine/EngineManager.js';
import {
  decodeStreamRecord,
  FRAME_HEADER_BYTES,
  MAX_CIPHER_FRAME_SIZE,
  MAX_PLAINTEXT_CHUNK_SIZE,
  type StreamFormat,
} from './util/frame.js';

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
  /** Framing used for new file/stream ciphertext; defaults to authenticated-v1 */
  streamFormat? : StreamFormat;
  /** Highest KDF difficulty accepted from ciphertext headers; defaults to high */
  maxDecryptionDifficulty? : Difficulty;
  /** Enable legacy file and text decryption version < 1.0.0 */
  acceptUnauthenticatedHeader?    : boolean;
  /** Verbosity level 0-4 for logging (0 = errors only) */
  verbose?      : Verbosity;
  /** Optional custom logger callback (receives formatted messages) */
  logger?       : (msg: string) => void;
}

export type DecodeDataResult =
  | { isChunked: true; format: StreamFormat; authenticated: boolean; chunks: { chunkSize: number; count: number; totalPayload: number } }
  | { isChunked: false; payloadLength: number; params: { iv: Uint8Array; ivLength: number; tag: Uint8Array; tagLength: number } };

/**
 * Cryptit provides high-level encryption/decryption utilities for text, blobs, and streams.
 */
export class Cryptit {
  // — runtime-mutable --------------------------------------------------------
  private v          : SchemeDescriptor;
  private cipher     : PaddingAwareEncryptionAlgorithm;
  private kdf        : KeyDerivation;
  private chunkSize  : number;
  private stream     : StreamProcessor;
  private streamFormat: StreamFormat;
  private maxDecryptionDifficulty: Difficulty;

  private acceptUnauthenticatedHeader: boolean;

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
    this.streamFormat = opt.streamFormat ?? 'authenticated-v1';
    this.maxDecryptionDifficulty = opt.maxDecryptionDifficulty ?? 'high';

    this.difficulty     = opt.difficulty   ?? 'middle';
    this.saltStrength   = opt.saltStrength ?? 'high';
    this.acceptUnauthenticatedHeader = opt.acceptUnauthenticatedHeader ?? false;

    this.log = createLogger(opt.verbose ?? 0, opt.logger);
  }

  // ════════════════════════════════════════════════════════════════════════
  //  PUBLIC  - Informational helpers
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
    } catch (err) {
      // A structural mismatch means "not a Cryptit container" = false.
      // Anything else (e.g. an unexpected internal/runtime fault) is a real
      // problem and must surface rather than be masked as `false`.
      if (
        err instanceof InvalidHeaderError ||
        err instanceof HeaderDecodeError  ||
        err instanceof DecodingError      ||
        err instanceof SchemeError
      ) {
        return false;
      }
      throw err;
    }
  }

  /**
   * Decode the Cryptit header and return readable metadata.
   * @param input - Base64 string, Uint8Array, or Blob to decode
   * @returns Object containing scheme, difficulty, salt (Base64), and salt length
   */
  static async decodeHeader(
    input: string | Uint8Array | Blob,
  ): Promise<{ scheme: number; difficulty: Difficulty; salt: string; saltBytes: Uint8Array; saltLength: number; }> {
    const hdr = await Cryptit.peekHeader(input);
    const h   = decodeHeader(hdr);
    return {
      scheme    : h.scheme,
      difficulty : h.difficulty,
      salt       : base64Encode(h.salt),
      saltBytes  : h.salt,
      saltLength : h.salt.byteLength,
    };
  } 
  
  /**
   * @deprecated Use `decodeHeader()` instead.
   */
  static async headerDecode(
    input: string | Uint8Array | Blob,
  ): Promise<{ scheme: number; difficulty: Difficulty; salt: string; saltBytes: Uint8Array; saltLength: number; }> {
    return this.decodeHeader(input);
  }

 static isRandomAccessSource(
  input: unknown
): input is RandomAccessSource {
  return (
    typeof input === "object" &&
    input !== null &&
    typeof (input as RandomAccessSource).read === "function"
  );
}

  /**
   * Inspect an encrypted payload and return either:
   *   • chunk statistics for file/stream containers
   *   • IV/nonce & auth -tag for single -block text containers
   *
   * This never decrypts - it merely parses framing bytes.
   */
  static async decodeData(
    input: string | Uint8Array | Blob | RandomAccessSource,
  ): Promise<DecodeDataResult> {
    /* normalise into a random-access reader */
    const src: RandomAccessSource = Cryptit.isRandomAccessSource(input)
    ? input
    : new ByteSource(input);
    const headSlice = await src.read(0, Math.min(256, src.length));
    const header    = await Cryptit.peekHeader(headSlice);
    const { scheme, headerLen, streamFormat } = decodeHeader(header);

    // Compute remaining payload length
    const totalLen  = src.length;
    const remain = totalLen - headerLen;
    if (remain < 0) {
      throw new InvalidHeaderError('Payload underflow');
    }
    if (remain === 0) {
      if (streamFormat === 'authenticated-v1') {
        throw new InvalidHeaderError('Authenticated stream is missing its terminator');
      }
      return {
        isChunked: true,
        format: 'legacy',
        authenticated: false,
        chunks: { chunkSize: 0, count: 0, totalPayload: 0 },
      } as const;
    }

    if (streamFormat === 'authenticated-v1') {
      const desc = SchemeRegistry.get(scheme);
      const minFrame = desc.cipher.IV_LENGTH + desc.cipher.TAG_LENGTH;
      let offset = headerLen;
      let count = 0;
      let total = 0;
      let chunkSize = 0;
      let terminalSeen = false;

      while (offset < totalLen) {
        if (totalLen - offset < FRAME_HEADER_BYTES) {
          throw new InvalidHeaderError('Truncated authenticated stream record');
        }
        const record = decodeStreamRecord(await src.read(offset, FRAME_HEADER_BYTES));
        if (record.length < minFrame || record.length > MAX_CIPHER_FRAME_SIZE) {
          throw new InvalidHeaderError(`Invalid authenticated stream record length: ${record.length}`);
        }
        const recordEnd = offset + FRAME_HEADER_BYTES + record.length;
        if (recordEnd > totalLen) {
          throw new InvalidHeaderError('Truncated authenticated stream record');
        }
        if (terminalSeen) {
          throw new InvalidHeaderError('Data found after authenticated stream terminator');
        }

        if (record.terminal) {
          if (record.length !== minFrame) {
            throw new InvalidHeaderError('Invalid authenticated stream terminator length');
          }
          terminalSeen = true;
        } else {
          if (count === 0) chunkSize = record.length;
          count++;
          total += record.length;
        }
        offset = recordEnd;
      }

      if (!terminalSeen) {
        throw new InvalidHeaderError('Authenticated stream is missing its terminator');
      }
      return {
        isChunked: true,
        format: 'authenticated-v1',
        authenticated: true,
        chunks: { chunkSize, count, totalPayload: total },
      } as const;
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
        format: 'legacy',
        authenticated: false,
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
    const tagLen      = SchemeRegistry.get(scheme).cipher.TAG_LENGTH
    if (cipher.length < ivLen + tagLen) {
      throw new InvalidHeaderError('Ciphertext too short for IV & tag');
    }

    return {
      isChunked: false,
      // full encrypted payload length (including IV+cipher+tag)
      payloadLength: remain - ivLen - tagLen,
      params: {
        iv : cipher.slice(0, ivLen),
        ivLength: ivLen,
        tag: cipher.slice(cipher.length - tagLen),
        tagLength: tagLen,
      },
    } as const;
  }

  // ════════════════════════════════════════════════════════════════════════
  //  PUBLIC  - Setters / getters for run-time flexibility
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
     
      const MAX_ALLOWED_CHUNK_SIZE = MAX_PLAINTEXT_CHUNK_SIZE;
      const rawSize = bytes;
      let size: number;

      if (rawSize == null) {
        size = this.v.defaultChunkSize;
      } else {
        size = Number(rawSize);
        if (!Number.isInteger(size) || size < 1) {
          throw new ConfigError(`Invalid chunkSize: ${rawSize}. Must be a positive integer.`);
        }
        if (size > MAX_ALLOWED_CHUNK_SIZE) {
          throw new ConfigError(`chunkSize cannot exceed ${MAX_ALLOWED_CHUNK_SIZE} bytes.`);
        }
      }

      // finally assign
      this.chunkSize = size;
      if (this.stream) { // Check if stream is initialized
          this.stream = new StreamProcessor(this.cipher, this.chunkSize);
      }
      return size;
  }
  /** Retrieve the current streaming chunk size. */
  getChunkSize(): number                     { return this.chunkSize; }

  /**
   * Adjust verbosity level of internal logger at runtime.
   * @param level - Logger verbosity (0-4)
   */
  setVerbose(level: Verbosity): void         { this.log.level = level; }
  /** Get the current logger verbosity setting. */
  getVerbose(): Verbosity                    { return this.log.level; }

  // ════════════════════════════════════════════════════════════════════════
  //  TEXT convenience
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Encrypt text/bytes into a self-describing container.
   *
   * @param plain - Plaintext as a string, `Uint8Array`, or `ConvertibleInput`.
   *   NOTE: when a `Uint8Array` (or `ConvertibleInput`) is supplied, its backing
   *   buffer is **zeroized in place** once encryption completes as a
   *   defence-in-depth measure. Pass a copy (e.g. `bytes.slice()`) if you still
   *   need the original plaintext afterwards.
   * @param pass - Passphrase for key derivation (must not be `null`).
   * @returns ConvertibleOutput over the container bytes (header + ciphertext).
   * @throws EncryptionError on failure (original cause is chained).
   */
  async encryptText(
    plain: string | Uint8Array | ConvertibleInput,
    pass: string | null,
  ): Promise<ConvertibleOutput> {

    if (pass === null) throw new EncryptionError("Password can't be null");
 
    const secret = { value: pass };
    const desc = this.v;
    const difficulty = this.difficulty;
    const saltStrength = this.saltStrength;
    const engine = EngineManager.getEngine(this.provider, desc.id);
    let inp: ConvertibleInput | null = null;

    try {
      if (pass === '') this.log.log(0, 'Empty passphrase provided to encryptText');
      this.log.log(1, `Start text encryption, scheme: ${desc.id}`);

      // Normalize input once; we’ll wipe after use
      inp = ConvertibleInput.from(plain);
      const plainBytes = inp.toUint8Array();

      this.log.log(2, 'Deriving key for text encryption');
      const salt = this.provider.getRandomValues(
        new Uint8Array(desc.saltLengths[saltStrength]),
      );
      await EngineManager.deriveKey(engine, secret, salt, difficulty);

      this.log.log(3, `Salt generated: ${base64Encode(salt)}, KDF difficulty: ${difficulty}`);
      this.log.log(3, 'Encoding header');

      const header = encodeHeader(desc.id, difficulty, saltStrength, salt, engine.cipher);

      engine.cipher.setPaddingScheme(new Magic48VerCrc8Padding());
      engine.cipher.setPaddingAlign(8);
      engine.cipher.setPaddingAADMode('require');

      this.log.log(2, 'Encrypting text data');
      const cipher = await engine.cipher.encryptChunk(plainBytes);

      // Return a convertible output over the raw container bytes (header + cipher)
      const container = concat(header, cipher);
      this.log.log(1, 'Encryption finished');
      return new ConvertibleOutput(container);

    } catch (err) {
      throw new EncryptionError(
        err instanceof Error ? err.message : String(err),
        { cause: err },
      );
    } finally {
      engine.cipher.zeroKey();
      zeroizeString(secret);
      pass = null;
      try { inp?.clear(); } catch {}
    }
  }

  /**
   * Decrypt a ciphertext container and return a flexible output wrapper.
   * @param data - Base64 string, Uint8Array, or ConvertibleInput of (header + ciphertext)
   * @param pass - passphrase (warning logged if empty)
   * @returns ConvertibleOutput over plaintext bytes (.text for UTF-8)
   * @throws DecryptionError on failure
   */
  async decryptText(
    data: string | Uint8Array | ConvertibleInput,
    pass: string | null,
  ): Promise<ConvertibleOutput> {
    
    if (pass === null) throw new DecryptionError("Password can't be null");
 
    const secret = { value: pass };
    let engine: Engine | null = null;

    try {
      if (pass === '') this.log.log(0, 'Empty passphrase provided to decryptText');
      this.log.log(1, `Start text decryption, Version ${this.getScheme()}`);

      // Normalize ciphertext container to bytes
      let container: Uint8Array;
      if (typeof data === 'string') {
        this.log.log(3, 'Decoding Base64 ciphertext');
        container = base64Decode(data);
      } else if (data instanceof Uint8Array) {
        container = data;
      } else if (data instanceof ConvertibleInput) {
        container = data.toUint8Array();
      } else {
        throw new DecodingError('Unsupported ciphertext input type');
      }

      this.log.log(3, 'Start header decoding');
      const hdr = decodeHeader(container);

      this.log.log(3, 'Selecting decryption engine');
      engine = EngineManager.getEngine(this.provider, hdr.scheme);

      this.log.log(2, `Deriving key via engine for scheme: ${hdr.scheme}`);
      this.log.log(3, `Salt use: ${base64Encode(hdr.salt)}, KDF difficulty: ${hdr.difficulty}`);
      this.assertDecryptionDifficulty(hdr.difficulty);

      try {
        await EngineManager.deriveKey(engine, secret, hdr.salt, hdr.difficulty);
      } finally {
        zeroizeString(secret);
        pass = null;
      }

      engine.cipher.setPaddingScheme(new Magic48VerCrc8Padding());
      engine.cipher.setPaddingAlign(8);
      engine.cipher.setPaddingAADMode('require');
      engine.cipher.setLegacyAADFallback({ enabled: true, policy: 'auto', tryEmptyAAD: this.acceptUnauthenticatedHeader ? true : false });

      this.log.log(2, 'Decrypting text data');
      decodeHeader(container, engine.cipher); // bind AAD on actual cipher
      const plainBytes = await engine.cipher.decryptChunk(
        container.slice(hdr.headerLen),
      );
      // if input was a ConvertibleInput, wipe it
      if (data instanceof ConvertibleInput) {
        try { data.clear(); } catch {}
      }

      this.log.log(1, 'Decryption finished');
      return new ConvertibleOutput(plainBytes);

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
        { cause: err },
      );
    } finally {
      engine?.cipher.zeroKey();
      zeroizeString(secret);
      pass = null;
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
  async encryptFile(file: Blob, pass: string | null): Promise<Blob> {
    
    if (pass === null) throw new EncryptionError("Password can't be null");
 
    const secret = { value: pass };
    const desc = this.v;
    const difficulty = this.difficulty;
    const saltStrength = this.saltStrength;
    const chunkSize = this.chunkSize;
    const streamFormat = this.streamFormat;
    const engine = EngineManager.getEngine(this.provider, desc.id);
    try {

      if (file.size === 0 && streamFormat === 'legacy') {
        const salt = this.provider.getRandomValues(
          new Uint8Array(desc.saltLengths[saltStrength]),
        );
        await EngineManager.deriveKey(engine, secret, salt, difficulty);

        const header = encodeHeader(
          desc.id,
          difficulty,
          saltStrength,
          salt,
        );
        /* nothing to encrypt ⇒ header alone is a valid container */
        return new Blob([header as BufferSource], { type: 'application/octet-stream' });
      }
      this.log.log(2, 'Deriving key for file encryption');
      const salt = this.provider.getRandomValues(
        new Uint8Array(desc.saltLengths[saltStrength]),
      );
      await EngineManager.deriveKey(engine, secret, salt, difficulty);

      const header = encodeHeader(
        desc.id,
        difficulty,
        saltStrength,
        salt,
        engine.cipher,
        streamFormat,
      );

      engine.cipher.setPaddingAADMode('forbid');
      const stream = new StreamProcessor(engine.cipher, chunkSize);

      const cipher = await stream.collect(
        file.stream() as ReadableStream<Uint8Array>,
        new EncryptTransform(engine.cipher, chunkSize, {
          format: streamFormat,
          header,
        }).toTransformStream(),
        header,
      );

      return new Blob([cipher as BufferSource], { type: 'application/octet-stream' });

    } catch (err) {
      throw new EncryptionError(
        err instanceof Error ? err.message : String(err),
        { cause: err },
      );
    } finally {
      engine.cipher.zeroKey();
      zeroizeString(secret);
      pass = null;
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
  async decryptFile(file: Blob, pass: string | null): Promise<Blob> {
    
    if (pass === null) throw new DecryptionError("Password can't be null");
 

    const secret = { value: pass };
    let engine: Engine | null = null;
    try {
      const header = await Cryptit.peekHeader(file);
      const parsed = decodeHeader(header);
      engine = EngineManager.getEngine(this.provider, parsed.scheme);
      this.assertDecryptionDifficulty(parsed.difficulty);
      

      try {
        await EngineManager.deriveKey(engine, secret, parsed.salt, parsed.difficulty);
      } finally {
        zeroizeString(secret);
        pass = null;
      }

      // ── 0-byte optimisation ────────────────────────────────────────
      if (file.size === parsed.headerLen && parsed.streamFormat === 'legacy') {
        /* container carries header only - nothing to decrypt */
        return new Blob([], { type: 'application/octet-stream' });
      }

      this.log.log(2, 'Decrypting file data');
      const streamProc = new StreamProcessor(engine.cipher, engine.chunkSize);
      // again for correc tdata
      decodeHeader(header, streamProc.getEngine());
      engine.cipher.setPaddingAADMode('forbid');
      engine.cipher.setLegacyAADFallback({
        enabled: parsed.streamFormat === 'legacy',
        policy: 'auto',
        tryEmptyAAD: parsed.streamFormat === 'legacy' && this.acceptUnauthenticatedHeader,
      });
      const plain = await streamProc.collect(
        file.slice(parsed.headerLen).stream() as ReadableStream<Uint8Array>,
        new DecryptTransform(engine.cipher, engine.chunkSize, {
          format: parsed.streamFormat,
          header,
        }).toTransformStream(),
      );

      return new Blob([plain as BufferSource], { type: 'application/octet-stream' });

    } catch (err) {
      if (err instanceof DecryptionError) throw err;
      throw new DecryptionError(
        err instanceof Error ? err.message : String(err),
        { cause: err },
      );
    } finally {
      engine?.cipher.zeroKey();
      zeroizeString(secret);
      pass = null;
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
  async createEncryptionStream(pass: string | null): Promise<EncryptStreamResult> {
    
    if (pass === null) throw new EncryptionError("Password can't be null");
 
    const secret = { value: pass };
    const desc = this.v;
    const difficulty = this.difficulty;
    const saltStrength = this.saltStrength;
    const chunkSize = this.chunkSize;
    const streamFormat = this.streamFormat;
    const engine = EngineManager.getEngine(this.provider, desc.id);

    try {
      this.log.log(2, 'Deriving key for stream encryption');
      const salt = this.provider.getRandomValues(
        new Uint8Array(desc.saltLengths[saltStrength]),
      );
      await EngineManager.deriveKey(engine, secret, salt, difficulty);

      const header = encodeHeader(
        desc.id,
        difficulty,
        saltStrength,
        salt,
        engine.cipher,
        streamFormat,
      );
      engine.cipher.setPaddingAADMode('forbid');
      const stream = new StreamProcessor(engine.cipher, chunkSize);
      const tf = stream.encryptionStream({ format: streamFormat, header });

      return { header, writable: tf.writable, readable: tf.readable };
    } catch (err) {
      engine.cipher.zeroKey();
      throw err;
    } finally {
      zeroizeString(secret);
      pass = null;
    }
  }

  /* ──────────────────────────────────────────────────────────
     Streaming decryption (auto-detect header, any scheme)
     ────────────────────────────────────────────────────────── */
  /**
   * Create a TransformStream for decrypting incoming ciphertext with header auto-detection.
   * @param pass - Passphrase for key derivation
   * @returns TransformStream encrypting Uint8Array chunks to Uint8Array plaintext chunks
   */
  async createDecryptionStream(
    pass: string | null,
  ): Promise<TransformStream<Uint8Array, Uint8Array>> {
    if (pass === null) throw new DecryptionError("Password can't be null");

    const provider = this.provider;

    const secret = { value: pass };
    let buf: Uint8Array = new Uint8Array(0);
    let downstream: TransformStream<Uint8Array, Uint8Array> | null = null;

    const MAX_HEADER_PREFIX = 64 * 1024;
    const MIN_INFO_BYTES    = 2;

    const pipeOut = async (
      readable: ReadableStream<Uint8Array>,
      ctl: TransformStreamDefaultController<Uint8Array>,
    ) => {
      const rd = readable.getReader();
      while (true) {
        const { value, done } = await rd.read();
        if (done) break;
        ctl.enqueue(value!);
      }
    };

    return new TransformStream<Uint8Array, Uint8Array>({
      transform: async (chunk, ctl) => {
        if (!downstream) {
          // --- New: only add up to MAX_HEADER_PREFIX bytes to the scan buffer.
          let tail: Uint8Array = new Uint8Array(0);
          if (chunk && chunk.byteLength) {
            const room = Math.max(0, MAX_HEADER_PREFIX - buf.byteLength);
            const head = room ? chunk.subarray(0, room) : new Uint8Array(0);
            tail       = chunk.subarray(head.byteLength);

            if (head.byteLength) {
              const nxt = new Uint8Array(buf.byteLength + head.byteLength);
              nxt.set(buf);
              nxt.set(head, buf.byteLength);
              buf = nxt;
            }
          }

          // Need at least the first 2 bytes to read "info"
          if (buf.byteLength < MIN_INFO_BYTES) return;

          // Determine required header length
          const info         = buf[1];
          const scheme       = info >> 5;
          const saltStrength = ((info >> 2) & 1) ? 'high' : 'low';

          let hdrLen = 0;
          try {
            const desc = SchemeRegistry.get(scheme);
            const sLen = desc.saltLengths[saltStrength as 'low' | 'high'];
            hdrLen     = 2 + sLen;
          } catch (e) {
            zeroizeString(secret);
            ctl.error(new HeaderDecodeError(
              e instanceof Error ? e.message : String(e),
            ));
            return;
          }

          // Not enough yet to hold the full header? keep waiting unless we've hit the cap.
          if (buf.byteLength < hdrLen) {
            if (buf.byteLength >= MAX_HEADER_PREFIX) {
              zeroizeString(secret);
              ctl.error(new InvalidHeaderError(
                `Header not found within ${MAX_HEADER_PREFIX} bytes`,
              ));
            }
            return;
          }

          // Parse header
          const headerBytes = buf.subarray(0, hdrLen);
          let parsed: ReturnType<typeof decodeHeader>;
          try {
            parsed = decodeHeader(headerBytes);
          } catch (err) {
            zeroizeString(secret);
            ctl.error(err instanceof Error ? err : new HeaderDecodeError('Invalid header'));
            return;
          }

          // Initialize engine and derive key
          const engine = EngineManager.getEngine(provider, parsed.scheme);
          try {
            this.assertDecryptionDifficulty(parsed.difficulty);
          } catch (err) {
            zeroizeString(secret);
            ctl.error(err instanceof Error ? err : new DecryptionError('KDF policy rejected ciphertext'));
            return;
          }
          try {
            await EngineManager.deriveKey(engine, secret, parsed.salt, parsed.difficulty);
          } finally {
            zeroizeString(secret);
            pass = null;
          }

          // Bind AAD, configure cipher
          decodeHeader(headerBytes, engine.cipher);
          engine.cipher.setPaddingAADMode('forbid');
          engine.cipher.setLegacyAADFallback({
            enabled: parsed.streamFormat === 'legacy',
            policy: 'auto',
            tryEmptyAAD: parsed.streamFormat === 'legacy' && this.acceptUnauthenticatedHeader,
          });

          // Build downstream using WRITER's chunkSize from the header/engine
          downstream = new DecryptTransform(engine.cipher, engine.chunkSize, {
            format: parsed.streamFormat,
            header: headerBytes,
          }).toTransformStream();
          void pipeOut(downstream.readable, ctl).catch(err => ctl.error(err));

          // Immediately forward remainder of buffered data + any tail from this chunk
          const remainder = buf.subarray(hdrLen);
          buf = new Uint8Array(0);
          if (remainder.byteLength || tail.byteLength) {
            const w = downstream.writable.getWriter();
            if (remainder.byteLength) await w.write(remainder);
            if (tail.byteLength)      await w.write(tail);
            w.releaseLock();
          }
          return;
        }

        // Already initialized: pass through
        const writer = downstream.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
      },

      flush: async () => {
        if (!downstream) {
          zeroizeString(secret);
          throw new InvalidHeaderError('Header not found before end of stream');
        }
        const writer = downstream.writable.getWriter();
        await writer.close();
        writer.releaseLock();
      },
    });
  }

  /**
   * Generate a syntactically valid Cryptit container consisting of:
   *   <header><random-bytes>
   * The header is created from the current scheme, difficulty and salt strength,
   * so it can be decoded by `decodeHeader()` and `decodeData()`, but the payload
   * is just random noise (not decryptable).
   *
   * @param payloadLength - Number of random bytes to append after the header (>= 0).
   * @returns Uint8Array containing header + random payload.
   * @throws RangeError if payloadLength is negative or not an integer.
   */
  public generateFakeData(payloadLength: number = 0, usePadding: boolean = false): Uint8Array {
    if (!Number.isInteger(payloadLength) || payloadLength < 0) {
      throw new RangeError('payloadLength must be a non-negative integer.');
    }

    // Create a fresh salt using the configured salt strength
    const salt = this.genSalt();

    // Build a real header that matches current settings.
    // Using the text-style header (cipher) keeps the container simple and valid.
    const header = encodeHeader(
      this.v.id,
      this.difficulty,
      this.saltStrength,
      salt,
      this.cipher
    );

    // Determine tail length
    let tailLen = payloadLength;
    if (usePadding) {
      const MIN = 16;      // minimum bytes
      const BLOCK = 8;     // must be a multiple of 8
      const atLeastMin = Math.max(MIN, tailLen);
      tailLen = Math.ceil(atLeastMin / BLOCK) * BLOCK; // round up to next multiple of 8
    }

    // Append N random bytes (noise) as the payload.
    const tail =
      tailLen > 0
        ? this.provider.getRandomValues(new Uint8Array(tailLen))
        : new Uint8Array(0);

    // <header><random>
    return concat(header, tail);
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
        { cause: err },
      );
    }
  }

  /** Generate a secure random salt according to configured length. */
  private genSalt<S extends SaltStrength>(strength: S = this.saltStrength as S): Uint8Array {
    const len = this.v.saltLengths[strength];
    return this.provider.getRandomValues(new Uint8Array(len));
  }

  private assertDecryptionDifficulty(difficulty: Difficulty): void {
    const rank: Record<Difficulty, number> = { low: 0, middle: 1, high: 2 };
    if (rank[difficulty] > rank[this.maxDecryptionDifficulty]) {
      throw new DecryptionError(
        `Ciphertext KDF difficulty '${difficulty}' exceeds configured maximum '${this.maxDecryptionDifficulty}'`,
      );
    }
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

  private static async peekHeader(input: string | Uint8Array | Blob): Promise<Uint8Array> {
    const buf = await this.readAsUint8(input);
    if (buf.length < 2) throw new InvalidHeaderError('Input too short');

    const { headerLen } = decodeHeader(buf.length >= 32 ? buf : buf.slice());

    if (buf.length < headerLen) throw new InvalidHeaderError('Incomplete header');
    return buf.slice(0, headerLen);
  }

  private static async readAsUint8(input: string | Uint8Array | Blob): Promise<Uint8Array> {
    if (typeof input === 'string') return base64Decode(input);
    if (input instanceof Uint8Array) return input;
    if (input instanceof Blob) {
      const need = Math.max(32, Math.min(256, input.size));
      const slice = input.slice(0, need);
      return new Uint8Array(await slice.arrayBuffer());
    }
    throw new HeaderDecodeError('Unsupported input type');
  }
}
