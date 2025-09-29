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
  /** Enable legacy file and text decryption version < 1.0.0 */
  acceptUnauthenticatedHeader?    : boolean;
  /** Verbosity level 0-4 for logging (0 = errors only) */
  verbose?      : Verbosity;
  /** Optional custom logger callback (receives formatted messages) */
  logger?       : (msg: string) => void;
}

export type DecodeDataResult =
  | { isChunked: true;  chunks: { chunkSize: number; count: number; totalPayload: number } }
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
    } catch {
      return false;
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
     
      const MAX_ALLOWED_CHUNK_SIZE = 128 * 1024 * 1024; // 128 MiB
      const rawSize = bytes;
      let size: number;

      if (rawSize == null) {
        size = this.v.defaultChunkSize;
      } else {
        size = Number(rawSize);
        if (!Number.isInteger(size) || size < 1) {
          throw new Error(`Invalid chunkSize: ${rawSize}. Must be a positive integer.`);
        }
        if (size > MAX_ALLOWED_CHUNK_SIZE) {
          throw new RangeError(`chunkSize cannot exceed ${MAX_ALLOWED_CHUNK_SIZE} bytes.`);
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
   * Encrypt plaintext and return a flexible output wrapper.
   * @param plain - string | Uint8Array | ConvertibleInput
   * @param pass  - passphrase (warning logged if empty)
   * @returns ConvertibleOutput (read via .base64 / .hex / .uint8array)
   * @throws EncryptionError on failure
   */
  async encryptText(
    plain: string | Uint8Array | ConvertibleInput,
    pass: string | null,
  ): Promise<ConvertibleOutput> {

    if (pass === null) throw new EncryptionError("Password can't be null");
 
    const secret = { value: pass };

    try {
      if (pass === '') this.log.log(0, 'Empty passphrase provided to encryptText');
      this.log.log(1, `Start text encryption, scheme: ${this.getScheme()}`);

      // Normalize input once; we’ll wipe after use
      const inp = ConvertibleInput.from(plain);
      const plainBytes = inp.toUint8Array();

      this.log.log(2, 'Deriving key for text encryption');
      const salt = this.genSalt();
      await this.deriveKey(secret, salt);

      zeroizeString(secret);
      pass = null;

      this.log.log(3, `Salt generated: ${base64Encode(salt)}, KDF difficulty: ${this.difficulty}`);
      this.log.log(3, 'Encoding header');

      const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt, this.cipher);

      this.cipher.setPaddingScheme(new Magic48VerCrc8Padding());
      this.cipher.setPaddingAlign(8);
      this.cipher.setPaddingAADMode('require');

      this.log.log(2, 'Encrypting text data');
      const cipher = await this.cipher.encryptChunk(plainBytes);
      this.cipher.zeroKey();

      // wipe plaintext ASAP
      try { inp.clear(); } catch {}

      // Return a convertible output over the raw container bytes (header + cipher)
      const container = concat(header, cipher);
      this.log.log(1, 'Encryption finished');
      return new ConvertibleOutput(container);

    } catch (err) {
      throw new EncryptionError(
        err instanceof Error ? err.message : String(err),
      );
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
    
    if (pass === null) throw new EncryptionError("Password can't be null");
 
    const secret = { value: pass };

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
      const engine = EngineManager.getEngine(this.provider, hdr.scheme);

      this.log.log(2, `Deriving key via engine for scheme: ${hdr.scheme}`);
      this.log.log(3, `Salt use: ${base64Encode(hdr.salt)}, KDF difficulty: ${hdr.difficulty}`);

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
      engine.cipher.zeroKey();

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
  async encryptFile(file: Blob, pass: string | null): Promise<Blob> {
    
    if (pass === null) throw new EncryptionError("Password can't be null");
 
    const secret = { value: pass };
    try {

      if (file.size === 0) {
        const salt = this.genSalt();
        await this.deriveKey(secret, salt);

        zeroizeString(secret);
        pass = null;

        const header = encodeHeader(
          this.v.id,
          this.difficulty,
          this.saltStrength,
          salt,
        );
        /* nothing to encrypt ⇒ header alone is a valid container */
        return new Blob([header as BufferSource], { type: 'application/octet-stream' });
      }
      this.log.log(2, 'Deriving key for file encryption');
      const salt = this.genSalt();
      await this.deriveKey(secret, salt);

      zeroizeString(secret);
      pass = null;

      const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt, this.stream.getEngine());

      this.stream.getEngine().setPaddingAADMode('forbid');

      const cipher = await this.stream.collect(
        file.stream() as ReadableStream<Uint8Array>,
        new EncryptTransform(this.cipher, this.chunkSize).toTransformStream(),
        header,
      );

      return new Blob([cipher as BufferSource], { type: 'application/octet-stream' });

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
  async decryptFile(file: Blob, pass: string | null): Promise<Blob> {
    
    if (pass === null) throw new EncryptionError("Password can't be null");
 

    const secret = { value: pass };
    try {
      const header = await Cryptit.peekHeader(file);
      const parsed = decodeHeader(header);
      const engine = EngineManager.getEngine(this.provider, parsed.scheme);
      

      try {
        await EngineManager.deriveKey(engine, secret, parsed.salt, parsed.difficulty);
      } finally {
        zeroizeString(secret);
        pass = null;
      }

      // ── 0-byte optimisation ────────────────────────────────────────
      if (file.size === parsed.headerLen) {
        /* container carries header only - nothing to decrypt */
        return new Blob([], { type: 'application/octet-stream' });
      }

      this.log.log(2, 'Decrypting file data');
      const streamProc = new StreamProcessor(engine.cipher, engine.chunkSize);
      // again for correc tdata
      decodeHeader(header, streamProc.getEngine());
      engine.cipher.setPaddingAADMode('forbid');
      engine.cipher.setLegacyAADFallback({ enabled: true, policy: 'auto', tryEmptyAAD: this.acceptUnauthenticatedHeader ? true : false });
      const plain = await streamProc.collect(
        file.slice(parsed.headerLen).stream() as ReadableStream<Uint8Array>,
        new DecryptTransform(engine.cipher, engine.chunkSize).toTransformStream(),
      );

      return new Blob([plain as BufferSource], { type: 'application/octet-stream' });

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
  async createEncryptionStream(pass: string | null): Promise<EncryptStreamResult> {
    
    if (pass === null) throw new EncryptionError("Password can't be null");
 
    const secret = { value: pass };

    this.log.log(2, 'Deriving key for stream encryption');
    const salt = this.genSalt();
    await this.deriveKey(secret, salt);

    zeroizeString(secret);
    pass = null;

    const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt, this.stream.getEngine());
    this.stream.getEngine().setPaddingAADMode('forbid');
    const tf     = this.stream.encryptionStream();

    return { header, writable: tf.writable, readable: tf.readable };
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
    if (pass === null) throw new EncryptionError("Password can't be null");

    // Capture only what you need from `this`
    const provider = this.provider;

    const secret = { value: pass };
    let buf: Uint8Array = new Uint8Array(0);
    let downstream: TransformStream<Uint8Array, Uint8Array> | null = null;

    const MAX_HEADER_PREFIX = 64 * 1024;
    const MIN_HEADER_BYTES  = 2 + 12;

    // Arrow => no `this` surprises
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
          if (chunk && chunk.byteLength) {
            if (buf.byteLength + chunk.byteLength > MAX_HEADER_PREFIX) {
              zeroizeString(secret);
              ctl.error(new InvalidHeaderError(
                `Header not found within ${MAX_HEADER_PREFIX} bytes`,
              ));
              return;
            }
            buf = concat(buf, chunk);
          }

          if (buf.byteLength < MIN_HEADER_BYTES) return;

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

          if (buf.byteLength < hdrLen) return;

          const headerBytes = buf.subarray(0, hdrLen);
          let parsed: ReturnType<typeof decodeHeader>;
          try {
            parsed = decodeHeader(headerBytes);
          } catch (err) {
            zeroizeString(secret);
            ctl.error(err instanceof Error ? err : new HeaderDecodeError('Invalid header'));
            return;
          }

          const engine = EngineManager.getEngine(provider, parsed.scheme);
          try {
            await EngineManager.deriveKey(engine, secret, parsed.salt, parsed.difficulty);
          } finally {
            zeroizeString(secret);
            pass = null;
          }

          decodeHeader(headerBytes, engine.cipher); // Assign authenticated data to engine.cipher

          engine.cipher.setPaddingAADMode('forbid');
          engine.cipher.setLegacyAADFallback({ enabled: true, policy: 'auto', tryEmptyAAD: this.acceptUnauthenticatedHeader ? true : false });

          downstream = new DecryptTransform(engine.cipher, engine.chunkSize).toTransformStream();
          void pipeOut(downstream.readable, ctl).catch(err => ctl.error(err));

          const remainder = buf.subarray(hdrLen);
          buf = new Uint8Array(0);
          if (remainder.byteLength) {
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
      );
    }
  }

  /** Generate a secure random salt according to configured length. */
  private genSalt<S extends SaltStrength>(strength: S = this.saltStrength as S): Uint8Array {
    const len = this.v.saltLengths[strength];
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
    if (typeof input === 'string') return base64Decode(input);
    if (input instanceof Blob) {
      const slice = input.slice(0, 64);
      return new Uint8Array(await slice.arrayBuffer());
    }
    return input;
  }
}
