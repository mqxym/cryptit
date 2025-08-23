import './config/defaults.js';
import type { CryptoProvider } from './providers/CryptoProvider.js';
import { Difficulty, SaltStrength } from './config/defaults.js';
import { ConvertibleInput, ConvertibleOutput } from './util/Convertible.js';
import { type Verbosity } from './util/logger.js';
import { RandomAccessSource } from './util/ByteSource.js';
/**
 * Result of creating an encryption stream: header and paired streams.
 */
export interface EncryptStreamResult {
    /** Binary header for decryption initialization */
    header: Uint8Array;
    /** Writable stream to feed plaintext data */
    writable: WritableStream<Uint8Array>;
    /** Readable stream emitting ciphertext data */
    readable: ReadableStream<Uint8Array>;
}
/**
 * Options for configuring Cryptit instance behavior.
 */
export interface CryptitOptions {
    /** Version identifier (0…7) to use; defaults to registry's current scheme */
    scheme?: number;
    /** Salt strength: 'low' | 'middle' | 'high'; defaults to descriptor's default */
    saltStrength?: SaltStrength;
    /** Key derivation difficulty; defaults to descriptor's default */
    difficulty?: Difficulty;
    /** Chunk size for streaming operations; defaults to descriptor's default */
    chunkSize?: number;
    /** Verbosity level 0-4 for logging (0 = errors only) */
    verbose?: Verbosity;
    /** Optional custom logger callback (receives formatted messages) */
    logger?: (msg: string) => void;
}
export type DecodeDataResult = {
    isChunked: true;
    chunks: {
        chunkSize: number;
        count: number;
        totalPayload: number;
    };
} | {
    isChunked: false;
    payloadLength: number;
    params: {
        iv: Uint8Array;
        ivLength: number;
        tag: Uint8Array;
        tagLength: number;
    };
};
/**
 * Cryptit provides high-level encryption/decryption utilities for text, blobs, and streams.
 */
export declare class Cryptit {
    private readonly provider;
    private v;
    private cipher;
    private kdf;
    private chunkSize;
    private stream;
    private difficulty;
    private saltStrength;
    private readonly engines;
    private readonly log;
    /**
     * Create a new Cryptit instance with given crypto provider and options.
     * @param provider - Underlying crypto provider for key derivation and randomness
     * @param opt - Configuration options for scheme, salts, logging, etc.
     */
    constructor(provider: CryptoProvider, opt?: CryptitOptions);
    /**
     * Check if the provided input contains a valid Cryptit header.
     * @param input - Base64 string, Uint8Array, or Blob to inspect
     * @returns True if header is valid; false otherwise
     */
    static isEncrypted(input: string | Uint8Array | Blob): Promise<boolean>;
    /**
     * Decode the Cryptit header and return readable metadata.
     * @param input - Base64 string, Uint8Array, or Blob to decode
     * @returns Object containing scheme, difficulty, salt (Base64), and salt length
     */
    static decodeHeader(input: string | Uint8Array | Blob): Promise<{
        scheme: number;
        difficulty: Difficulty;
        salt: string;
        saltBytes: Uint8Array;
        saltLength: number;
    }>;
    /**
     * @deprecated Use `decodeHeader()` instead.
     */
    static headerDecode(input: string | Uint8Array | Blob): Promise<{
        scheme: number;
        difficulty: Difficulty;
        salt: string;
        saltBytes: Uint8Array;
        saltLength: number;
    }>;
    static isRandomAccessSource(input: unknown): input is RandomAccessSource;
    /**
     * Inspect an encrypted payload and return either:
     *   • chunk statistics for file/stream containers
     *   • IV/nonce & auth -tag for single -block text containers
     *
     * This never decrypts - it merely parses framing bytes.
     */
    static decodeData(input: string | Uint8Array | Blob | RandomAccessSource): Promise<DecodeDataResult>;
    /** Set the difficulty level for subsequent operations. */
    setDifficulty(d: Difficulty): void;
    /** Get the current difficulty setting. */
    getDifficulty(): Difficulty;
    /**
     * Change the protocol scheme for future encrypt/decrypt actions.
     * @param id - Version identifier from registry
     */
    setScheme(id: number): void;
    /** Retrieve the active protocol scheme identifier. */
    getScheme(): number;
    /**
     * Override salt length (in bytes) for new operations (advanced use).
     * @param len - Custom salt length in bytes
     */
    setSaltDifficulty(d: SaltStrength): void;
    /** Get the effective salt length for the current strength. */
    getSaltDifficulty(): SaltStrength;
    /**
     * Configure chunk size (bytes) for streaming transforms.
     * @param bytes - Desired chunk size in bytes
     */
    setChunkSize(bytes: number): number;
    /** Retrieve the current streaming chunk size. */
    getChunkSize(): number;
    /**
     * Adjust verbosity level of internal logger at runtime.
     * @param level - Logger verbosity (0-4)
     */
    setVerbose(level: Verbosity): void;
    /** Get the current logger verbosity setting. */
    getVerbose(): Verbosity;
    /**
   * Encrypt plaintext and return a flexible output wrapper.
   * @param plain - string | Uint8Array | ConvertibleInput
   * @param pass  - passphrase (warning logged if empty)
   * @returns ConvertibleOutput (read via .base64 / .hex / .uint8array)
   * @throws EncryptionError on failure
   */
    encryptText(plain: string | Uint8Array | ConvertibleInput, pass: string | null): Promise<ConvertibleOutput>;
    /**
     * Decrypt a ciphertext container and return a flexible output wrapper.
     * @param data - Base64 string, Uint8Array, or ConvertibleInput of (header + ciphertext)
     * @param pass - passphrase (warning logged if empty)
     * @returns ConvertibleOutput over plaintext bytes (.text for UTF-8)
     * @throws DecryptionError on failure
     */
    decryptText(data: string | Uint8Array | ConvertibleInput, pass: string | null): Promise<ConvertibleOutput>;
    /**
     * Encrypt a Blob (file) and return a new Blob with embedded header.
     * @param file - Input Blob to encrypt
     * @param pass - Passphrase for key derivation
     * @returns Encrypted Blob (application/octet-stream)
     * @throws EncryptionError on failure
     */
    encryptFile(file: Blob, pass: string | null): Promise<Blob>;
    /**
     * Decrypt an encrypted Blob using the embedded header for parameters.
     * @param file - Encrypted Blob containing header + ciphertext
     * @param pass - Passphrase for key derivation
     * @returns Decrypted Blob (application/octet-stream)
     * @throws DecryptionError on failure or invalid header
     */
    decryptFile(file: Blob, pass: string | null): Promise<Blob>;
    /**
     * Initialize streaming encryption, returning header and transform streams.
     * @param pass - Passphrase for key derivation
     * @returns Streams and header for real-time encryption
     */
    createEncryptionStream(pass: string | null): Promise<EncryptStreamResult>;
    /**
     * Create a TransformStream for decrypting incoming ciphertext with header auto-detection.
     * @param pass - Passphrase for key derivation
     * @returns TransformStream encrypting Uint8Array chunks to Uint8Array plaintext chunks
     */
    createDecryptionStream(pass: string | null): Promise<TransformStream<Uint8Array, Uint8Array>>;
    /**
     * Derive cryptographic key from passphrase and salt using configured KDF.
     * @param pass - Passphrase to derive key from
     * @param salt - Random salt value
     * @param diff - Difficulty level for KDF (optional)
     * @throws KeyDerivationError on KDF failure
     */
    private deriveKey;
    /** Generate a secure random salt according to configured length. */
    private genSalt;
    /**
     * Read minimal bytes to extract and validate Cryptit header.
     * @param input - Base64 string, Uint8Array, or Blob containing header
     * @returns Uint8Array slice of the header bytes
     * @throws HeaderDecodeError or InvalidHeaderError on invalid input
     */
    private static peekHeader;
    private static readAsUint8;
}
