import { CryptoProvider } from '../../../providers/CryptoProvider.js';
import { EncryptionAlgorithm } from '../../../types/index.js';
export declare class XChaCha20Poly1305 implements EncryptionAlgorithm {
    private readonly p;
    static readonly IV_LENGTH: number;
    static readonly TAG_LENGTH: number;
    readonly IV_LENGTH: number;
    readonly TAG_LENGTH: number;
    private key;
    private aad;
    constructor(p: CryptoProvider);
    /**
     * Export the raw key material for use with @noble/ciphers
     */
    setKey(k: CryptoKey): Promise<void>;
    /**
     * Encrypts a chunk with XChaCha20-Poly1305:
     * - Generates a 24-byte nonce
     * - Prepends nonce to ciphertext || tag
     * - Uses AAD if set (omitted when empty)
     */
    encryptChunk(plain: Uint8Array): Promise<Uint8Array>;
    /**
     * Decrypts a chunk with XChaCha20-Poly1305:
     * - Extracts nonce (first 24 bytes)
     * - Decrypts ciphertext || tag
     * - Uses the same AAD rule (omit when empty)
     * - Throws on authentication failure
     */
    decryptChunk(data: Uint8Array): Promise<Uint8Array>;
    zeroKey(): void;
    setAAD(aadData: Uint8Array): void;
}
