import { CryptoProvider } from '../../../providers/CryptoProvider.js';
import { BaseAEADWithPadAAD } from '../base/BaseAEADWithPadAAD.js';
import type { PaddingAwareEncryptionAlgorithm } from '../../../types/index.js';
/**
 * XChaCha20-Poly1305 encryption with padding policy binding via {@link BaseAEADWithPadAAD}.
 *
 * ## Framing
 * - Output ciphertext is framed as: `[ NONCE(24) | ciphertext || tag(16) ]`.
 * - NONCE is generated per-call via the provided {@link CryptoProvider.getRandomValues}.
 *
 * ## AAD and policy
 * - Uses the base class to compose the final AAD (`headerAAD || padAAD`) and to enforce
 *   padding policy after decryption.
 * - The bound AAD ensures decrypt will fail if either header or pad settings differ.
 *
 * ## Key handling
 * - This class accepts a WebCrypto {@link CryptoKey} via {@link setKey}, then exports
 *   its raw bytes to feed `@noble/ciphers` (which requires a raw 32-byte key).
 * - The exported raw key is stored in memory; {@link zeroKey} overwrites and discards it.
 *
 * ## Zeroization
 * - Plaintext zeroization occurs in {@link BaseAEADWithPadAAD.encryptChunk}, not here.
 */
export declare class XChaCha20Poly1305 extends BaseAEADWithPadAAD implements PaddingAwareEncryptionAlgorithm {
    /** XChaCha20-Poly1305 nonce length in bytes. */
    static readonly IV_LENGTH: number;
    /** Poly1305 tag length in bytes. */
    static readonly TAG_LENGTH: number;
    /** Instance nonce length (exposed for interface parity). */
    readonly IV_LENGTH: number;
    /** Instance tag length (exposed for interface parity). */
    readonly TAG_LENGTH: number;
    /**
     * Raw 32-byte key material for `@noble/ciphers`. When `null`, the instance
     * cannot encrypt/decrypt.
     * @internal
     */
    private key;
    /**
     * Construct an XChaCha20-Poly1305 instance backed by the given crypto provider.
     * @param p - Platform crypto provider (WebCrypto subtle + CSPRNG).
     */
    constructor(p: CryptoProvider);
    /**
     * Set the key using a WebCrypto {@link CryptoKey}.
     *
     * @param k - A WebCrypto secret key (e.g., imported/generated 256-bit secret).
     * @returns Resolves once the key is exported and stored.
     *
     * @remarks
     * - The key is **exported as raw bytes** using `subtle.exportKey('raw', k)` and kept
     *   in memory for use with `@noble/ciphers`.
     * - Ensure the provided key was created/imported with `extractable: true`.
     */
    setKey(k: CryptoKey): Promise<void>;
    /**
     * Overwrite and discard the in-memory raw key bytes.
     * Subsequent calls to encrypt/decrypt will fail until {@link setKey}.
     */
    zeroKey(): void;
    /**
     * **Subclass hook:** Perform XChaCha20-Poly1305 encryption with the supplied AAD.
     *
     * @param toEncrypt - Plaintext (may already include a padding trailer; see base).
     * @param aad - AAD produced by the base (`headerAAD || padAAD`).
     * @returns Ciphertext framed as `[ NONCE(24) | ciphertext || tag(16) ]`.
     *
     * @remarks
     * - NONCE is generated fresh using {@link CryptoProvider.getRandomValues}.
     * - The same AAD must be provided at decrypt-time or authentication will fail.
     */
    protected encryptWithAAD(toEncrypt: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
    /**
     * **Subclass hook:** Perform XChaCha20-Poly1305 decryption with the supplied AAD.
     *
     * @param data - Ciphertext framed as `[ NONCE(24) | ciphertext || tag(16) ]`.
     * @param aad  - AAD that must exactly match what was used during encryption.
     * @returns The recovered plaintext on success (padding policy enforced in base).
     * @throws {DecryptionError}
     *  - If the frame is too short,
     *  - If authentication fails (AAD mismatch, wrong key/nonce/tag),
     *  - Or if the underlying cipher rejects inputs.
     */
    protected decryptWithAAD(data: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
    /**
     * Ensure a raw key is present; throw otherwise.
     * @returns The raw 32-byte key.
     * @throws {Error} If no key has been set.
     * @internal
     */
    private requireRawKey;
}
