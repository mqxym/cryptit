import { CryptoProvider } from '../../../providers/CryptoProvider.js';
import { BaseAEADWithPadAAD } from '../base/BaseAEADWithPadAAD.js';
import type { PaddingAwareEncryptionAlgorithm } from 'packages/core/src/types/index.js';
/**
 * AES-GCM encryption with padding policy binding via {@link BaseAEADWithPadAAD}.
 *
 * ## Framing
 * - Output ciphertext is framed as: `[ IV(12) | ciphertext || tag(16) ]`.
 * - IV is generated per-call via the provided {@link CryptoProvider.getRandomValues}.
 *
 * ## AAD and policy
 * - This subclass relies on the base class to compose the final AAD as
 *   `headerAAD || padAAD` and to enforce the padding policy (`require | forbid | auto`)
 *   after decryption.
 * - The `padAAD` fragment (see base class docs) cryptographically binds the
 *   "is padding expected?" decision into the AEAD.
 *
 * ## Zeroization
 * - Plaintext zeroization occurs in {@link BaseAEADWithPadAAD.encryptChunk}, not here.
 *
 * @remarks
 * Interoperates with WebCrypto’s `AES-GCM`. Keys are held as non-extractable
 * {@link CryptoKey} objects in this class by default.
 */
export declare class AESGCM extends BaseAEADWithPadAAD implements PaddingAwareEncryptionAlgorithm {
    /** AES-GCM nonce/IV length in bytes. */
    static readonly IV_LENGTH: number;
    /** AES-GCM tag length in bytes. */
    static readonly TAG_LENGTH: number;
    /** Instance IV length (exposed for interface parity). */
    readonly IV_LENGTH: number;
    /** Instance tag length (exposed for interface parity). */
    readonly TAG_LENGTH: number;
    /**
     * Current WebCrypto key. When `null`, the instance cannot encrypt/decrypt.
     * @internal
     */
    private key;
    /**
     * Construct an AES-GCM instance backed by the given crypto provider.
     * @param p - Platform crypto provider (WebCrypto subtle + CSPRNG).
     */
    constructor(p: CryptoProvider);
    /**
     * Set the WebCrypto key used for AES-GCM operations.
     *
     * @param k - A {@link CryptoKey} for `AES-GCM` with usages `encrypt` and `decrypt`.
     * @returns Resolves once the key is associated with the instance.
     *
     * @remarks
     * - The key is stored as-is (no re-wrapping).
     * - Passing a key with insufficient usages will cause runtime errors on use.
     */
    setKey(k: CryptoKey): Promise<void>;
    /**
     * Zeroize the in-memory key handle and make the instance unusable until
     * {@link setKey} is called again.
     *
     * @remarks
     * WebCrypto keys are non-extractable by default; this simply drops the handle.
     */
    zeroKey(): void;
    /**
     * **Subclass hook:** Perform AES-GCM encryption with the supplied AAD.
     *
     * @param toEncrypt - Plaintext (may already include a padding trailer; see base).
     * @param aad - AAD produced by the base (`headerAAD || padAAD`).
     * @returns Ciphertext framed as `[ IV(12) | ciphertext || tag(16) ]`.
     *
     * @remarks
     * - IV is generated fresh using {@link CryptoProvider.getRandomValues}.
     * - `additionalData` is always supplied and must match on decrypt for auth to succeed.
     */
    protected encryptWithAAD(toEncrypt: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
    /**
     * **Subclass hook:** Perform AES-GCM decryption with the supplied AAD.
     *
     * @param data - Ciphertext framed as `[ IV(12) | ciphertext || tag(16) ]`.
     * @param aad  - AAD that must exactly match what was used during encryption.
     * @returns The recovered plaintext on success (padding policy enforced in base).
     * @throws {DecryptionError}
     *  - If the frame is too short,
     *  - If AEAD authentication fails (AAD mismatch, wrong key/IV/tag),
     *  - Or if WebCrypto rejects the parameters.
     */
    protected decryptWithAAD(data: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
    /**
     * Ensure a key is present; throw otherwise.
     * @returns The current {@link CryptoKey}.
     * @throws {Error} If no key has been set.
     * @internal
     */
    private requireKey;
}
