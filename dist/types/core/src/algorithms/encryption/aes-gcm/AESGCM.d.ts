import { CryptoProvider } from '../../../providers/CryptoProvider.js';
import { BaseAEADWithPadAAD } from '../base/BaseAEADWithPadAAD.js';
import type { PaddingAwareEncryptionAlgorithm } from '../../../types/index.js';
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
    static readonly IV_LENGTH: number;
    static readonly TAG_LENGTH: number;
    readonly IV_LENGTH: number;
    readonly TAG_LENGTH: number;
    private key;
    constructor(p: CryptoProvider);
    setKey(k: CryptoKey): Promise<void>;
    zeroKey(): void;
    protected encryptWithAAD(toEncrypt: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
    protected decryptWithAAD(data: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
    private requireKey;
}
