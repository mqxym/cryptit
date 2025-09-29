// packages/core/src/algorithms/encryption/base/BaseAEADWithPadAAD.ts
import { CryptoProvider }       from '../../../providers/CryptoProvider.js';
import { DecryptionError }      from '../../../errors/index.js';
import type { EncryptionAlgorithm } from '../../../types/index.js';
import type { PaddingScheme }   from '../../padding/magic48ver-crc8.js';

/**
 * Padding enforcement policy encoded into AAD and applied during decrypt.
 *
 * - `'require'` — The plaintext **must** carry a valid padding trailer. Encrypt will
 *   add padding; decrypt will throw if it is missing or malformed.
 * - `'forbid'`  — The plaintext **must not** carry a padding trailer. Encrypt will not
 *   add padding; decrypt will throw if a valid trailer is present.
 * - `'auto'`    — *Configuration-derived* behavior:
 *     - If a {@link PaddingScheme} is set via {@link setPaddingScheme}, behaves as `'require'`.
 *     - Otherwise behaves as `'forbid'`.
 *
 * @remarks
 * The resolved policy (after mapping `'auto'`) is encoded into the "PAD AAD" fragment,
 * binding the expectation to AEAD integrity. See {@link buildPadAAD}.
 */
export type PaddingAADMode = 'auto' | 'require' | 'forbid';

/**
 * ## BaseAEADWithPadAAD
 *
 * An abstract helper for AEAD implementations (e.g., AES-GCM, XChaCha20-Poly1305)
 * that need:
 *
 * - deterministic, versioned **PAD AAD** composition to bind "padding semantics" to
 *   the AEAD tag,
 * - consistent **policy resolution** (`require/forbid/auto`) and **enforcement**,
 * - safe **padding/unpadding** calls, and
 * - optional **legacy AAD fallback** for backward compatibility with previously
 *   written ciphertexts that did not include the PAD AAD fragment.
 *
 * Subclasses implement only cipher-specific work:
 * - key management ({@link setKey}, {@link zeroKey}),
 * - encrypt/decrypt primitives that accept an AAD
 *   ({@link encryptWithAAD}, {@link decryptWithAAD}).
 *
 * ### Security model
 * - **All padding trailers are authenticated by the surrounding AEAD**; CRCs inside the
 *   trailer (if any) are used only to reduce accidental false-positives.
 * - **Plaintext zeroization:** {@link encryptChunk} overwrites the caller-supplied
 *   plaintext buffer (and any padded copy) with zeros after use.
 * - **AAD binding:** The class appends a compact PAD AAD fragment to any header AAD
 *   configured via {@link setAAD}. Decrypt will only succeed if the AAD exactly matches.
 *
 * ### PAD AAD (version 0x01)
 * The PAD AAD fragment is:
 * ```
 *   "PAD1" (0x50 0x41 0x44 0x31) || VER(0x01) || MODE(1) || ALIGN(1)
 *   where MODE: 0x00=require, 0x01=forbid; ALIGN ∈ [1..255]
 * ```
 * The full AAD used for encryption/decryption is:
 * ```
 *   headerAAD || padAAD
 * ```
 *
 * ### Backward compatibility
 * If enabled (see {@link setLegacyAADFallback}), decrypt will retry with *legacy*
 * AADs (header-only, optionally empty) when decrypt with the composed AAD fails.
 * When a legacy AAD is used, policy enforcement defaults to `'auto'` unless
 * overridden by {@link setLegacyAADFallback}.
 */
export abstract class BaseAEADWithPadAAD implements EncryptionAlgorithm {
  /**
   * Size of the nonce/IV used by the concrete AEAD in bytes.
   * @public
   */
  public abstract readonly IV_LENGTH: number;

  /**
   * Size of the authentication tag produced by the concrete AEAD in bytes.
   * @public
   */
  public abstract readonly TAG_LENGTH: number;

  /**
   * Active padding scheme. If `null`, `'auto'` resolves to `'forbid'`.
   * @protected
   */
  protected padding: PaddingScheme | null = null;

  /**
   * Caller-provided header AAD (e.g., protocol header). Always copied on set.
   * @protected
   */
  protected headerAAD: Uint8Array = new Uint8Array(0);

  /**
   * Configured padding policy. See {@link PaddingAADMode} for semantics.
   * @protected
   * @defaultValue `'auto'`
   */
  protected padAADMode: PaddingAADMode = 'auto';

  /**
   * Declared alignment stored in PAD AAD (does not change parsing at decrypt-time).
   * Must be an integer in `[1..255]`.
   * @protected
   * @defaultValue `8`
   */
  protected padAlign: number = 8;

  // ---- Legacy AAD fallback controls ----

  /**
   * If `true`, decrypt will retry with legacy AAD(s) (header-only and/or empty)
   * when decrypt with the composed AAD fails. Use to read old ciphertexts that
   * did not include the PAD AAD fragment.
   * @protected
   * @defaultValue `true`
   */
  protected allowLegacyAADFallback = true;

  /**
   * Policy to apply **when** a legacy AAD path is taken.
   * - `'auto'`: mimic old behavior (strip trailer if present; otherwise pass-through).
   * - `'require'`: demand a valid trailer (may break some legacy material).
   * - `'forbid'`: reject if a valid trailer is present.
   * @protected
   * @defaultValue `'auto'`
   */
  protected legacyFallbackPolicy: PaddingAADMode = 'auto';

  /**
   * If `true`, one of the legacy decrypt retries will use an **empty AAD**.
   * Enable only if very old writers omitted AAD entirely.
   * @protected
   * @defaultValue `false`
   */
  protected tryEmptyAADOnLegacyFallback = false;

  /**
   * Configure legacy AAD fallback behavior used during {@link decryptChunk}.
   *
   * @param opts - Optional configuration.
   * @param opts.enabled - Enable/disable the legacy retry logic. Default: `current value` (initially `true`).
   * @param opts.policy  - Policy to enforce if a legacy AAD succeeds. Default: `'auto'`.
   * @param opts.tryEmptyAAD - Whether to also retry with empty AAD. Default: `current value` (initially `false`).
   */
  public setLegacyAADFallback(opts: {
    enabled?: boolean;
    policy?: PaddingAADMode;
    tryEmptyAAD?: boolean;
  } = {}): void {
    if (opts.enabled !== undefined) this.allowLegacyAADFallback = !!opts.enabled;
    if (opts.policy) this.legacyFallbackPolicy = opts.policy;
    if (opts.tryEmptyAAD !== undefined) this.tryEmptyAADOnLegacyFallback = !!opts.tryEmptyAAD;
  }

  // Deterministic, versioned PAD AAD marker
  /**
   * Four-byte ASCII magic `"PAD1"` used at the start of the PAD AAD fragment.
   * @internal
   */
  protected static readonly PAD_AAD_MAGIC = new Uint8Array([0x50, 0x41, 0x44, 0x31]); // "PAD1"

  /**
   * PAD AAD version byte. Increment if the PAD AAD layout changes.
   * @internal
   * @defaultValue `0x01`
   */
  protected static readonly PAD_AAD_VER   = 0x01;

  /**
   * Construct the base class with a {@link CryptoProvider}.
   * @param p - Platform crypto provider (WebCrypto subtle + CSPRNG).
   */
  constructor(protected readonly p: CryptoProvider) {}

  // ---------------- public, common API ----------------

  /**
   * Set (or clear) the padding scheme used for padding/unpadding.
   *
   * @param s - The {@link PaddingScheme} to use, or `null` to disable padding.
   *
   * @remarks
   * - When set, `'auto'` policy resolves to `'require'`. When `null`, `'auto'`
   *   resolves to `'forbid'`.
   * - The scheme’s trailer bytes are authenticated because they are part of the
   *   ciphertext payload covered by the AEAD tag.
   */
  public setPaddingScheme(s: PaddingScheme | null) { this.padding = s; }

  /**
   * Configure the high-level padding policy. See {@link PaddingAADMode}.
   * @param mode - `'auto' | 'require' | 'forbid'`
   */
  public setPaddingAADMode(mode: PaddingAADMode) { this.padAADMode = mode; }

  /**
   * Set the alignment **declared** in the PAD AAD (one-byte field).
   *
   * @param n - Alignment in `[1..255]`.
   * @throws {Error} If `n` is not an integer in range.
   *
   * @remarks
   * - This value is informational and bound into the AAD. It does not alter
   *   unpadding logic at decrypt-time (parsers validate the trailer
   *   structure and ignore align).
   */
  public setPaddingAlign(n: number) {
    if (!Number.isInteger(n) || n < 1 || n > 255) throw new Error('padAlign must be 1..255');
    this.padAlign = n | 0;
  }

  /**
   * Set the **header** AAD (caller-defined protocol header).
   * @param aadData - Header bytes; an internal copy is stored.
   *
   * @remarks
   * The final AAD used in AEAD operations is `headerAAD || padAAD`.
   */
  public setAAD(aadData: Uint8Array): void {
    this.headerAAD = aadData && aadData.byteLength
      ? new Uint8Array(aadData) // copy
      : new Uint8Array(0);
  }

  /**
   * Encrypt a plaintext chunk under the current policy and AAD configuration.
   *
   * @param plain - Caller-owned plaintext buffer. **Will be zeroed** after encryption.
   * @returns Ciphertext including nonce/IV prefix and AEAD tag (format decided by subclass).
   * @throws {Error} If `'require'` policy is in effect and no padding scheme is set.
   * @throws {Error | DecryptionError} Propagates subclass errors if they surface during encrypt.
   *
   * @remarks
   * - If the resolved policy is `'require'`, the method pads the plaintext
   *   using {@link PaddingScheme.pad} before calling {@link encryptWithAAD}.
   * - After encryption, this method zeroes `plain` and the padded copy (if any).
   */
  public async encryptChunk(plain: Uint8Array): Promise<Uint8Array> {
    const effective = this.resolveMode();
    let toEncrypt = plain;

    if (effective === 'require') {
      if (!this.padding) throw new Error('Padding required but no scheme set');
      const rng = (n: number) => this.p.getRandomValues(new Uint8Array(n));
      toEncrypt = this.padding.pad(plain, rng, this.padAlign);
    }

    const aad = this.composeAAD(effective);
    const out = await this.encryptWithAAD(toEncrypt, aad);

    // Zeroize plaintext (and padded variant if different)
    plain.fill(0);
    if (toEncrypt !== plain) toEncrypt.fill(0);

    return out;
  }

  /**
   * Decrypt a ciphertext chunk, enforcing the configured policy and (optionally)
   * retrying legacy AADs for backward compatibility.
   *
   * @param data - Ciphertext buffer produced by the matching subclass (nonce/IV prefix + ct||tag).
   * @returns The recovered plaintext (unpadded if policy and trailer permit).
   * @throws {DecryptionError}
   *  - If AEAD authentication fails for all eligible AADs,
   *  - If `'require'` policy is selected and no trailer is present,
   *  - If `'forbid'` policy is selected and a valid trailer is present,
   *  - If `'require'` policy is selected but no padding scheme is configured.
   *
   * @remarks
   * 1. The method first tries with **composed AAD** (`headerAAD || padAAD`).
   * 2. If that fails and {@link allowLegacyAADFallback} is `true`, it retries with:
   *    - header-only AAD (if present),
   *    - and, if {@link tryEmptyAADOnLegacyFallback} is `true`, **empty AAD**.
   * 3. When a legacy AAD succeeds, the enforcement policy is taken from
   *    {@link legacyFallbackPolicy} (default `'auto'`).
   */
  public async decryptChunk(data: Uint8Array): Promise<Uint8Array> {
    const effective = this.resolveMode();
    const newAAD = this.composeAAD(effective);

    // 1) Try new-format AAD first
    try {
      const plain = await this.decryptWithAAD(data, newAAD);
      return this.enforcePolicyAfterDecrypt(plain, effective);
    } catch (primaryErr) {
      // 2) Optionally retry legacy AADs
      if (!this.allowLegacyAADFallback) throw primaryErr;

      const candidates: Uint8Array[] = [];
      if (this.headerAAD.length) candidates.push(this.headerAAD);
      if (this.tryEmptyAADOnLegacyFallback) candidates.push(new Uint8Array(0));

      let lastErr: unknown = primaryErr;
      for (const legacyAAD of candidates) {
        try {
          const plainLegacy = await this.decryptWithAAD(data, legacyAAD);
          const legacyMode =
            this.legacyFallbackPolicy === 'auto'
              ? 'auto'
              : (this.legacyFallbackPolicy as Exclude<PaddingAADMode, 'auto'>);
          return this.enforcePolicyAfterDecrypt(plainLegacy, legacyMode);
        } catch (e) {
          lastErr = e;
        }
      }
      throw lastErr;
    }
  }

  /**
   * Apply post-decrypt padding policy to the recovered plaintext.
   *
   * @param plain - AEAD-authenticated plaintext (may or may not contain a trailer).
   * @param mode  - Policy to enforce (`'require' | 'forbid' | 'auto'`).
   * @returns Either the original plaintext (no trailer stripped) or the trailer-stripped view.
   * @throws {DecryptionError} When policy requirements are not met.
   *
   * @remarks
   * - `'auto'`: strip trailer if present; otherwise pass through.
   * - When no {@link PaddingScheme} is configured, only `'require'` can fail.
   */
  protected enforcePolicyAfterDecrypt(
    plain: Uint8Array,
    mode: PaddingAADMode
  ): Uint8Array {
    // No padding scheme configured? Only 'require' needs to error.
    if (!this.padding) {
      if (mode === 'require') throw new DecryptionError('Expected padding but no scheme configured');
      return plain;
    }

    const { used, plain: unpadded } = this.padding.tryUnpad(plain);

    if (mode === 'require') {
      if (!used) throw new DecryptionError('Expected padding trailer not found');
      return new Uint8Array(unpadded);
    }
    if (mode === 'forbid') {
      if (used) throw new DecryptionError('Padding forbidden by policy');
      return plain;
    }

    // 'auto' (legacy behavior): strip if present, else pass through
    return used ? new Uint8Array(unpadded) : plain;
  }

  // ---------------- abstract hooks for subclasses ----------------

  /**
   * Import or set the cipher key. Subclasses decide the key format (e.g., CryptoKey
   * for WebCrypto algorithms, exported raw key for libraries that require it).
   * @param k - A {@link CryptoKey} handle provided by the caller.
   */
  public abstract setKey(k: CryptoKey): Promise<void>;

  /**
   * Zeroize in-memory key material and render the instance unusable until
   * {@link setKey} is called again.
   */
  public abstract zeroKey(): void;

  /**
   * **Subclass hook:** perform AEAD encryption with the provided AAD.
   *
   * @param toEncrypt - Plaintext (may already include padding trailer).
   * @param aad - Additional authenticated data to bind (headerAAD || padAAD).
   * @returns Ciphertext in the subclass’s framing (e.g., `[IV | ct||tag]`).
   */
  protected abstract encryptWithAAD(toEncrypt: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;

  /**
   * **Subclass hook:** perform AEAD decryption with the provided AAD.
   *
   * @param data - Ciphertext in the subclass’s framing.
   * @param aad  - Additional authenticated data used at encryption-time.
   * @returns The recovered plaintext on success.
   * @throws {DecryptionError} On authentication failure or framing errors.
   */
  protected abstract decryptWithAAD(data: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;

  // ---------------- internals ----------------

  /**
   * Resolve `'auto'` into a concrete policy using the presence of a padding scheme:
   * - if {@link padding} is set → `'require'`
   * - otherwise → `'forbid'`
   *
   * @returns The concrete policy used for this operation.
   */
  protected resolveMode(): Exclude<PaddingAADMode, 'auto'> {
    if (this.padAADMode === 'auto') {
      return this.padding ? 'require' : 'forbid';
    }
    return this.padAADMode;
  }

  /**
   * Build the deterministic PAD AAD fragment:
   * `"PAD1" || VER(0x01) || MODE(1) || ALIGN(1)`
   *
   * @param mode - Concrete policy (`'require' | 'forbid'`).
   * @returns A new {@link Uint8Array} containing the PAD AAD bytes.
   * @internal
   */
  protected buildPadAAD(mode: Exclude<PaddingAADMode, 'auto'>): Uint8Array {
    // MODE encoding: 0=require, 1=forbid
    const modeByte = (mode === 'require') ? 0x00 : 0x01;

    const out = new Uint8Array(
      BaseAEADWithPadAAD.PAD_AAD_MAGIC.length + 1 /*ver*/ + 1 /*mode*/ + 1 /*align*/
    );
    let o = 0;
    out.set(BaseAEADWithPadAAD.PAD_AAD_MAGIC, o); o += BaseAEADWithPadAAD.PAD_AAD_MAGIC.length;
    out[o++] = BaseAEADWithPadAAD.PAD_AAD_VER & 0xff;
    out[o++] = modeByte;
    out[o++] = this.padAlign & 0xff;
    return out;
  }

  /**
   * Compose the final AAD as `headerAAD || padAAD`.
   *
   * @param mode - Concrete policy (`'require' | 'forbid'`).
   * @returns A new {@link Uint8Array} with the concatenated AAD.
   * @internal
   */
  protected composeAAD(mode: Exclude<PaddingAADMode, 'auto'>): Uint8Array {
    const padAAD = this.buildPadAAD(mode);
    if (!this.headerAAD.length) return padAAD;
    const out = new Uint8Array(this.headerAAD.length + padAAD.length);
    out.set(this.headerAAD, 0);
    out.set(padAAD, this.headerAAD.length);
    return out;
  }
}