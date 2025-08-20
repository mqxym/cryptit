/**
 * Normalizes user input (string or Uint8Array) to bytes.
 * You can clear() it to securely wipe the underlying memory.
 */
export declare class ConvertibleInput {
    private bytes;
    private destroyed;
    static from(input: string | Uint8Array | ConvertibleInput): ConvertibleInput;
    constructor(bytes: Uint8Array);
    toUint8Array(): Uint8Array;
    clear(): void;
}
/**
 * Wraps bytes and exposes multiple views, with secure wiping via clear().
 * String(result) yields Base64 for convenience.
 */
export declare class ConvertibleOutput {
    private bytes;
    private destroyed;
    constructor(bytes: Uint8Array);
    /** Raw bytes view (do NOT mutate). */
    get uint8array(): Uint8Array;
    /** Base64 view of the underlying bytes. */
    get base64(): string;
    /** Hex view of the underlying bytes. */
    get hex(): string;
    /** UTF-8 decoded string (useful for decrypted text). */
    get text(): string;
    /** Securely zero the buffer. */
    clear(): void;
    /** For backwards ergonomics: String(output) -> Base64 */
    toString(): string;
}
