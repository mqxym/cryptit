/* ------------------------------------------------------------------
   Centralised error hierarchy - keeps stack traces out of user-space
   ------------------------------------------------------------------ */

export class CryptitError extends Error {
  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);   // fix instanceof
    this.name  = new.target.name;
    this.stack = undefined;                              // no stack traces
  }
}

export class InvalidHeaderError   extends CryptitError {}
export class DecodingError        extends CryptitError {}
export class EncodingError        extends CryptitError {}
export class SchemeError          extends CryptitError {}
export class HeaderDecodeError    extends CryptitError {}
export class KeyDerivationError   extends CryptitError {}
export class EncryptionError      extends CryptitError {}
export class DecryptionError      extends CryptitError {}
export class FilesystemError      extends CryptitError {}