/**
 * Stack-trace redaction is opt-in via the `CRYPTIT_DISABLE_STACKTRACE`
 * environment variable (truthy → redact). By default stack traces are
 * preserved to aid debugging. The lookup is defensive so it stays safe in
 * browser bundles where `process` may be undefined.
 */
function shouldRedactStack(): boolean {
  try {
    return (
      typeof process !== 'undefined' &&
      !!process.env &&
      /^(1|true|yes|on)$/i.test(process.env.CRYPTIT_DISABLE_STACKTRACE ?? '')
    );
  } catch {
    return false;
  }
}

export class CryptitError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    Object.setPrototypeOf(this, new.target.prototype);
    this.name  = new.target.name;
    if (shouldRedactStack()) this.stack = undefined;
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
export class ConfigError          extends CryptitError {}