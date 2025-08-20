export declare class CryptitError extends Error {
    constructor(message: string);
}
export declare class InvalidHeaderError extends CryptitError {
}
export declare class DecodingError extends CryptitError {
}
export declare class EncodingError extends CryptitError {
}
export declare class SchemeError extends CryptitError {
}
export declare class HeaderDecodeError extends CryptitError {
}
export declare class KeyDerivationError extends CryptitError {
}
export declare class EncryptionError extends CryptitError {
}
export declare class DecryptionError extends CryptitError {
}
export declare class FilesystemError extends CryptitError {
}
