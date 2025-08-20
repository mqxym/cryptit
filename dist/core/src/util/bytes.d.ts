export declare function concat(...chunks: Uint8Array[]): Uint8Array;
export declare function base64Encode(...chunks: Uint8Array[]): string;
export declare function base64Decode(b64: string): Uint8Array;
export declare function zeroizeString(ref: {
    value: string;
}): void;
