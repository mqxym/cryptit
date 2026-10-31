// packages/core/src/header/constants.ts
export const HEADER_START_BYTE = 0x01;
export const HEADER_START_BYTE_OFFSET = 0;
export const HEADER_INFO_BYTE_OFFSET = 1;
export const HEADER_SALT_OFFSET = 2;
export const HEADER_PREFIX_LENGTH = HEADER_SALT_OFFSET;
export const HEADER_MIN_SALT_LENGTH = 12;
export const HEADER_MIN_LENGTH = HEADER_PREFIX_LENGTH + HEADER_MIN_SALT_LENGTH;

// Info byte: [scheme low: 3 bits][extended info: 1][stream auth: 1][salt strength: 1][difficulty: 2].
export const HEADER_SCHEME_BIT_SHIFT = 5;
export const HEADER_SCHEME_MASK = 0xe0;
export const HEADER_SCHEME_LOW_BITS_MASK = 0x07;
export const HEADER_EXTENDED_SCHEME_BIT_SHIFT = 3;
export const HEADER_MAX_SCHEME_ID = 0x7f;
export const HEADER_HIGH_SALT_STRENGTH_BIT = 0x04;
export const HEADER_STREAM_AUTH_BIT = 0x08;
export const HEADER_RESERVED_MASK = 0x10;
export const HEADER_EXTENDED_INFO_BIT = HEADER_RESERVED_MASK;
export const HEADER_SECOND_INFO_BYTE_OFFSET = 2;
export const HEADER_EXTENDED_PREFIX_LENGTH = HEADER_PREFIX_LENGTH + 1;
// Second info byte: [reserved: 4 bits][scheme high: 4 bits].
export const HEADER_SECOND_INFO_SCHEME_MASK = 0x0f;
export const HEADER_SECOND_INFO_RESERVED_MASK = 0xf0;
export const HEADER_DIFFICULTY_MASK = 0x03;
export const HEADER_INVALID_DIFFICULTY_CODE = 0x03;