// packages/core/src/header/decoder.ts
import {
  HEADER_DIFFICULTY_MASK,
  HEADER_EXTENDED_INFO_BIT,
  HEADER_EXTENDED_PREFIX_LENGTH,
  HEADER_EXTENDED_SCHEME_BIT_SHIFT,
  HEADER_HIGH_SALT_STRENGTH_BIT,
  HEADER_INFO_BYTE_OFFSET,
  HEADER_INVALID_DIFFICULTY_CODE,
  HEADER_MIN_LENGTH,
  HEADER_PREFIX_LENGTH,
  HEADER_SCHEME_BIT_SHIFT,
  HEADER_SCHEME_MASK,
  HEADER_SECOND_INFO_BYTE_OFFSET,
  HEADER_SECOND_INFO_RESERVED_MASK,
  HEADER_SECOND_INFO_SCHEME_MASK,
  HEADER_START_BYTE,
  HEADER_START_BYTE_OFFSET,
  HEADER_STREAM_AUTH_BIT,
} from './constants.js';
import { SchemeRegistry }   from '../config/SchemeRegistry.js';
import { InvalidHeaderError, HeaderDecodeError } from '../errors/index.js';
import { EncryptionAlgorithm } from '../types/index.js';

export function decodeHeaderPrefix(buf: Uint8Array) {
  if (buf.length < HEADER_PREFIX_LENGTH) {
    throw new InvalidHeaderError('Invalid input format. Header too short.');
  }
  const info = buf[HEADER_INFO_BYTE_OFFSET];
  const hasExtendedInfo = (info & HEADER_EXTENDED_INFO_BIT) !== 0;
  const prefixLength = hasExtendedInfo ? HEADER_EXTENDED_PREFIX_LENGTH : HEADER_PREFIX_LENGTH;
  let scheme = (info & HEADER_SCHEME_MASK) >> HEADER_SCHEME_BIT_SHIFT;
  if (hasExtendedInfo) {
    if (buf.length < prefixLength) {
      throw new InvalidHeaderError('Invalid input format. Second info byte missing.');
    }
    const secondInfo = buf[HEADER_SECOND_INFO_BYTE_OFFSET];
    if ((secondInfo & HEADER_SECOND_INFO_RESERVED_MASK) !== 0) {
      throw new InvalidHeaderError('Unsupported second info byte flags.');
    }
    scheme |= (secondInfo & HEADER_SECOND_INFO_SCHEME_MASK) << HEADER_EXTENDED_SCHEME_BIT_SHIFT;
  }
  const saltStrength: 'low' | 'high' = (info & HEADER_HIGH_SALT_STRENGTH_BIT) ? 'high' : 'low';
  return { scheme, saltStrength, prefixLength };
}

export function decodeHeader(
  buf: Uint8Array,
  cipher?: EncryptionAlgorithm,
) {
  if (buf[HEADER_START_BYTE_OFFSET] !== HEADER_START_BYTE) {
    throw new InvalidHeaderError('Invalid input format. The input is unknown.');
  }

  if (buf.length < HEADER_MIN_LENGTH) {
    throw new InvalidHeaderError('Invalid input format. Header too short.');
  }

  try {
    const info          = buf[HEADER_INFO_BYTE_OFFSET];
    const { scheme, saltStrength, prefixLength } = decodeHeaderPrefix(buf);
    const diffCode      = info & HEADER_DIFFICULTY_MASK;
    if (diffCode === HEADER_INVALID_DIFFICULTY_CODE) {
      throw new InvalidHeaderError('Unsupported difficulty code.');
    }
    const difficulty    = (['low', 'middle', 'high'] as const)[diffCode];
    const streamFormat: 'authenticated-v1' | 'legacy' = (info & HEADER_STREAM_AUTH_BIT) !== 0
      ? 'authenticated-v1'
      : 'legacy';
    const saltLen       = SchemeRegistry.get(scheme).saltLengths[saltStrength];
    const headerLen     = prefixLength + saltLen;

    if (buf.length < headerLen) {
      throw new InvalidHeaderError('Invalid input format. Header truncated.');
    }

    // IMPORTANT: set AAD to the *exact* bytes that were (or will be) transmitted as header.
    if (cipher) cipher.setAAD(buf.subarray(0, headerLen));

    const salt          = buf.slice(prefixLength, headerLen);

    return { scheme, difficulty, saltStrength, salt, headerLen, streamFormat };
  } catch (err) {
    throw new HeaderDecodeError(err instanceof Error ? err.message : String(err), { cause: err });
  }
}