// packages/core/src/header/encoder.ts
import {
  HEADER_EXTENDED_INFO_BIT,
  HEADER_EXTENDED_SCHEME_BIT_SHIFT,
  HEADER_HIGH_SALT_STRENGTH_BIT,
  HEADER_SCHEME_BIT_SHIFT,
  HEADER_SCHEME_LOW_BITS_MASK,
  HEADER_START_BYTE,
  HEADER_STREAM_AUTH_BIT,
} from './constants.js';
import { concat } from '../util/bytes.js';
import { EncryptionAlgorithm } from '../types/index.js';
import type { StreamFormat } from '../util/frame.js';
import { SchemeRegistry } from '../config/SchemeRegistry.js';

export function encodeHeader(
  scheme: number,
  difficulty: 'low' | 'middle' | 'high',
  saltStrength: 'low' | 'high',
  salt: Uint8Array,
  cipher?: EncryptionAlgorithm,
  streamFormat: StreamFormat = 'legacy',
): Uint8Array {
  const diffMap = { low: 0, middle: 1, high: 2 } as const;
  if (!(difficulty in diffMap))
    throw new TypeError(`Unsupported difficulty: ${difficulty}`);
  if (saltStrength !== 'low' && saltStrength !== 'high') {
    throw new TypeError(`Unsupported salt strength: ${saltStrength}`);
  }
  if (streamFormat !== 'legacy' && streamFormat !== 'authenticated-v1') {
    throw new TypeError(`Unsupported stream format: ${streamFormat}`);
  }

  const descriptor = SchemeRegistry.get(scheme);
  const expectedSaltLength = descriptor.saltLengths[saltStrength];
  if (!(salt instanceof Uint8Array) || salt.length !== expectedSaltLength) {
    throw new TypeError(
      `Scheme ${scheme} ${saltStrength} salt must be ${expectedSaltLength} bytes`,
    );
  }

  const diffCode = diffMap[difficulty];
  const hasExtendedInfo = scheme > HEADER_SCHEME_LOW_BITS_MASK;
  const infoByte =
    ((scheme & HEADER_SCHEME_LOW_BITS_MASK) << HEADER_SCHEME_BIT_SHIFT) |
    (hasExtendedInfo ? HEADER_EXTENDED_INFO_BIT : 0) |
    (streamFormat === 'authenticated-v1' ? HEADER_STREAM_AUTH_BIT : 0) |
    (saltStrength === 'high' ? HEADER_HIGH_SALT_STRENGTH_BIT : 0) |
    diffCode;

  const prefix = hasExtendedInfo
    ? [HEADER_START_BYTE, infoByte, scheme >> HEADER_EXTENDED_SCHEME_BIT_SHIFT]
    : [HEADER_START_BYTE, infoByte];
  const header = concat(new Uint8Array(prefix), salt);

  // Make the *raw header bytes* the AAD for this message.
  if (cipher) cipher.setAAD(header);

  return header;
}