// packages/core/src/header/encoder.ts
import { HEADER_START_BYTE } from './constants.js';
import { concat } from '../util/bytes.js';
import { EncryptionAlgorithm } from '../types/index.js';

export function encodeHeader(
  scheme: number,
  difficulty: 'low' | 'middle' | 'high',
  saltStrength: 'low' | 'high',
  salt: Uint8Array,
  cipher?: EncryptionAlgorithm,
): Uint8Array {
  const diffMap = { low: 0, middle: 1, high: 2 } as const;
  if (!(difficulty in diffMap))
    throw new TypeError(`Unsupported difficulty: ${difficulty}`);

  const diffCode = diffMap[difficulty];
  const infoByte =
    (scheme << 5) |
    ((saltStrength === 'high' ? 1 : 0) << 2) |
    diffCode;

  const header = concat(new Uint8Array([HEADER_START_BYTE, infoByte]), salt);

  // Make the *raw header bytes* the AAD for this message.
  if (cipher) cipher.setAAD(header);

  return header;
}