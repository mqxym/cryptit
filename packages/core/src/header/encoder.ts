// packages/core/src/header/encoder.ts
import { HEADER_START_BYTE, HEADER_STREAM_AUTH_BIT } from './constants.js';
import { concat } from '../util/bytes.js';
import { EncryptionAlgorithm } from '../types/index.js';
import type { StreamFormat } from '../util/frame.js';

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

  const diffCode = diffMap[difficulty];
  const infoByte =
    (scheme << 5) |
    (streamFormat === 'authenticated-v1' ? HEADER_STREAM_AUTH_BIT : 0) |
    ((saltStrength === 'high' ? 1 : 0) << 2) |
    diffCode;

  const header = concat(new Uint8Array([HEADER_START_BYTE, infoByte]), salt);

  // Make the *raw header bytes* the AAD for this message.
  if (cipher) cipher.setAAD(header);

  return header;
}