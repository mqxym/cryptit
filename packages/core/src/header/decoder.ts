// packages/core/src/header/decoder.ts
import { HEADER_START_BYTE } from './constants.js';
import { SchemeRegistry }   from '../config/SchemeRegistry.js';
import { InvalidHeaderError, HeaderDecodeError } from '../errors/index.js';
import { EncryptionAlgorithm } from '../types/index.js';

export function decodeHeader(
  buf: Uint8Array,
  cipher?: EncryptionAlgorithm,
) {
  if (buf[0] !== HEADER_START_BYTE) {
    throw new InvalidHeaderError('Invalid input format. The input is unknown.');
  }

  // Minimum header length guard (start + info + minimum salt len = 2 + 12)
  if (buf.length < 2 + 12) {
    throw new InvalidHeaderError('Invalid input format. Header too short.');
  }

  try {
    const info          = buf[1];
    const scheme        = info >> 5;
    const saltStrength  = ((info >> 2) & 1) ? 'high' : 'low';
    const diffCode      = info & 0b11;
    const difficulty    = (['low', 'middle', 'high'] as const)[diffCode];
    const saltLen       = SchemeRegistry.get(scheme).saltLengths[saltStrength];
    const headerLen     = 2 + saltLen;

    if (buf.length < headerLen) {
      throw new InvalidHeaderError('Invalid input format. Header truncated.');
    }

    // IMPORTANT: set AAD to the *exact* bytes that were (or will be) transmitted as header.
    if (cipher) cipher.setAAD(buf.subarray(0, headerLen));

    const salt          = buf.slice(2, 2 + saltLen);

    return { scheme, difficulty, saltStrength, salt, headerLen };
  } catch (err) {
    throw new HeaderDecodeError(err instanceof Error ? err.message : String(err));
  }
}