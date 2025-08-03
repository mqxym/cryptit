// packages/core/src/header/decoder.ts
import { HEADER_START_BYTE } from './constants.js';
import { SchemeRegistry }   from '../config/SchemeRegistry.js';
import { InvalidHeaderError, HeaderDecodeError } from '../errors/index.js';

export function decodeHeader(buf: Uint8Array) {
  if (buf[0] !== HEADER_START_BYTE) throw new InvalidHeaderError('Invalid input format. The input is unknown.');

  if ( buf.length < 2 + 12 ) throw new InvalidHeaderError('Invalid input format. Header too short.'); //minimum header length

  try {
    const info         = buf[1];
    const scheme      = info >> 5;
    const saltStrength = ((info >> 2) & 1) ? 'high' : 'low';
    const diffCode     = info & 0b11;
    const difficulty   = (['low', 'middle', 'high'] as const)[diffCode];
    const saltLen      = SchemeRegistry.get(scheme).saltLengths[saltStrength];
    const salt         = buf.slice(2, 2 + saltLen);

    return { scheme, difficulty, saltStrength, salt, headerLen: 2 + saltLen };

  } catch (err) {
    throw new HeaderDecodeError(
      err instanceof Error ? err.message : String(err),
    );
  }
}