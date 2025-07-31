// packages/core/src/header/decoder.ts
import { HEADER_START_BYTE } from './constants.js';
import { VersionRegistry }   from '../config/VersionRegistry.js';
import { InvalidHeaderError, HeaderDecodeError } from '../errors/index.js';

export function decodeHeader(buf: Uint8Array) {
  if (buf[0] !== HEADER_START_BYTE) throw new InvalidHeaderError('Invalid input format. The input is unknown.');

  try {
    const info         = buf[1];
    const version      = info >> 5;
    const saltStrength = ((info >> 2) & 1) ? 'high' : 'low';
    const diffCode     = info & 0b11;
    const difficulty   = (['low', 'middle', 'high'] as const)[diffCode];
    const saltLen      = VersionRegistry.get(version).saltLengths[saltStrength];
    const salt         = buf.slice(2, 2 + saltLen);

    return { version, difficulty, saltStrength, salt, headerLen: 2 + saltLen };

  } catch (err) {
    throw new HeaderDecodeError(
      err instanceof Error ? err.message : String(err),
    );
  }
}