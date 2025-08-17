// packages/core/src/header/encoder.ts
import { HEADER_START_BYTE } from './constants.js';
import { concat } from '../util/bytes.js';

export function encodeHeader(
  scheme: number,
  difficulty: string,
  saltStrength: 'low' | 'high',
  salt: Uint8Array,
): Uint8Array {
  const diffMap = { low: 0, middle: 1, high: 2 } as const;
  if (!(difficulty in diffMap))
    throw new TypeError(`Unsupported difficulty: ${difficulty}`);
  const diffCode = diffMap[difficulty as keyof typeof diffMap];
  
  const infoByte = (scheme << 5) | ((saltStrength === 'high' ? 1 : 0) << 2) | diffCode;
  return concat(new Uint8Array([HEADER_START_BYTE, infoByte]), salt);
}