// packages/core/src/header/encoder.ts
import { HEADER_START_BYTE } from './constants.js';
import { concat } from '../util/bytes.js';

export function encodeHeader(
  version: number,
  difficulty: string,
  saltStrength: 'low' | 'high',
  salt: Uint8Array,
): Uint8Array {
  const diffCode = { low: 0, middle: 1, high: 2 }[difficulty] ?? 0;
  const infoByte = (version << 5) | ((saltStrength === 'high' ? 1 : 0) << 2) | diffCode;
  return concat(new Uint8Array([HEADER_START_BYTE, infoByte]), salt);
}