// packages/core/src/header/encoder.ts
import { DefaultConfig, Difficulty, SaltStrength } from '../config/defaults.js';
import { CURRENT_VERSION, HEADER_START_BYTE } from './constants.js';

export function encodeHeader(
  diff: Difficulty,
  saltStrength: SaltStrength,
  salt: Uint8Array
): Uint8Array {
  const infoByte =
    (CURRENT_VERSION << 5) |
    ((saltStrength === 'high' ? 1 : 0) << 2) |
    ({ low: 0, middle: 1, high: 2 } as const)[diff];
  return new Uint8Array([HEADER_START_BYTE, infoByte, ...salt]);
}