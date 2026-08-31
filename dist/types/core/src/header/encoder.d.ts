import { EncryptionAlgorithm } from '../types/index.js';
import type { StreamFormat } from '../util/frame.js';
export declare function encodeHeader(scheme: number, difficulty: 'low' | 'middle' | 'high', saltStrength: 'low' | 'high', salt: Uint8Array, cipher?: EncryptionAlgorithm, streamFormat?: StreamFormat): Uint8Array;
