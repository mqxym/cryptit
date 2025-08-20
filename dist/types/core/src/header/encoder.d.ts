import { EncryptionAlgorithm } from '../types/index.js';
export declare function encodeHeader(scheme: number, difficulty: 'low' | 'middle' | 'high', saltStrength: 'low' | 'high', salt: Uint8Array, cipher?: EncryptionAlgorithm): Uint8Array;
