import { HEADER_START_BYTE } from './constants.js';
import { DefaultConfig } from '../config/defaults.js';
export function decodeHeader(bytes) {
    if (bytes[0] !== HEADER_START_BYTE)
        throw new Error('INVALID_HEADER');
    const info = bytes[1];
    const version = info >> 5;
    const saltStrength = ((info >> 2) & 1) ? 'high' : 'low';
    const diffCode = info & 0b11;
    const difficulty = ['low', 'middle', 'high'][diffCode];
    const saltLen = DefaultConfig.saltLengths[saltStrength];
    const salt = bytes.slice(2, 2 + saltLen);
    return { version, difficulty, saltStrength, salt, headerLen: 2 + saltLen };
}
//# sourceMappingURL=decoder.js.map