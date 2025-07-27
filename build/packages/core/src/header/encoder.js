import { CURRENT_VERSION, HEADER_START_BYTE } from './constants.js';
export function encodeHeader(diff, saltStrength, salt) {
    const infoByte = (CURRENT_VERSION << 5) |
        ((saltStrength === 'high' ? 1 : 0) << 2) |
        { low: 0, middle: 1, high: 2 }[diff];
    return new Uint8Array([HEADER_START_BYTE, infoByte, ...salt]);
}
//# sourceMappingURL=encoder.js.map