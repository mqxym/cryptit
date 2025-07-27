import { Cryptit } from '../../core/src/index.js';
import { nodeProvider } from './provider.js';
export function createCryptit(cfg) {
    return new Cryptit(nodeProvider, cfg);
}
//# sourceMappingURL=index.js.map