import { webcrypto, randomFillSync } from "node:crypto";
export const nodeProvider = {
    // cast is safe: Node’s SubtleCrypto is a superset of the browser spec
    subtle: webcrypto.subtle,
    getRandomValues(buf) {
        randomFillSync(buf);
        return buf;
    },
    isNode: true
};
//# sourceMappingURL=provider.js.map