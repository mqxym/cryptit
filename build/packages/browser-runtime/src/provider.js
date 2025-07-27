/**
 * Crypto shim for modern browsers (and Bun when used in “browser” code-paths).
 */
export const browserProvider = {
    subtle: globalThis.crypto.subtle,
    getRandomValues(buf) {
        return globalThis.crypto.getRandomValues(buf);
    },
    isNode: false // <- distinguishes from nodeProvider
};
//# sourceMappingURL=provider.js.map