// packages/core/src/stream/StreamProcessor.ts
import { EncryptTransform } from "./EncryptTransform.js";
import { DecryptTransform } from "./DecryptTransform.js";
export class StreamProcessor {
    constructor(engine, chunkSize = 512 * 1024) {
        this.engine = engine;
        this.chunkSize = chunkSize;
    }
    // ─────────────────────────────────────────────────────────────
    //  Encrypt: prepend header once, then run EncryptTransform
    // ─────────────────────────────────────────────────────────────
    encryptionStream(header) {
        let pushed = false;
        const prepend = new TransformStream({
            transform(chunk, ctl) {
                if (!pushed) {
                    ctl.enqueue(header);
                    pushed = true;
                }
                ctl.enqueue(chunk);
            },
        });
        const encrypted = new EncryptTransform(this.engine, this.chunkSize)
            .toTransformStream();
        /* .readable → pipeThrough → returns ReadableStream
           Cast back to TransformStream so callers can use it with
           Readable.pipeThrough(transform). */
        return {
            writable: prepend.writable, // upstream entry
            readable: prepend.readable
                .pipeThrough(encrypted), // downstream exit
        };
    }
    // ─────────────────────────────────────────────────────────────
    //  Decrypt: strip header bytes first, then run DecryptTransform
    // ─────────────────────────────────────────────────────────────
    decryptionStream(headerLen) {
        let skip = headerLen;
        const strip = new TransformStream({
            transform(chunk, ctl) {
                if (skip === 0) {
                    ctl.enqueue(chunk);
                    return;
                }
                if (chunk.byteLength <= skip) {
                    skip -= chunk.byteLength; // still inside header
                    return;
                }
                ctl.enqueue(chunk.slice(skip));
                skip = 0;
            },
        });
        const decrypted = new DecryptTransform(this.engine, this.chunkSize)
            .toTransformStream();
        return {
            writable: strip.writable,
            readable: strip.readable
                .pipeThrough(decrypted),
        };
    }
    // ─────────────────────────────────────────────────────────────
    //  Helper that collects a full stream into a single Uint8Array
    // ─────────────────────────────────────────────────────────────
    async collect(readable, transform, prefix = null) {
        const reader = readable.pipeThrough(transform).getReader();
        const chunks = [];
        if (prefix === null || prefix === void 0 ? void 0 : prefix.length)
            chunks.push(prefix);
        while (true) {
            const { value, done } = await reader.read();
            if (done)
                break;
            chunks.push(value);
        }
        const total = chunks.reduce((n, c) => n + c.byteLength, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const c of chunks) {
            out.set(c, offset);
            offset += c.byteLength;
        }
        return out;
    }
}
//# sourceMappingURL=StreamProcessor.js.map