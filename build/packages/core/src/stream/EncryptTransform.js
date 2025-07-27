/**
 * TransformStream that:
 *   • collects plaintext into fixed-size blocks (default 512 KiB)
 *   • encrypts each block via the provided crypto engine
 *   • emits: [4-byte big-endian length ‖ encryptedBlock]
 *
 * Input  types accepted: Uint8Array | ArrayBuffer | Blob
 * Output type:           Uint8Array
 */
export class EncryptTransform {
    constructor(engine, chunkSize = 512 * 1024) {
        this.engine = engine;
        this.chunkSize = chunkSize;
        this.buffer = new Uint8Array(0);
    }
    /** Public factory – keeps callers one-liner-simple */
    toTransformStream() {
        return new TransformStream({
            transform: async (chunk, ctl) => {
                await this.transform(await this.asUint8Array(chunk), ctl);
            },
            flush: async (ctl) => this.flush(ctl),
        });
    }
    // --------------------------------------------------------------------------
    async transform(bytes, ctl) {
        // concat previous tail + new data
        const combined = new Uint8Array(this.buffer.length + bytes.length);
        combined.set(this.buffer);
        combined.set(bytes, this.buffer.length);
        let offset = 0;
        while (combined.length - offset >= this.chunkSize) {
            const block = combined.slice(offset, offset + this.chunkSize);
            offset += this.chunkSize;
            const encrypted = await this.engine.encryptChunk(block);
            // prepend 4-byte length-header (big-endian)
            const header = new Uint8Array(4);
            new DataView(header.buffer).setUint32(0, encrypted.length, false);
            const out = new Uint8Array(header.length + encrypted.length);
            out.set(header);
            out.set(encrypted, header.length);
            ctl.enqueue(out);
        }
        this.buffer = combined.slice(offset);
    }
    async flush(ctl) {
        if (!this.buffer.length)
            return;
        const encrypted = await this.engine.encryptChunk(this.buffer);
        const header = new Uint8Array(4);
        new DataView(header.buffer).setUint32(0, encrypted.length, false);
        const out = new Uint8Array(4 + encrypted.length);
        out.set(header);
        out.set(encrypted, 4);
        ctl.enqueue(out);
        this.buffer = new Uint8Array(0); // GC friendly
    }
    async asUint8Array(input) {
        if (input instanceof Uint8Array)
            return input;
        if (input instanceof ArrayBuffer)
            return new Uint8Array(input);
        // Blob
        return new Uint8Array(await input.arrayBuffer());
    }
}
//# sourceMappingURL=EncryptTransform.js.map