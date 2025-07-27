/**
 * Counterpart to EncryptTransform.
 * Accepts the framed ciphertext and streams out raw plaintext.
 *
 * Emits Uint8Array chunks identical to the original plaintext
 * (except block boundaries aren’t guaranteed to match).
 */
export class DecryptTransform {
    constructor(engine, chunkSize = 512 * 1024) {
        this.engine = engine;
        this.chunkSize = chunkSize;
        this.buffer = new Uint8Array(0);
    }
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
        const combined = new Uint8Array(this.buffer.length + bytes.length);
        combined.set(this.buffer);
        combined.set(bytes, this.buffer.length);
        let offset = 0;
        while (true) {
            if (combined.length - offset < 4)
                break; // not enough for header
            const cipherLen = new DataView(combined.buffer, combined.byteOffset + offset, 4).getUint32(0, false);
            if (combined.length - offset - 4 < cipherLen)
                break; // incomplete
            offset += 4;
            const cipher = combined.slice(offset, offset + cipherLen);
            offset += cipherLen;
            const plain = await this.engine.decryptChunk(cipher);
            ctl.enqueue(plain);
        }
        this.buffer = combined.slice(offset);
    }
    async flush(ctl) {
        await this.transform(new Uint8Array(0), ctl); // process any tail
        this.buffer = new Uint8Array(0);
    }
    async asUint8Array(input) {
        if (input instanceof Uint8Array)
            return input;
        if (input instanceof ArrayBuffer)
            return new Uint8Array(input);
        return new Uint8Array(await input.arrayBuffer());
    }
}
//# sourceMappingURL=DecryptTransform.js.map