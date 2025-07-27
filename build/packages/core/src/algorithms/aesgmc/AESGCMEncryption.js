import { argon2id } from '../argon2.js';
import { DefaultConfig } from '../../config/defaults.js';
export class AESGCMEncryption {
    constructor(provider) {
        this.provider = provider;
        this.key = null;
    }
    async deriveKey(passphrase, salt, diff) {
        const env = this.provider.isNode ? 'node' : 'browser';
        const { hash } = await argon2id(passphrase, salt, DefaultConfig.argon[diff], env);
        this.key = await this.provider.subtle.importKey('raw', hash, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    }
    async encryptChunk(plain) {
        if (!this.key)
            throw new Error('KEY_NOT_DERIVED');
        const iv = this.provider.getRandomValues(new Uint8Array(12));
        const cipher = new Uint8Array(await this.provider.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, plain));
        const out = new Uint8Array(iv.length + cipher.length);
        out.set(iv);
        out.set(cipher, iv.length);
        return out;
    }
    async decryptChunk(data) {
        if (!this.key)
            throw new Error('KEY_NOT_DERIVED');
        const iv = data.slice(0, 12);
        const cipher = data.slice(12);
        const plain = await this.provider.subtle.decrypt({ name: 'AES-GCM', iv }, this.key, cipher);
        return new Uint8Array(plain);
    }
}
//# sourceMappingURL=AESGCMEncryption.js.map