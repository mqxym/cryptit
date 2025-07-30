// packages/core/src/index.ts

import './config/defaults.js';

import type { CryptoProvider } from "./providers/CryptoProvider.js";

import { Difficulty, SaltStrength } from './config/defaults.js';

import { encodeHeader } from "./header/encoder.js";
import { decodeHeader } from "./header/decoder.js";

import {
  EncryptionAlgorithm,
  KeyDerivation,
  VersionDescriptor,
} from './types/index.js';

import { VersionRegistry } from "./config/VersionRegistry.js";

import { base64Encode, base64Decode } from "./util/bytes.js";

import { StreamProcessor }  from "./stream/StreamProcessor.js";
import { EncryptTransform } from "./stream/EncryptTransform.js";
import { DecryptTransform } from "./stream/DecryptTransform.js";

// ────────────────────────────────────────────────────────────────────────────
//  Public configuration shape
// ────────────────────────────────────────────────────────────────────────────

export interface EncryptStreamResult {
  header: Uint8Array;
  writable: WritableStream<Uint8Array>;
  readable: ReadableStream<Uint8Array>;
}


export interface CryptitOptions {
  /** 0 … 7 – defaults to the registry’s *current* version */
  version?: number;
  /** ‘low’ | ‘middle’ | ‘high’; defaults to descriptor’s middle/high */
  saltStrength?: SaltStrength;
  difficulty?: Difficulty;
  chunkSize?: number;
}

export class Cryptit {
  private readonly v: VersionDescriptor;
  private readonly cipher: EncryptionAlgorithm;
  private readonly kdf: KeyDerivation;
  private readonly chunkSize: number;
  private readonly stream: StreamProcessor;
  
  private readonly difficulty: Difficulty;
  private readonly saltStrength: SaltStrength;

  constructor(
    private readonly provider: CryptoProvider,
    opt: CryptitOptions = {},
  ) {
    this.v = VersionRegistry.get(opt.version ?? VersionRegistry.current.id);
    this.cipher = new this.v.cipher(provider);
    this.kdf    = this.v.kdf;
    this.chunkSize = opt.chunkSize ?? this.v.defaultChunkSize;
    this.stream = new StreamProcessor(this.cipher, this.chunkSize);

    this.difficulty   = opt.difficulty   ?? 'middle';
    this.saltStrength = opt.saltStrength ?? 'high';
  }

  // ------------------------------------------------------------------------------------------------
  //  TEXT
  // ------------------------------------------------------------------------------------------------
  async encryptText(plain: string | Uint8Array, pass: string): Promise<string> {
    const salt = this.genSalt();
    await this.deriveKey(pass, salt);

    const cipher = await this.cipher.encryptChunk(
      typeof plain === 'string' ? new TextEncoder().encode(plain) : plain,
    );
    const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt);
    return base64Encode(header, cipher);
  }

  async decryptText(b64: string, pass: string): Promise<string> {
    const data = base64Decode(b64);
    const hdr  = decodeHeader(data);
    const v    = VersionRegistry.get(hdr.version);

    this.ensureSameVersion(v);                // LSP – never mix engines
    await this.deriveKey(pass, hdr.salt, hdr.difficulty);

    const plain = await this.cipher.decryptChunk(data.slice(hdr.headerLen));
    return new TextDecoder().decode(plain);
  }


  /* ──────────────────────────────────────────────────────────
   Encrypt a whole Blob and return an opaque binary Blob
   ────────────────────────────────────────────────────────── */
async encryptFile(file: Blob, pass: string): Promise<Blob> {
  const salt = this.genSalt();
  await this.deriveKey(pass, salt);                       // difficulty defaulted

  const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt);

  const cipher = await this.stream.collect(
    file.stream() as ReadableStream<Uint8Array>,
    new EncryptTransform(this.cipher, this.chunkSize).toTransformStream(),
    header,                                               // prepend once
  );

  return new Blob([cipher], { type: 'application/octet-stream' });
}

/* ──────────────────────────────────────────────────────────
   Decrypt a Blob that carries its own header (any version)
   ────────────────────────────────────────────────────────── */
async decryptFile(file: Blob, pass: string): Promise<Blob> {
  /* peek first 2 bytes → work out version & saltStrength      */
  const info          = new Uint8Array(await file.slice(0, 2).arrayBuffer());
  const version       = info[1] >> 5;
  const saltStrength  = ((info[1] >> 2) & 1) ? 'high' : 'low';
  const saltLen       = VersionRegistry.get(version).saltLengths[saltStrength];
  const headerLen     = 2 + saltLen;

  const header = new Uint8Array(await file.slice(0, headerLen).arrayBuffer());
  const parsed = decodeHeader(header);                    // gives salt & difficulty

  await this.deriveKey(pass, parsed.salt, parsed.difficulty);

  const plain = await this.stream.collect(
    file.slice(headerLen).stream() as ReadableStream<Uint8Array>,
    new DecryptTransform(this.cipher, this.chunkSize).toTransformStream(),
  );

  return new Blob([plain], { type: 'application/octet-stream' });
}

/* ──────────────────────────────────────────────────────────
   Streaming encryption: returns header + TransformStream
   ────────────────────────────────────────────────────────── */
async createEncryptionStream(pass: string): Promise<EncryptStreamResult> {
  const salt = this.genSalt();
  await this.deriveKey(pass, salt);

  const header = encodeHeader(this.v.id, this.difficulty, this.saltStrength, salt);
  const tf     = this.stream.encryptionStream();          // headerless pipeline

  return { header, writable: tf.writable, readable: tf.readable };
}

/* ──────────────────────────────────────────────────────────
   Streaming decryption (auto-detect header, any version)
   ────────────────────────────────────────────────────────── */
async createDecryptionStream(
  passphrase: string,
): Promise<TransformStream<Uint8Array, Uint8Array>> {

  const self       = this;
  let   buf        = new Uint8Array(0);
  let   derived    = false;
  let   downstream!: TransformStream<Uint8Array, Uint8Array>;

  function concat(a: Uint8Array, b: Uint8Array) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a); out.set(b, a.length);
    return out;
  }

  async function pump(
    readable: ReadableStream<Uint8Array>,
    ctl: TransformStreamDefaultController<Uint8Array>,
  ) {
    const reader = readable.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      ctl.enqueue(value);
    }
  }

  return new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, ctl) {
      if (!derived) {
        buf = concat(buf, chunk);
        if (buf.length < 2) return;

        const version       = buf[1] >> 5;
        const saltStrength  = ((buf[1] >> 2) & 1) ? 'high' : 'low';
        const saltLen       = VersionRegistry.get(version).saltLengths[saltStrength];
        const hdrLen        = 2 + saltLen;
        if (buf.length < hdrLen) return;

        const header                  = buf.slice(0, hdrLen);
        const { salt, difficulty }    = decodeHeader(header);

        /* Safety: ensure stream version matches this instance */
        if (version !== self.v.id)
          throw new Error(`Ciphertext v${version} but Cryptit instance is v${self.v.id}`);

        await self.deriveKey(passphrase, salt, difficulty);

        downstream = new DecryptTransform(self.cipher, self.chunkSize).toTransformStream();
        pump(downstream.readable, ctl);                   // fire-and-forget

        const remainder = buf.slice(hdrLen);
        if (remainder.length) {
          const w = downstream.writable.getWriter();
          await w.write(remainder);
          w.releaseLock();
        }
        derived = true;
        return;
      }

      const w = downstream.writable.getWriter();
      await w.write(chunk);
      w.releaseLock();
    },

    async flush() {
      if (derived) {
        const w = downstream.writable.getWriter();
        await w.close();
        w.releaseLock();
      }
    },
  });
}

  // ──────────────────────────────────────────────────
  //  Helpers
  // ──────────────────────────────────────────────────
  private async deriveKey(
    pass: string,
    salt: Uint8Array,
    diff: Difficulty = this.difficulty,   // ← default so callers may omit
  ): Promise<void> {
    const key = await this.kdf.derive(pass, salt, diff, this.provider);
    (this.cipher as any).key = key;       // AES-GCM (and other engines) expect it
  }

  concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  private genSalt(): Uint8Array {
    const len = this.v.saltLengths[this.saltStrength];
    return this.provider.getRandomValues(new Uint8Array(len));
  }

  private ensureSameVersion(v: VersionDescriptor): void {
    if (v.id !== this.v.id)
      throw new Error(
        `This Cryptit instance was created for v${this.v.id} but ciphertext is v${v.id}`,
      );
  }
}
