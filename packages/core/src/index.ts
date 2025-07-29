// packages/core/src/index.ts
import type { CryptoProvider } from "./providers/CryptoProvider.js";
import { AESGCMEncryption } from "./algorithms/aesgmc/AESGCMEncryption.js";

import { encodeHeader } from "./header/encoder.js";
import { decodeHeader } from "./header/decoder.js";

import {
  DefaultConfig,
  type Difficulty,
  type SaltStrength,
} from "./config/defaults.js";

import { StreamProcessor }  from "./stream/StreamProcessor.js";
import { EncryptTransform } from "./stream/EncryptTransform.js";
import { DecryptTransform } from "./stream/DecryptTransform.js";

// ────────────────────────────────────────────────────────────────────────────
//  Public configuration shape
// ────────────────────────────────────────────────────────────────────────────
export interface EncryptionConfig {
  difficulty?: Difficulty;
  saltStrength?: SaltStrength;
  chunkSize?: number;
}

export interface EncryptStreamResult {
  header: Uint8Array;
  writable: WritableStream<Uint8Array>;
  readable: ReadableStream<Uint8Array>;
}


// ────────────────────────────────────────────────────────────────────────────
//  Main high-level façade
// ────────────────────────────────────────────────────────────────────────────
export class Cryptit {
  private readonly algo: AESGCMEncryption;
  private readonly difficulty: Difficulty;
  private readonly saltStrength: SaltStrength;
  private readonly chunkSize: number;

  /** StreamProcessor can only be constructed *after* the three fields above */
  private readonly streamer: StreamProcessor;

  constructor(
    private readonly provider: CryptoProvider,
    cfg: EncryptionConfig = {},
  ) {
    this.algo         = new AESGCMEncryption(provider);
    this.difficulty   = cfg.difficulty   ?? "middle";
    this.saltStrength = cfg.saltStrength ?? "high";
    this.chunkSize    = cfg.chunkSize    ?? DefaultConfig.chunkSize;

    this.streamer = new StreamProcessor(this.algo, this.chunkSize);
  }

  // ──────────────────────────────────────────────────
  //  TEXT helpers
  // ──────────────────────────────────────────────────
  async encryptText(plain: string | Uint8Array, pass: string): Promise<string> {
    const salt = this.genSalt();
    await this.algo.deriveKey(pass, salt, this.difficulty);

    const cipher = await this.algo.encryptChunk(
      typeof plain === "string" ? new TextEncoder().encode(plain) : plain,
    );

    const header = encodeHeader(this.difficulty, this.saltStrength, salt);

    return Buffer.from([...header, ...cipher]).toString("base64");
  }

  async decryptText(b64: string, pass: string): Promise<string> {
    const data = Uint8Array.from(Buffer.from(b64, "base64"));
    const { difficulty, salt, headerLen } = decodeHeader(data);

    await this.algo.deriveKey(pass, salt, difficulty);

    const plain = await this.algo.decryptChunk(data.slice(headerLen));
    return new TextDecoder().decode(plain);
  }

  // ──────────────────────────────────────────────────
  //  FILE helpers
  // ──────────────────────────────────────────────────
  async encryptFile(file: Blob, pass: string): Promise<Blob> {
    const salt = this.genSalt();
    await this.algo.deriveKey(pass, salt, this.difficulty);

    const header = encodeHeader(this.difficulty, this.saltStrength, salt);
    const cipher = await this.streamer.collect(
      file.stream() as ReadableStream<Uint8Array>,
      new EncryptTransform(this.algo, this.chunkSize).toTransformStream(),
      header,
    );

    return new Blob([cipher], { type: "application/octet-stream" });
  }

  async decryptFile(file: Blob, pass: string): Promise<Blob> {
    // peek first 2 bytes → work out full header length
    const info   = new Uint8Array(await file.slice(0, 2).arrayBuffer());
    const strong = ((info[1] >> 2) & 1) ? "high" : "low";
    const hdrLen = 2 + DefaultConfig.saltLengths[strong];

    const header = new Uint8Array(await file.slice(0, hdrLen).arrayBuffer());
    const parsed = decodeHeader(header);

    await this.algo.deriveKey(pass, parsed.salt, parsed.difficulty);

    const plain = await this.streamer.collect(
      file.slice(hdrLen).stream() as ReadableStream<Uint8Array>,
      new DecryptTransform(this.algo, this.chunkSize).toTransformStream(),
    );

    return new Blob([plain], { type: "application/octet-stream" });
  }

  // ──────────────────────────────────────────────────
  //  STREAM-BASED (piping) helpers – for CLI, etc.
  // ──────────────────────────────────────────────────

async createEncryptionStream(pass: string): Promise<EncryptStreamResult> {
  const salt  = this.genSalt();
  await this.algo.deriveKey(pass, salt, this.difficulty);

  const header = encodeHeader(this.difficulty, this.saltStrength, salt);
  const tf     = this.streamer.encryptionStream();      // headerless

  return { header, writable: tf.writable, readable: tf.readable };
}
// ───────────────────────────────────────────────
//  Streaming decrypt (header-aware)
// ───────────────────────────────────────────────
async createDecryptionStream(
  passphrase: string
): Promise<TransformStream<Uint8Array, Uint8Array>> {

  const self = this;
  let buf    = new Uint8Array(0);
  let derived = false;
  let downstream!: TransformStream<Uint8Array, Uint8Array>;

  /** pumps decryptTs.readable → outer controller continuously */
  async function startPump(
    readable: ReadableStream<Uint8Array>,
    ctl: TransformStreamDefaultController<Uint8Array>
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
        // accumulate header
        buf = self.concat(buf, chunk);
        if (buf.length < 2) return;

        const saltFlag = ((buf[1] >> 2) & 1) ? "high" : "low";
        const hdrLen   = 2 + DefaultConfig.saltLengths[saltFlag];
        if (buf.length < hdrLen) return;

        // parse + derive
        const header = buf.slice(0, hdrLen);
        const { salt, difficulty } = decodeHeader(header);
        await self.algo.deriveKey(passphrase, salt, difficulty);

        // set up decrypt transform (no further header skipping)
        downstream = new DecryptTransform(self.algo, self.chunkSize)
                       .toTransformStream();

        // begin pumping plaintext out
        startPump(downstream.readable, ctl);   // fire-and-forget

        // push remainder (ciphertext after header) into decrypt
        const rem = buf.slice(hdrLen);
        if (rem.length) {
          const w = downstream.writable.getWriter();
          await w.write(rem);
          w.releaseLock();
        }
        derived = true;
        return;
      }

      // after derivation every chunk is plain ciphertext
      const w = downstream.writable.getWriter();
      await w.write(chunk);
      w.releaseLock();
    },

    async flush() {
      if (derived) {
        const w = downstream.writable.getWriter();
        await w.close();              // let pump finish
        w.releaseLock();
      }
    }
  });
}

  // ──────────────────────────────────────────────────
  //  Helpers
  // ──────────────────────────────────────────────────
  concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

  private genSalt(): Uint8Array {
    const len = DefaultConfig.saltLengths[this.saltStrength];
    return this.provider.getRandomValues(new Uint8Array(len));
  }
}