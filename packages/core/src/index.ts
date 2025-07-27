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
  async createEncryptionStream(pass: string): Promise<TransformStream> {
    const salt = this.genSalt();
    await this.algo.deriveKey(pass, salt, this.difficulty);
    const header = encodeHeader(this.difficulty, this.saltStrength, salt);
    return this.streamer.encryptionStream(header);
  }

  async createDecryptionStream(pass: string): Promise<TransformStream> {
    // Dynamically buffer header, then hand off to real decrypt stream.
    // Keeps memory footprint low for large files.
    const self = this;
    let headerBuf = new Uint8Array(0);
    let downstream: TransformStream<Uint8Array, Uint8Array> | null = null;
    let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;

    return new TransformStream<Uint8Array, Uint8Array>({
      async transform(chunk, ctl) {
        if (downstream) {
          await writer!.write(chunk);
          return;
        }

        // accumulate until full header present
        const tmp = new Uint8Array(headerBuf.length + chunk.length);
        tmp.set(headerBuf);
        tmp.set(chunk, headerBuf.length);
        headerBuf = tmp;

        if (headerBuf.length < 2) return;

        const strong = ((headerBuf[1] >> 2) & 1) ? "high" : "low";
        const expect = 2 + DefaultConfig.saltLengths[strong];
        if (headerBuf.length < expect) return;

        // header complete → derive key & create downstream pipeline
        const head = headerBuf.slice(0, expect);
        const rest = headerBuf.slice(expect);

        const meta = decodeHeader(head);
        await self.algo.deriveKey(pass, meta.salt, meta.difficulty);

        downstream = self.streamer.decryptionStream(expect);
        writer     = (downstream.writable as WritableStream<Uint8Array>).getWriter();

        if (rest.length) await writer.write(rest);
        if (chunk.length > rest.length) {
          // any bytes from 'chunk' after header have already been forwarded
          const extra = chunk.slice(rest.length);
          if (extra.length) await writer.write(extra);
        }

        // pipe subsequent chunks directly
        ctl.enqueue = (x: Uint8Array) => writer!.write(x) as unknown as void;
      },
      async flush() {
        await writer?.close();
      },
    });
  }

  // ──────────────────────────────────────────────────
  //  Helpers
  // ──────────────────────────────────────────────────
  private genSalt(): Uint8Array {
    const len = DefaultConfig.saltLengths[this.saltStrength];
    return this.provider.getRandomValues(new Uint8Array(len));
  }
}