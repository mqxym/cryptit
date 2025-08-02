# @mqxym/cryptit

Modern, cross-platform **AES-GCM 256 / XChaCha20Poly1305 + Argon2-id** encryption for both **files** *and* **text**.

* **Node 18 / Bun 1** – native `argon2` addon + WebCrypto
* **Browser (evergreen)** – tiny WASM build of `argon2-browser`
* **CLI** – stream encryption & decryption, zero memory bloat
* **TypeScript-first**, tree-shakable, ESM & CJS builds
* **Format-agnostic decryption** – one instance reads any registered version

---

## Install

```bash
# Bun (recommended)
bun add @mqxym/cryptit

# npm / pnpm
yarn add @mqxym/cryptit           # or npm i / pnpm add
```

---

## Quick start – Node / Bun

```ts
import { createCryptit } from "@mqxym/cryptit";

const crypt = createCryptit({ difficulty: "middle" });
const pass  = "correct horse battery staple";

const b64 = await crypt.encryptText("hello", pass);
console.log(await crypt.decryptText(b64, pass)); // → "hello"
```

### Streaming files

```ts
import { createCryptit } from "@mqxym/cryptit";
import { createReadStream, createWriteStream } from "node:fs";

const crypt = createCryptit();
const pass  = "hunter2";

// encrypt → movie.enc
await createReadStream("movie.mkv")
  .pipeThrough(await crypt.createEncryptionStream(pass))
  .pipeTo(createWriteStream("movie.enc"));

// decrypt back
await createReadStream("movie.enc")
  .pipeThrough(await crypt.createDecryptionStream(pass))
  .pipeTo(createWriteStream("movie.mkv"));
```

---

## Browser usage

```html
<!-- app.ts / app.js -->
<script type="module">
  import { createCryptit } from "@mqxym/cryptit/browser";

  // IMPORTANT: host argon2.wasm at /dist/argon2.wasm (relative to final HTML)

  const crypt = createCryptit({ saltStrength: "high", verbose: 2 });

  async function enc() {
    const cipher = await crypt.encryptText("hello", "pw");
    console.log(cipher);
  }
  enc();
</script>
```

*Use with a bundler or simply via `<script type="module">`.*

---

## API highlights

```ts
const c = createCryptit({ verbose: 1 });

// text
await c.encryptText("txt", pass);
await c.decryptText(b64,  pass);

// runtime tweaks
c.setDifficulty("high");
c.setScheme(1);           // choose another registered format (version 1 = XChaCha20Poly1305)
c.setSaltDifficulty("low");

// helpers
Cryptit.isEncrypted(blobOrB64);          // ↦ boolean
Cryptit.headerDecode(blobOrB64);         // ↦ meta {version, salt, …}
```

Verbose levels:

| Level | Emits                         |
| ----- | ----------------------------- |
| 0     | errors only                   |
| 1     | +start/finish notices         |
| 2     | +timings, key-derivation info |
| 3     | +salt / version / KDF details |
| 4     | wire-level debug              |

---

## CLI (`cryptit`)

```bash
# encrypt file → .enc | decrypt back
encrypt: cryptit encrypt  <in> [-o out] [options]
decrypt: cryptit decrypt  <in> [-o out] [options]

encrypt text  : echo "secret" | cryptit encrypt-text  -p pw
decrypt text  : echo "…b64…" | cryptit decrypt-text -p pw

# inspect header (no decryption)
cryptit decode movie.enc
cat movie.enc | cryptit decode
```

### Common flags

| Flag                      | Default | Description          |
| ------------------------- | ------- | -------------------- |
| `-p, --pass <pw>`         | prompt  | passphrase           |
| `-d, --difficulty <l>`    | middle  | Argon2 preset        |
| `-S, --scheme <0-1>. `    | 0.      | Scheme preset        |
| `-s, --salt-strength <l>` | high    | 12 B vs 16 B salt    |
| `-c, --chunk-size <n>`    | 524 288 | plaintext block size |
| `-v, --verbose`           |  0 … 4  | repeat to increase   |

Exit codes: **0** success · **1** any failure (invalid header, auth, I/O …)

---

## Versioned format

* Header: `0x01 | infoByte | salt`
* Decryptors pick the engine by the header’s version ⇒ **one CLI handles all registered versions**.

---

## Build from source

```bash
git clone https://github.com/mqxym/cryptit
cd cryptit
bun install && bun run build && bun test
```

---

## Security

* AES-GCM 256 / 12-byte IV / 128-bit tag
* Argon2-id presets (low / middle / high)
* Salts generated per-ciphertext; never reused

---

## License

MIT
