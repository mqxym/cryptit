# @mqxym/cryptit

[![Base CI](https://github.com/mqxym/cryptit/actions/workflows/base-ci.yml/badge.svg)](https://github.com/mqxym/cryptit/actions/workflows/base-ci.yml)

Modern, cross-platform encryption for both **files** *and* **text**.

* **Node 18 / Bun 1** - native `argon2` addon + WebCrypto
* **Browser (evergreen)** - tiny WASM build of `argon2-browser`
* **CLI** - stream encryption & decryption, zero memory bloat
* **TypeScript-first**, tree-shakable, ESM & CJS builds
* **Format-agnostic decryption** - one instance reads any registered scheme

## Scheme Support

Currently there are 2 encryption schemes supported:

* **Scheme 0** (default): **AES-GCM 256** (native via Crypto API) and **Argon2id** (single thread parallelism setup using `argon2` or `argon2-browser`\*)
* **Scheme 1**: **XChaCha20Poly1305** (via JavaScript engine `@noble/ciphers`) and and **Argon2id** (multi thread parallelism setup using `argon2` or `argon2-browser`\*)

**\*** This means that for the same "difficulty" setting, the KDF will be significantly slower in the browser than in Node.js.

The library can support up to 8 schemes via a header info byte (3 bit allocated).

> [!WARNING]
> Scheme 1 works with an extractable CryptoKey. If unsure use scheme 0.

---

## Live Demo

* Encryption / Decryption: [https://mqxym.github.io/cryptit/text-encryption.html](https://mqxym.github.io/cryptit/text-encryption.html)
* Data Decoding [https://mqxym.github.io/cryptit/text-decoding.html](https://mqxym.github.io/cryptit/text-decoding.html)

---

## Install

```bash
# Bun (recommended)
bun add @mqxym/cryptit

# npm / pnpm
yarn add @mqxym/cryptit           # or npm i / pnpm add
```

---

## Quick start - Node / Bun

```ts
import { createCryptit } from "@mqxym/cryptit";

const crypt = createCryptit({ scheme: 1 });
const pass  = "correct horse battery staple";

// Encrypt: returns a ConvertibleOutput wrapper
const out = await crypt.encryptText("hello", pass);

// Pick your preferred representation
console.log(out.base64);      // Base64 container
console.log(out.hex);         // Hex container
const bytes = out.uint8array; // Uint8Array container

// Decrypt: accepts Base64, Uint8Array, or ConvertibleInput
const dec = await crypt.decryptText(out.base64, pass);
console.log(dec.text);        // "hello"

// Clean sensitive buffers when done
out.clear();
dec.clear();
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
<script>
  // This needs to be included before the actual importing of cryptit
  // IMPORTANT: host argon2.wasm where the fetch command points to
  window.loadArgon2WasmBinary = () =>
    fetch("/examples/assets/argon2.wasm")
      .then(r => r.arrayBuffer())
      .then(buf => new Uint8Array(buf));
</script>

<!-- app.ts / app.js -->
<script type="module">
  import { createCryptit } from "@mqxym/cryptit/browser";

  const crypt = createCryptit({ saltStrength: "high", verbose: 2 });

  async function enc() {
    const cipher = await crypt.encryptText("hello", "pw");
    console.log(cipher.base64);  // or .hex / .uint8array
    cipher.clear();
  }
  enc();
</script>
```

*Use with a bundler or simply via `<script type="module">`.*

---

## API highlights

```ts
import { createCryptit, Cryptit } from "@mqxym/cryptit";
// Also available: ConvertibleInput / ConvertibleOutput
// import { ConvertibleInput, ConvertibleOutput } from "@mqxym/cryptit/util/convertible";

const c = createCryptit({ verbose: 1 });

// TEXT 
const enc: ConvertibleOutput =
  await c.encryptText(/* string | Uint8Array | ConvertibleInput */ "txt", pass);
// Choose your representation:
enc.base64; enc.hex; enc.uint8array; // and wipe when done:
enc.clear();

const dec: ConvertibleOutput =
  await c.decryptText(/* Base64 string | Uint8Array | ConvertibleInput */ enc.base64, pass);
dec.text;
dec.clear();

// RUNTIME TWEAKS
c.setDifficulty("high");  // Argon2id difficulty preset
c.setScheme(1);           // choose another registered format (scheme 1 = XChaCha20Poly1305)
c.setSaltDifficulty("low");

// HELPERS
Cryptit.isEncrypted(blobOrB64);   // ↦ boolean
Cryptit.headerDecode(blobOrB64);  // ↦ meta {scheme, salt, …}
```

Verbose levels:

| Level | Emits                         |
| ----- | ----------------------------- |
| 0     | errors only                   |
| 1     | +start/finish notices         |
| 2     | +timings, key-derivation info |
| 3     | +salt / scheme / KDF details |
| 4     | wire-level debug              |

---

## CLI (`cryptit`)

```bash
# encrypt file → .enc
cryptit encrypt  <in> [-o out] [options]

# decrypt back
cryptit decrypt  <in> [-o out] [options]

# encrypt text
echo "secret" | cryptit encrypt-text  -p pw
cryptit encrypt-text "secret" -d high -S 1 # -> Prompt for password, Argon2id difficulty "high" and Scheme 1

# decrypt text
echo "…b64…" | cryptit decrypt-text -p pw

# inspect header (no decryption)
cryptit decode movie.enc
cat movie.enc | cryptit decode
```

## Docker CLI

```bash
docker pull ghcr.io/mqxym/cryptit-cli:latest

echo "AQVWgYDH/rkR6Ymxv1W9NzFWTsvTTXsnEaLHPx+NlATmuwcqea5RlljX1ly16Px716I2yGX/XsXHt7xG14DmnJ3Czu0A9/TM1sPJayRdHDYPckJ5eGfAGY5n5H8nNjKqhpY=" | docker run --rm -i cryptit:latest decode | jq
```

### Common flags

| Flag                      | Default | Description          |
| ------------------------- | ------- | -------------------- |
| `-p, --pass <pw>`         | prompt  | passphrase           |
| `-d, --difficulty <l>`    | middle  | Argon2 preset        |
| `-S, --scheme <0-1>.`     | 0.      | Scheme preset        |
| `-s, --salt-strength <l>` | high    | 12 B vs 16 B salt    |
| `-c, --chunk-size <n>`    | 524 288 | plaintext block size |
| `-v, --verbose`           |  0 … 4  | repeat to increase   |

Exit codes: **0** success · **1** any failure (invalid header, auth, I/O …)

> [!NOTE]
> Use the prompt password feature where ever possible, to not leak your password via history.

---

## Versioned format

* Header: `0x01 | infoByte | salt`
* Decryptors pick the engine by the header’s scheme ⇒ **one CLI handles all registered schemes**.

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
* XChaCha20Poly1305 / 24-byte IV / 128-bit tag
* Argon2-id presets (low / middle / high)
* Salts generated per-ciphertext; never reused

> [!IMPORTANT]
> **DISCLAIMER** This project was created in collaboration with OpenAI’s language models and me, @mqxym.

---

## License

MIT
