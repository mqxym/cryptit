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

* Text Encryption / Decryption: [https://mqxym.github.io/cryptit/text-encryption.html](https://mqxym.github.io/cryptit/text-encryption.html)
* Text Data Decoding [https://mqxym.github.io/cryptit/text-decoding.html](https://mqxym.github.io/cryptit/text-decoding.html)
* File Encryption / Decryption [https://mqxym.github.io/cryptit/file-encryption.html](https://mqxym.github.io/cryptit/file-encryption.html)
* File Streaming [https://mqxym.github.io/cryptit/streaming.html](https://mqxym.github.io/cryptit/streaming.html)
* File Data Decoding [https://mqxym.github.io/cryptit/file-decoding.html](https://mqxym.github.io/cryptit/file-decoding.html)

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
// import { ConvertibleInput, ConvertibleOutput } from "@mqxym/cryptit";

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
Cryptit.decodeHeader(blobOrB64);  // ↦ meta {scheme, salt, …}
Cryptit.decodeData(blobOrB64);  // ↦ {isChunked, ivLength, tagLength, iv, tag, …}
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

# inspect header, chunk and text details of Cryptit-encrypted payloads (no decryption)
cryptit decode movie.enc
cat movie.enc | cryptit decode

# output fake data (valid header) in base64 with random 32-byte tail
cryptit fake-data --base64 32
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

### Additional Authenticated Data

* Since version 1.0.0: Header data is authenticated.
* Since version 2.2.0: `encryptText()` uses 8-bit padding before AEAD, which is also tagged in AAD.

### Compatibility

* To decrypt data from versions prior to 1.0.0, there is a temporary solution:

  ```javascript
  const cryptit = createCryptit({ acceptUnauthenticatedHeader: true });
  ```

  * This option will be removed in future releases because the header must always be authenticated.
* The padding tag for encrypted text in AAD is not required, so encrypted text from versions prior to 2.2.0 can still be decrypted with versions greater than 2.2.0.
  * This backward compatibility will also be removed in future releases.

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

## CLI Benchmarks (Bun Engine, MacOS, M3 Pro Chip)

> **TL;DR**
> • **Scheme 0** (AES‑GCM/SubtleCrypto + XChaCha20‑Poly1305) is much faster for streaming: **peak ~1,810 MiB/s** (stdin→stdout, 256 MiB, *middle*).
> • **Scheme 1** (XChaCha20‑Poly1305) peaks **~170 MiB/s**.
> • KDF cost is now measured separately and **not** included in “stream‑only” throughput below.

---

#### KDF Baseline (avg of 3, encrypt‑text 16 B payload)

| Difficulty | KDF avg (Scheme 0) | KDF avg (Scheme 1) |
| :--------: | -----------------: | -----------------: |
|     low    |         174.29 ms  |         167.05 ms  |
|   middle   |         540.41 ms  |         442.74 ms  |
|    high    |        1013.10 ms  |         825.44 ms  |

<details>
<summary><strong>Stream‑only Throughput (KDF‑subtracted) — Scheme 0</strong></summary>

**Higher is better (MiB/s).**

|    Size   |  Difficulty  |  enc f→f  |  dec f→out  |   enc in→out  |  dec in→out  |
| :-------: | :----------: | --------: | ----------: | ------------: | -----------: |
|  256 MiB  |    low       |   868.33  |     910.05  |      1709.13  |     1519.16  |
|  256 MiB  |    middle    |   995.48  |     910.46  |  **1810.27**  |     1585.49  |
|  256 MiB  |    high      |   899.43  |     866.88  |      1658.29  |     1409.89  |

</details>

<details>
<summary><strong>Stream‑only Throughput (KDF‑subtracted) — Scheme 1</strong></summary>

**Higher is better (MiB/s).**

|    Size   |  Difficulty  |  enc f→f  |  dec f→out  |  enc in→out  |  dec in→out  |
| :-------: | :----------: | --------: | ----------: | -----------: | -----------: |
|  256 MiB  |    low       |   149.33  |     153.01  |      167.36  |      164.99  |
|  256 MiB  |    middle    |   154.23  |     154.72  |  **169.55**  |      162.91  |
|  256 MiB  |    high      |   149.83  |     151.26  |      157.55  |      163.05  |

</details>

<details>
<summary><strong>Wall‑clock Durations (no subtraction) — Scheme 0</strong></summary>

**Lower is better (ms / s). Decode columns show latency (ms).**

|    Size   |  Difficulty  |           enc f→f  |         dec f→out  |        enc in→out  |        dec in→out  |  decode file (ms)  |  decode stdin (ms)  |
| :-------: | :----------: | -----------------: | -----------------: | -----------------: | -----------------: | -----------------: | ------------------: |
|  256 MiB  |    low       |   469 ms / 0.47 s  |   456 ms / 0.46 s  |   324 ms / 0.32 s  |   343 ms / 0.34 s  |                45  |                153  |
|  256 MiB  |    middle    |   798 ms / 0.80 s  |   822 ms / 0.82 s  |   682 ms / 0.68 s  |   702 ms / 0.70 s  |                46  |                190  |
|  256 MiB  |    high      |  1298 ms / 1.30 s  |  1308 ms / 1.31 s  |  1167 ms / 1.17 s  |  1195 ms / 1.19 s  |                45  |                178  |

</details>

<details>
<summary><strong>Wall‑clock Durations (no subtraction) — Scheme 1</strong></summary>

**Lower is better (ms / s). Decode columns show latency (ms).**

|    Size   |  Difficulty  |           enc f→f  |         dec f→out  |        enc in→out  |        dec in→out  |  decode file (ms)  |  decode stdin (ms)  |
| :-------: | :----------: | -----------------: | -----------------: | -----------------: | -----------------: | -----------------: | ------------------: |
|  256 MiB  |    low       |  1881 ms / 1.88 s  |  1840 ms / 1.84 s  |  1697 ms / 1.70 s  |  1719 ms / 1.72 s  |                48  |                133  |
|  256 MiB  |    middle    |  2103 ms / 2.10 s  |  2097 ms / 2.10 s  |  1953 ms / 1.95 s  |  2014 ms / 2.01 s  |                48  |                180  |
|  256 MiB  |    high      |  2534 ms / 2.53 s  |  2518 ms / 2.52 s  |  2450 ms / 2.45 s  |  2396 ms / 2.40 s  |                49  |                190  |

</details>

**Legend**
`enc f→f` = encrypt file→file • `dec f→out` = decrypt file→stdout • `enc in→out` = encrypt stdin→stdout • `dec in→out` = decrypt stdin→stdout.

**Method notes**
• CLI: `bun run cli:run`  • Difficulties: low/middle/high  • Size: 256 MiB  • Repeats: 1
• **KDF repeats = 3**, payload = 16 bytes. “Stream‑only” removes the measured KDF baseline for the respective difficulty; wall‑clock shows full end‑to‑end time.


---

## License

MIT
