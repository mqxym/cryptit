# @mqxym/cryptit

[![Base CI](https://github.com/mqxym/cryptit/actions/workflows/base-ci.yml/badge.svg)](https://github.com/mqxym/cryptit/actions/workflows/base-ci.yml)

Modern, cross-platform encryption for both **files** *and* **text**.

* **Node 22 / Bun 1** - native `argon2` addon + WebCrypto
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
echo "secret" | cryptit encrypt-text  --pass-file ~/.secret_pass
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
| `--pass-file <file>`      | none    | read passphrase from a file (max 64 KiB) |
| `-d, --difficulty <l>`    | middle  | Argon2 preset        |
| `-S, --scheme <0-1>.`     | 0.      | Scheme preset        |
| `-s, --salt-strength <l>` | high    | 12 B vs 16 B salt    |
| `-c, --chunk-size <n>`    | 524 288 | plaintext block size |
| `-v, --verbose`           |  0 … 4  | repeat to increase   |

Exit codes: **0** success · **1** any failure (invalid header, auth, I/O …)

> [!NOTE]
> Prefer the prompt or `--pass-file`. Values passed through `--pass` can be visible
> in shell history and process listings before the CLI can redact its argument array.

---

## Versioned format

* Header: `0x01 | infoByte | salt`
* Decryptors pick the engine by the header’s scheme ⇒ **one CLI handles all registered schemes**.
* Header info bit 3 marks an `authenticated-v1` file/stream container.
* Authenticated streams bind every record to its zero-based ordinal, record type,
  encoded frame word, and exact header through AEAD additional data.
* Every authenticated stream ends with an authenticated empty terminal record.
  Missing, duplicated, reordered, or post-terminal records are rejected.

### Additional Authenticated Data

* Since version 1.0.0: Header data is authenticated.
* Since version 2.2.0: `encryptText()` uses 8-bit padding before AEAD, which is also tagged in AAD.

### Compatibility

* New file and stream writes use `authenticated-v1` framing by default. Current
  readers continue to decrypt all unmarked legacy containers.
* Older Cryptit releases cannot read authenticated streams. During a migration,
  create a writer with `{ streamFormat: "legacy" }` when old readers must consume
  newly encrypted files. Legacy framing does not authenticate record order or a
  terminal record and should only be used for that compatibility requirement.
  Re-encrypt legacy containers with the default format when old-reader support is
  no longer required.
* `Cryptit.decodeData()` reports `format` and `authenticated` for chunked payloads.
* Services accepting untrusted ciphertext can set
  `{ maxDecryptionDifficulty: "low" | "middle" | "high" }` to reject a more
  expensive Argon2 profile before key derivation. The compatible default is `high`.

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
* Argon2-id presets (low / middle / high); configured memory values are in KiB,
  giving the current schemes 64-96 MiB memory costs
* Salts generated per-ciphertext; never reused
* AES-GCM refuses more than 2^32 encryption invocations with one loaded
  `CryptoKey`. Loading a different key starts an independent invocation budget.
* File/stream records are sequence-authenticated and require an authenticated end marker
* Mutable cipher state is isolated per operation and keys are cleared on completion or failure
* CLI file output is written to a restrictive same-directory temporary file and
  renamed into place only after the complete operation succeeds
* Custom `CryptoProvider` implementations are trusted to supply cryptographically
  secure randomness and a conforming WebCrypto implementation

For stdout decryption, consumers must treat emitted bytes as provisional until the
command exits successfully. A terminal authentication failure cannot retract bytes
already consumed from a pipe.

Authentication of an individual stream record does not by itself prove that the
whole stream is complete. Successful completion requires validation of the final
authenticated empty terminal record. See [SECURITY.md](SECURITY.md) for reporting
instructions and the complete security boundary.

---

## CLI Benchmarks (Cryptit 2.5.0, Bun 1.4.2, macOS, M3 Pro)

> **TL;DR**
> • **Scheme 0** (AES‑GCM/SubtleCrypto) is much faster for streaming: **peak ~1,015 MiB/s** (encrypt stdin→stdout, 1 GiB, *high*).
> • **Scheme 1** (XChaCha20‑Poly1305) peaks **~169 MiB/s**.
> • KDF cost is now measured separately and **not** included in “stream‑only” throughput below.

---

#### KDF Baseline (avg of 10, encrypt‑text 16 B payload)

| Difficulty | KDF avg (Scheme 0) | KDF avg (Scheme 1) |
| :--------: | -----------------: | -----------------: |
|     low    |         138.72 ms  |         115.78 ms  |
|   middle   |         451.63 ms  |         172.52 ms  |
|    high    |         826.76 ms  |         300.12 ms  |

<details>
<summary><strong>Stream‑only Throughput (KDF‑subtracted) — Scheme 0</strong></summary>

**Higher is better (MiB/s).**

|    Size   |  Difficulty  |  enc f→f  |  dec f→out  |   enc in→out  |  dec in→out  |
| :-------: | :----------: | --------: | ----------: | ------------: | -----------: |
|    1 GiB  |    low       |   580.74  |     630.70  |       919.22  |      828.95  |
|    1 GiB  |    middle    |   562.16  |     690.75  |       977.37  |      878.60  |
|    1 GiB  |    high      |   555.89  |     704.89  |  **1014.75**  |      852.49  |

</details>

<details>
<summary><strong>Stream‑only Throughput (KDF‑subtracted) — Scheme 1</strong></summary>

**Higher is better (MiB/s).**

|    Size   |  Difficulty  |  enc f→f  |  dec f→out  |  enc in→out  |  dec in→out  |
| :-------: | :----------: | --------: | ----------: | -----------: | -----------: |
|    1 GiB  |    low       |   147.86  |     151.37  |  **168.96**  |      158.51  |
|    1 GiB  |    middle    |   152.17  |     151.74  |      167.54  |      163.03  |
|    1 GiB  |    high      |   132.74  |     133.44  |      152.44  |      144.00  |

</details>

<details>
<summary><strong>Wall‑clock Durations (no subtraction) — Scheme 0</strong></summary>

**Lower is better (ms / s). Decode columns show latency (ms).**

|    Size   |  Difficulty  |           enc f→f  |         dec f→out  |        enc in→out  |        dec in→out  |  decode file (ms)  |  decode stdin (ms)  |
| :-------: | :----------: | -----------------: | -----------------: | -----------------: | -----------------: | -----------------: | ------------------: |
|    1 GiB  |    low       |  1904 ms / 1.90 s  |  1784 ms / 1.78 s  |  1278 ms / 1.28 s  |  1385 ms / 1.39 s  |                86  |                626  |
|    1 GiB  |    middle    |  2280 ms / 2.28 s  |  1938 ms / 1.94 s  |  1502 ms / 1.50 s  |  1621 ms / 1.62 s  |                65  |                561  |
|    1 GiB  |    high      |  2673 ms / 2.67 s  |  2284 ms / 2.28 s  |  1853 ms / 1.85 s  |  2052 ms / 2.05 s  |                65  |                566  |

</details>

<details>
<summary><strong>Wall‑clock Durations (no subtraction) — Scheme 1</strong></summary>

**Lower is better (ms / s). Decode columns show latency (ms).**

|    Size   |  Difficulty  |           enc f→f  |         dec f→out  |        enc in→out  |        dec in→out  |  decode file (ms)  |  decode stdin (ms)  |
| :-------: | :----------: | -----------------: | -----------------: | -----------------: | -----------------: | -----------------: | ------------------: |
|    1 GiB  |    low       |  7049 ms / 7.05 s  |  6884 ms / 6.88 s  |  6186 ms / 6.19 s  |  6578 ms / 6.58 s  |                79  |                585  |
|    1 GiB  |    middle    |  6907 ms / 6.91 s  |  6934 ms / 6.93 s  |  6301 ms / 6.30 s  |  6473 ms / 6.47 s  |                70  |                572  |
|    1 GiB  |    high      |  8027 ms / 8.03 s  |  7994 ms / 7.99 s  |  7043 ms / 7.04 s  |  7425 ms / 7.43 s  |                91  |                587  |

</details>

**Legend**
`enc f→f` = encrypt file→file • `dec f→out` = decrypt file→stdout • `enc in→out` = encrypt stdin→stdout • `dec in→out` = decrypt stdin→stdout.

**Method notes**
• CLI: `bun run cli:run`  • Difficulties: low/middle/high  • Size: 1 GiB  • Repeats: 5
• **KDF repeats = 10**, payload = 16 bytes. “Stream‑only” removes the measured KDF baseline for the respective difficulty; wall‑clock shows full end‑to‑end time.
• Values are arithmetic means. Results are end-to-end measurements and include runtime, OS, and storage variability.

---

## License

MIT
