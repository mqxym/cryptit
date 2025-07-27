# @mqxym/cryptit

Modern, cross-platform AES-GCM + Argon2-id encryption for files **and** text.

* **Node 18+ / Bun 1+** – uses the native `argon2` addon & WebCrypto
* **Browser (evergreen)** – loads the tiny `argon2-browser` WASM module
* **CLI** – stream-encrypt large files without loading them in memory
* **TypeScript-first**, tree-shakable, ESM & CommonJS builds.

---

## Install

```bash
# with Bun (recommended)
bun add @mqxym/cryptit

# …or with npm / pnpm
npm i @mqxym/cryptit
```

---

## Quick start (Node / Bun)

```ts
import { createCryptit } from "@mqxym/cryptit";

const crypt = createCryptit({ difficulty: "middle" });
const passphrase = "correct horse battery staple";

const cipherB64 = await crypt.encryptText("hello world", passphrase);
const plainTxt  = await crypt.decryptText(cipherB64, passphrase);
console.log(plainTxt); // → "hello world"
```

### Encrypt / decrypt a file (streaming)

```ts
import { createCryptit } from "@mqxym/cryptit";
import { createReadStream, createWriteStream } from "node:fs";

const crypt = createCryptit();
const pass  = "hunter2";

const rs = createReadStream("movie.mkv");
const ws = createWriteStream("movie.enc");

await rs
  .pipeThrough(await crypt.createEncryptionStream(pass))
  .pipeTo(ws);

// ——— later ———
const drs = createReadStream("movie.enc");
const dws = createWriteStream("movie.mkv");

await drs
  .pipeThrough(await crypt.createDecryptionStream(pass))
  .pipeTo(dws);
```

---

## Browser usage

### Bundle with Vite / Webpack / esbuild

```ts
// app.ts
import { createCryptit } from "@mqxym/cryptit/browser";

const crypt = createCryptit({ saltStrength: "high" });

input.addEventListener("change", async (e) => {
  const file  = (e.target as HTMLInputElement).files![0];
  const blob  = await crypt.encryptFile(file, "mypw");
  downloadBlob(blob, file.name + ".enc");
});
```

> The `argon2-browser` WASM file is fetched lazily.
> Host it yourself:
>
> ```ts
> import * as a2 from "argon2-browser";
> a2.wasmURL = "/static/argon2.wasm";
> ```

### Script-tag fallback

```html
<script src="https://unpkg.com/@mqxym/cryptit/dist/browser.min.js"></script>
<script>
  const crypt = Cryptit.createCryptit();
  crypt.encryptText("hi", "pw").then(console.log);
</script>
```

---

## CLI

```bash
# one-off use
bunx @mqxym/cryptit encrypt notes.txt -o notes.enc -p "pw"

# or install globally
bun add -g @mqxym/cryptit          # -> `cryptit` in $PATH

# encrypt file
cat photo.jpg | cryptit encrypt - -p hunter2 > photo.enc

# decrypt
cryptit decrypt photo.enc -p hunter2 -o photo.jpg

# encrypt text
echo "secret" | cryptit encrypt-text -p pw
```

| Flag                       | Default  | Notes                                 |
| -------------------------- | -------- | ------------------------------------- |
| `-p, --pass`               | *prompt* | passphrase (hidden prompt if omitted) |
| `-d, --difficulty`         | middle   | Argon2 preset: `low / middle / high`  |
| `-s, --salt-strength`      | high     | `low` (8 B) or `high` (16 B) salt     |
| `-c, --chunk-size <bytes>` | 524288   | size of plaintext blocks              |
| `-v, -vv, …`               | 0        | increase verbosity                    |

Exit codes: **0** ok · **10** auth failure · **11** invalid header · **≥20** other error

---

## API surface

```ts
createCryptit(cfg?: EncryptionConfig) → Cryptit

interface EncryptionConfig {
  difficulty?: "low" | "middle" | "high"
  saltStrength?: "low" | "high"
  chunkSize?: number               // default 512 KiB
}

class Cryptit {
  encryptText(plain, pass): Promise<string>
  decryptText(b64, pass): Promise<string>

  encryptFile(file: Blob, pass): Promise<Blob>
  decryptFile(file: Blob, pass): Promise<Blob>

  createEncryptionStream(pass): Promise<TransformStream>
  createDecryptionStream(pass): Promise<TransformStream>
}
```

---

## Building from source

```bash
git clone https://github.com/mqxym/cryptit
cd cryptit
bun install
bun run build           # emits dist/ + native CLI binary
bun test                # Bun test runner with coverage
```

---

## Security notes

* AES-GCM 256 with 12-byte IV, 128-bit tag
* Argon2-id defaults: `middle` = `t=3`, `memory=64 MiB`
* Keys derived & held in-memory only; secrets zeroed where possible

---

## License

MIT
