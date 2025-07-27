// bun.build.js – executed by `bun build bun.build.js`
import { $ } from "bun";               // shell helper
import { resolve } from "node:path";

// shared opts
const outdir = "dist";
const base   = ["--outdir=" + outdir, "--minify"];

await $`bun build ${[
  ...base,
  "packages/core/src/index.ts",
  "packages/browser-runtime/src/index.ts"
]}`;

// compile a native executable for the CLI
await $`bun build packages/node-runtime/src/cli.ts --compile --outfile=${resolve(outdir, "cryptit")}`;