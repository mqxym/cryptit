import { $ } from "bun";
import { resolve, join, dirname } from 'node:path';

const outdir = "dist";

// Ensure clean output dir (optional)
await $`rm -rf ${outdir}`;

// === Build Targets ===

const entryNode     = "packages/node-runtime/src/index.ts"
const entryBrowser  = "packages/browser-runtime/src/index.ts";
const entryCLI      = "packages/node-runtime/src/cli.ts";

await runBuild(
  entryNode,
  "--minify",
  "--format=esm",
  "--external:argon2-browser",
  "--target=node",
  `--asset-naming=cryptit.index.[ext]`,
  "--sourcemap=external",
  `--outdir=${resolve(outdir, "cryptit.index.mjs")}`
);

await runBuild(
  entryNode,
  "--minify",
  "--format=cjs",
  "--target=node",
  "--sourcemap=external",
  "--external:argon2-browser",
  `--asset-naming=cryptit.index.[ext]`,
  `--outdir=${resolve(outdir, "cryptit.index.cjs")}`
);

await runBuild(
  entryCLI,
  "--minify",
  "--format=cjs",
  "--target=node",
  "--external:argon2-browser",
  "--sourcemap=external",
  `--outdir=${resolve(outdir, "cryptit.cli.cjs")}`,
  `--asset-naming=cryptit.cli.[ext]`
);

await runBuild(
  entryCLI,
  "--minify",
  "--format=esm",
  "--target=node",
  "--external:argon2-browser",
  "--sourcemap=external",
  `--outdir=${resolve(outdir, "cryptit.cli.mjs")}`,
  `--asset-naming=cryptit.cli.[ext]`
);

await runBuild(
  entryCLI,
  "--compile",
  "--external:argon2-browser",
  `--outfile=${resolve(outdir, "bin", "cryptit")}`
);

await runBuild(
  [entryBrowser],
  "--minify",
  "--target=browser",
  "--format=esm",
  "--sourcemap=external",
  "--external:commander",
  "--external:buffer",                      
  "--external:process",
  `--asset-naming=cryptit.browser.min.[ext]`,
  `--outdir=${resolve(outdir, "cryptit.browser.min.js")}`
);

async function runBuild(entryFile, ...flags) {
  await $`bun build ${entryFile} ${flags}`;
}

import { copyFileSync } from 'node:fs';

const outDir = resolve(__dirname, 'dist', 'cryptit.browser.min.js');

const srcWasm = join(outDir, 'cryptit.browser.min.wasm');
const dstWasm = join(outDir, 'argon2.wasm');
const dstWasm2 = join('examples', 'dist', 'argon2.wasm')

copyFileSync(srcWasm, dstWasm);
copyFileSync(srcWasm, dstWasm2);

await $`rm -rf ${join(outDir, 'cryptit.browser.min.wasm')}`;
await $`rm -rf ${join(outdir, 'cryptit.cli.cjs', 'cryptit.cli.wasm')}`;
await $`rm -rf ${join(outdir, 'cryptit.cli.mjs', 'cryptit.cli.wasm')}`;
await $`rm -rf ${join(outdir, 'cryptit.index.mjs', 'cryptit.index.wasm')}`;
await $`rm -rf ${join(outdir, 'cryptit.index.cjs', 'cryptit.index.wasm')}`;


