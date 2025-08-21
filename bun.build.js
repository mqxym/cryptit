// bun.build.js
import { rmSync, copyFileSync, mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';

// Clean output dir
const outdir = "dist";

const outdirCLI = join(outdir, "cli");
const outdirBrowser = join(outdir, "browser");

rmSync(outdir, { recursive: true, force: true });
mkdirSync(outdir, { recursive: true });

// Bundles via Bun.build()

// Helper to check success
async function doBuild(opts) {
  const result = await Bun.build(opts);
  if (!result.success) {
    for (const log of result.logs) {
      console.error(log.text || log);
    }
    throw new Error("Build failed");
  }
}

// ---- Node runtime (ESM) ----
await doBuild({
  entrypoints: ["packages/node-runtime/src/index.ts"],
  outdir: outdir,
  minify: true,
  format: "esm",
  external: ["argon2-browser"],
  target: "node",
  naming: {
    entry: "cryptit.index.[ext]",
    chunk: "[name]-[hash].[ext]",
    asset: "[name]-[hash].[ext]",
  },
  sourcemap: "external",
});

// ---- Node runtime (CJS) ----
await doBuild({
  entrypoints: ["packages/node-runtime/src/index.ts"],
  outdir: outdir,
  minify: true,
  format: "cjs",
  external: ["argon2-browser"],
  target: "node",
  naming: {
    entry: "cryptit.index.cjs",
    chunk: "[name]-[hash].[ext]",
    asset: "[name]-[hash].[ext]",
  },
  sourcemap: "external",
});

// ---- CLI (CJS) ----
await doBuild({
  entrypoints: ["packages/node-runtime/src/cli.ts"],
  outdir: outdirCLI,
  minify: true,
  format: "cjs",
  external: ["argon2-browser"],
  target: "node",
  naming: {
    entry: "cryptit.cli.cjs",
    chunk: "[name]-[hash].[ext]",
    asset: "[name]-[hash].[ext]",
  },
  sourcemap: "external",
});

// ---- CLI (ESM) ----
await doBuild({
  entrypoints: ["packages/node-runtime/src/cli.ts"],
  outdir: outdirCLI,
  minify: true,
  format: "esm",
  external: ["argon2-browser"],
  target: "node",
  naming: {
    entry: "cryptit.cli.[ext]",
    chunk: "[name]-[hash].[ext]",
    asset: "[name]-[hash].[ext]",
  },
  sourcemap: "external",
});

// Compile CLI to standalone binary (fallback to CLI flag)
await Bun.spawn({
  cmd: [
    "bun",
    "build",
    "--compile",
    `--outfile=${resolve(outdir, "bin", "cryptit")}`,
    "packages/node-runtime/src/cli.ts",
  ],
});

// ---- Browser bundle ----
await doBuild({
  entrypoints: ["packages/browser-runtime/src/index.ts"],
  outdir: outdirBrowser,
  minify: true,
  format: "esm",
  external: ["commander", "buffer", "process", "argon2"],
  target: "browser",
  naming: {
    entry: "cryptit.browser.min.[ext]",
    chunk: "[name]-[hash].[ext]",
    asset: "[name].[ext]",
  },
  sourcemap: "external",
});

/*
// ---- Browser bundle ----
await doBuild({
  entrypoints: ["packages/browser-runtime/src/index.ts"],
  outdir: outdirBrowser,
  minify: true,
  format: "iife",
  external: ["commander", "buffer", "process", "argon2"],
  target: "browser",
  footer: "globalThis.createCryptit = createCryptit;",
  naming: {
    entry: "cryptit.browser.global.min.[ext]",
    chunk: "[name]-[hash].[ext]",
    asset: "[name].[ext]",
  },
  sourcemap: "external",
});*/

// Post-build WASM handling
const wasmSrc = join(outdirBrowser, "argon2.wasm");
const wasmDst = join("examples", "assets", "argon2.wasm");

const browserSrc = join(outdirBrowser, "cryptit.browser.min.js");
const browserDst = join("examples", "assets", "cryptit.browser.min.js");

copyFileSync(wasmSrc, wasmDst);
copyFileSync(browserSrc, browserDst);

console.log("All builds complete");