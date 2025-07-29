import { $ } from "bun";
import { resolve } from "node:path";

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
  `--asset-naming=cryptit.index.[ext]`,
  `--outdir=${resolve(outdir, "cryptit.index.cjs")}`
);

await runBuild(
  entryBrowser,
  "--minify",
  "--target=browser",
  "--format=esm",
  "--sourcemap=external",
  "--external:commander",
  "--external:argon2",
  "--scope-hoist",
  `--asset-naming=cryptit.browser.min.[ext]`,
  `--outdir=${resolve(outdir, "cryptit.browser.min.js")}`
);

await runBuild(
  entryCLI,
  "--minify",
  "--format=cjs",
  "--target=node",
  "--sourcemap=external",
  `--outdir=${resolve(outdir, "cryptit.cli.cjs")}`,
  `--asset-naming=cryptit.cli.[ext]`
);

await runBuild(
  entryCLI,
  "--minify",
  "--format=esm",
  "--target=node",
  "--sourcemap=external",
  `--outdir=${resolve(outdir, "cryptit.cli.mjs")}`,
  `--asset-naming=cryptit.cli.[ext]`
);

await runBuild(
  entryCLI,
  "--compile",
  `--outfile=${resolve(outdir, "bin", "cryptit")}`
);

async function runBuild(entryFile, ...flags) {
  await $`bun build ${entryFile} ${flags}`;
}
