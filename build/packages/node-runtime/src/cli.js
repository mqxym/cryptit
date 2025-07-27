#!/usr/bin/env bun
// packages/node-runtime/src/cli.ts
import { Command } from "commander";
import { createReadStream, createWriteStream, } from "node:fs";
import { stdin, stdout, stderr, exit as processExit, } from "node:process";
import { Readable as NodeReadable, Writable as NodeWritable, } from "node:stream";
import { createCryptit } from "./index.js";
const PKG_VERSION = "0.2.0"; // keep in sync with root package.json
// ──────────────────────────────────────────────────────────────
//  ── Helper: silent pass-prompt ───────────────────────────────
// ──────────────────────────────────────────────────────────────
async function promptPass() {
    var _a;
    if (!stdin.isTTY)
        throw new Error("STDIN not a TTY; --pass required");
    stderr.write("Passphrase: ");
    (_a = stdin.setRawMode) === null || _a === void 0 ? void 0 : _a.call(stdin, true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let buf = "";
    return new Promise((resolve) => {
        function done() {
            var _a;
            (_a = stdin.setRawMode) === null || _a === void 0 ? void 0 : _a.call(stdin, false);
            stdin.pause();
            stderr.write("\n");
            stdin.off("data", onData);
            resolve(buf);
        }
        function onData(ch) {
            if (ch === "\u0003")
                processExit(130); // Ctrl-C
            if (ch === "\r" || ch === "\n")
                return done();
            if (ch === "\u0008" || ch === "\u007F") { // Backspace
                buf = buf.slice(0, -1);
                return;
            }
            buf += ch;
        }
        stdin.on("data", onData);
    });
}
function nodeToWeb(reader) {
    return NodeReadable.toWeb(reader);
}
function nodeToWebW(writer) {
    return NodeWritable.toWeb(writer);
}
async function readAllFromStdin() {
    const chunks = [];
    for await (const c of stdin)
        chunks.push(c);
    return Buffer.concat(chunks).toString("utf8");
}
// ──────────────────────────────────────────────────────────────
//  ── CLI definition ───────────────────────────────────────────
// ──────────────────────────────────────────────────────────────
const program = new Command()
    .name("cryptit")
    .description("AES-GCM / Argon2 encryption utility")
    .version(PKG_VERSION)
    .option("-p, --pass <passphrase>", "passphrase (prompt if omitted)")
    .option("-d, --difficulty <level>", "argon2 difficulty low|middle|high", "middle")
    .option("-s, --salt-strength <low|high>", "salt length difficulty", "high")
    .option("-c, --chunk-size <bytes>", "chunk size (bytes)", (v) => Number(v), 512 * 1024)
    .option("-v, --verbose", "increase verbosity", (_v, prev) => (prev !== null && prev !== void 0 ? prev : 0) + 1, 0);
// -----------------------------------------------------------------------------
// FILE encrypt / decrypt  (streaming, constant memory)
// -----------------------------------------------------------------------------
program.command("encrypt <src>")
    .description("encrypt file; use - for STDIN, --out - for STDOUT")
    .option("-o, --out <file>", "output file (default STDOUT)", "-")
    .action(async (src, cmd) => {
    var _a;
    const g = program.opts();
    const crypt = createCryptit({
        difficulty: g.difficulty,
        saltStrength: g.saltStrength,
        chunkSize: g.chunkSize,
    });
    const pass = (_a = g.pass) !== null && _a !== void 0 ? _a : (stdin.isTTY ? await promptPass()
        : (() => {
            stderr.write("Use --pass when piping data via STDIN\n");
            processExit(1);
        })());
    const rs = src === "-" ? stdin : createReadStream(src);
    const ws = cmd.out === "-" ? stdout : createWriteStream(cmd.out);
    const webRS = nodeToWeb(rs);
    const webWS = nodeToWebW(ws);
    const tf = await crypt.createEncryptionStream(pass);
    // Read side → Transform.writable   AND   Transform.readable → Write side
    await Promise.all([
        webRS.pipeTo(tf.writable),
        tf.readable.pipeTo(webWS)
    ]);
});
program.command("decrypt <src>")
    .description("decrypt file; use - for STDIN, --out - for STDOUT")
    .option("-o, --out <file>", "output file (default STDOUT)", "-")
    .action(async (src, cmd) => {
    var _a;
    const g = program.opts();
    const crypt = createCryptit({
        difficulty: g.difficulty,
        saltStrength: g.saltStrength,
        chunkSize: g.chunkSize,
    });
    const pass = (_a = g.pass) !== null && _a !== void 0 ? _a : await promptPass();
    const rs = src === "-" ? stdin : createReadStream(src);
    const ws = cmd.out === "-" ? stdout : createWriteStream(cmd.out);
    const webRS = nodeToWeb(rs);
    const webWS = nodeToWebW(ws);
    const tf = await crypt.createDecryptionStream(pass);
    await Promise.all([
        webRS.pipeTo(tf.writable),
        tf.readable.pipeTo(webWS)
    ]);
});
// -----------------------------------------------------------------------------
// TEXT encrypt / decrypt  (entire payload in memory)
// -----------------------------------------------------------------------------
program.command("encrypt-text [text]")
    .description("encrypt plaintext; omit arg to read from STDIN")
    .action(async (text) => {
    var _a;
    const g = program.opts();
    const crypt = createCryptit({
        difficulty: g.difficulty,
        saltStrength: g.saltStrength,
    });
    const pass = (_a = g.pass) !== null && _a !== void 0 ? _a : (stdin.isTTY ? await promptPass()
        : (() => {
            stderr.write("Use --pass when piping data via STDIN\n");
            processExit(1);
        })());
    const plain = text !== null && text !== void 0 ? text : (await readAllFromStdin());
    const cipher = await crypt.encryptText(plain, pass);
    stdout.write(cipher + "\n");
});
program.command("decrypt-text [b64]")
    .description("decrypt Base64 ciphertext; omit arg to read from STDIN")
    .action(async (b64) => {
    var _a;
    const g = program.opts();
    const crypt = createCryptit({
        difficulty: g.difficulty,
        saltStrength: g.saltStrength,
    });
    const pass = (_a = g.pass) !== null && _a !== void 0 ? _a : await promptPass();
    const data = b64 !== null && b64 !== void 0 ? b64 : (await readAllFromStdin()).trim();
    const plain = await crypt.decryptText(data, pass);
    stdout.write(plain + "\n");
});
program.parse();
//# sourceMappingURL=cli.js.map