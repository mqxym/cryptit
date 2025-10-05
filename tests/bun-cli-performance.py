#!/usr/bin/env python3
"""
Performance analysis for the "cryptit" CLI using Bun.

Key points:
- Bun executes from the project root (package.json). The CLI's DEFAULT_ROOT is that directory.
- Workspace lives inside the repo: tests/.cryptit-perf-work/<timestamp>
- All paths passed to the CLI are RELATIVE TO THE REPO ROOT.
- We still open files via absolute paths for stdin benchmarks.

Measures (per difficulty x size):
  • encrypt (file → file)
  • decrypt (file → stdout)
  • encrypt (stdin → stdout)
  • decrypt (stdin → stdout)
  • decode (file path)
  • decode (stdin)
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

# ---------- time / formatting ----------
def now_ns() -> int:
    return time.perf_counter_ns()

def fmt_dur(ns: int) -> Tuple[str, str]:
    ms = ns / 1_000_000.0
    s  = ns / 1_000_000_000.0
    return f"{ms:.2f} ms", f"{s:.3f} s"

def human_bytes(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    i = 0
    f = float(n)
    while f >= 1024.0 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.2f} {units[i]}"

def parse_size(s: str) -> int:
    s = s.strip().lower()
    mult = 1
    if s.endswith("kib"): mult, s = 1024, s[:-3]
    elif s.endswith("kb"): mult, s = 1000, s[:-2]
    elif s.endswith("mib"): mult, s = 1024**2, s[:-3]
    elif s.endswith("mb"):  mult, s = 1000**2, s[:-2]
    elif s.endswith("gib"): mult, s = 1024**3, s[:-3]
    elif s.endswith("gb"):  mult, s = 1000**3, s[:-2]
    return int(float(s) * mult)

def throughput_mibs(bytes_count: int, ns: int) -> float:
    if ns <= 0:
        return float("nan")
    mib = bytes_count / (1024**2)
    sec = ns / 1_000_000_000.0
    return mib / sec

def check_available(bin_name: str) -> None:
    if shutil.which(bin_name) is None:
        print(f"ERROR: '{bin_name}' not found on PATH", file=sys.stderr)
        sys.exit(1)

# ---------- CLI runner ----------
@dataclass
class Runner:
    base_cmd: List[str]
    passphrase: str
    scheme: int
    repo_root: Path  # cwd for Bun; DEFAULT_ROOT in the CLI

    def _common(self, difficulty: str) -> List[str]:
        return ["--difficulty", difficulty, "--scheme", str(self.scheme)]

    def run(self, args: List[str], *, stdin=None, stdout=None, stderr=subprocess.PIPE, check=True) -> int:
        cmd = self.base_cmd + args
        proc = subprocess.run(cmd, cwd=str(self.repo_root), stdin=stdin, stdout=stdout, stderr=stderr)
        if check and proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{err}")
        return proc.returncode

    # timed operations (paths here must be RELATIVE TO repo_root for file args)
    def encrypt_file_to_file(self, src_rel: str, out_rel: str, difficulty: str) -> int:
        args = self._common(difficulty) + ["encrypt", src_rel, "--pass", self.passphrase, "--out", out_rel]
        t0 = now_ns(); self.run(args, stdout=subprocess.DEVNULL); return now_ns() - t0

    def decrypt_file_to_stdout(self, src_rel: str, difficulty: str) -> int:
        args = self._common(difficulty) + ["decrypt", src_rel, "--pass", self.passphrase, "--out", "-"]
        t0 = now_ns(); self.run(args, stdout=subprocess.DEVNULL); return now_ns() - t0

    def encrypt_stdin_to_stdout(self, src_abs: Path, difficulty: str) -> int:
        args = self._common(difficulty) + ["encrypt", "-", "--pass", self.passphrase, "--out", "-"]
        with open(src_abs, "rb") as f:
            t0 = now_ns(); self.run(args, stdin=f, stdout=subprocess.DEVNULL); return now_ns() - t0

    def decrypt_stdin_to_stdout(self, cipher_abs: Path, difficulty: str) -> int:
        args = self._common(difficulty) + ["decrypt", "-", "--pass", self.passphrase, "--out", "-"]
        with open(cipher_abs, "rb") as f:
            t0 = now_ns(); self.run(args, stdin=f, stdout=subprocess.DEVNULL); return now_ns() - t0

    def decode_file(self, src_rel: str) -> int:
        args = ["decode", src_rel]
        t0 = now_ns(); self.run(args, stdout=subprocess.DEVNULL); return now_ns() - t0

    def decode_stdin(self, src_abs: Path) -> int:
        args = ["decode", "-"]
        with open(src_abs, "rb") as f:
            t0 = now_ns(); self.run(args, stdin=f, stdout=subprocess.DEVNULL); return now_ns() - t0

# ---------- data classes ----------
@dataclass
class Metrics:
    encrypt_file_ns: int
    decrypt_file_ns: int
    encrypt_stdin_ns: int
    decrypt_stdin_ns: int
    decode_file_ns: int
    decode_stdin_ns: int

@dataclass
class CaseResult:
    size_bytes: int
    difficulty: str
    repeats: int
    metrics: List[Metrics] = field(default_factory=list)
    def add(self, m: Metrics) -> None: self.metrics.append(m)
    def avg(self, attr: str) -> float:
        vals = [getattr(m, attr) for m in self.metrics]
        return sum(vals) / len(vals) if vals else float("nan")

# ---------- file creation ----------
def make_test_file(path: Path, size_bytes: int, *, sparse: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if sparse:
        with open(path, "wb") as f:
            if size_bytes > 0:
                f.seek(size_bytes - 1)
                f.write(b"\0")
        return
    buf = b"\0" * (1024 * 1024)
    remaining = size_bytes
    with open(path, "wb", buffering=1024 * 1024) as f:
        while remaining > 0:
            n = min(len(buf), remaining)
            f.write(buf[:n]); remaining -= n

# ---------- main ----------
def main() -> None:
    parser = argparse.ArgumentParser(description="Cryptit CLI performance (workspace under tests/.cryptit-perf-work)")
    parser.add_argument("--sizes", nargs="+", default=["64MiB", "256MiB"], help="e.g. 64MiB 256MiB 1GiB")
    parser.add_argument("--repeats", type=int, default=1, help="averaging repeats per case")
    parser.add_argument("--scheme", type=int, default=int(os.environ.get("CRYPTIT_SCHEME", "0")))
    parser.add_argument("--passphrase", default=os.environ.get("CRYPTIT_PASS", "testpass"))
    parser.add_argument("--cli-cmd", default=os.environ.get("CRYPTIT_CLI_CMD", "bun run cli:run"),
                        help="default: bun run cli:run")
    parser.add_argument("--no-sparse", action="store_true", help="write zeros instead of sparse files")
    parser.add_argument("--keep", action="store_true", help="keep workspace after run")
    args = parser.parse_args()

    sizes = [parse_size(s) for s in args.sizes]
    difficulties = ["low", "middle", "high"]

    if args.cli_cmd.strip().startswith("bun "):
        check_available("bun")

    # script dir and REPO ROOT
    script_path = Path(__file__).resolve()
    tests_dir = script_path.parent
    repo_root = tests_dir.parent  # project root (package.json)
    # workspace INSIDE repo root:
    ts = time.strftime("%Y%m%d-%H%M%S")
    ws = repo_root / "tests" / ".cryptit-perf-work" / ts
    (ws / "in").mkdir(parents=True, exist_ok=True)
    (ws / "out").mkdir(parents=True, exist_ok=True)

    base_cmd = shlex.split(args.cli_cmd)
    runner = Runner(base_cmd=base_cmd, passphrase=args.passphrase, scheme=args.scheme, repo_root=repo_root)

    # version check from repo root
    try:
        runner.run(["--version"], stdout=subprocess.DEVNULL)
    except Exception as e:
        print("ERROR: CLI version check failed.", file=sys.stderr)
        print(str(e), file=sys.stderr)
        if not args.keep: shutil.rmtree(ws, ignore_errors=True)
        sys.exit(1)

    print("\n=== Configuration ===")
    print(f"CLI command : {' '.join(base_cmd)}")
    print(f"Scheme      : {args.scheme}")
    print(f"Difficulties: {', '.join(difficulties)}")
    print(f"Sizes       : {', '.join(human_bytes(s) for s in sizes)}")
    print(f"Repeats     : {args.repeats}")
    print(f"Repo root   : {repo_root}")
    print(f"Workspace   : {ws} (inside repo root)")
    print(f"Passphrase  : (hidden)\n")

    results: List[CaseResult] = []

    for size in sizes:
        # ABS paths in workspace
        in_abs  = ws / "in" / f"in_{size}.bin"
        # RELATIVE paths from repo root (this is what the CLI must see)
        in_rel_cli  = os.path.relpath(in_abs, start=repo_root)

        print(f"=== Prepare input ({human_bytes(size)}) ===")
        print(f"Creating {in_abs} (sparse={not args.no_sparse})")
        t0 = now_ns(); make_test_file(in_abs, size, sparse=not args.no_sparse); tprep = now_ns() - t0
        ms, s = fmt_dur(tprep); print(f"File created in {ms}  ({s})")

        for difficulty in difficulties:
            case = CaseResult(size_bytes=size, difficulty=difficulty, repeats=args.repeats)
            print(f"\n=== Run: difficulty={difficulty}  size={human_bytes(size)}  repeats={args.repeats} ===")

            for r in range(args.repeats):
                print(f"-- iteration {r+1}/{args.repeats}")

                cipher_abs = ws / "out" / f"cipher_{difficulty}_{size}_{r}.bin"
                cipher_rel_cli = os.path.relpath(cipher_abs, start=repo_root)

                # encrypt (file → file) | src: REL to repo root, out: REL to repo root
                t_enc_file = runner.encrypt_file_to_file(in_rel_cli, cipher_rel_cli, difficulty)
                ms, s = fmt_dur(t_enc_file); tp = throughput_mibs(size, t_enc_file)
                print(f"encrypt (file→file)   : {ms}  ({s})   ~ {tp:.2f} MiB/s")

                # decrypt (file → stdout) | src: REL to repo root
                t_dec_file = runner.decrypt_file_to_stdout(cipher_rel_cli, difficulty)
                ms, s = fmt_dur(t_dec_file); tp = throughput_mibs(size, t_dec_file)
                print(f"decrypt (file→stdout) : {ms}  ({s})   ~ {tp:.2f} MiB/s")

                # encrypt (stdin → stdout) | stdin from ABS input path
                t_enc_stdin = runner.encrypt_stdin_to_stdout(in_abs, difficulty)
                ms, s = fmt_dur(t_enc_stdin); tp = throughput_mibs(size, t_enc_stdin)
                print(f"encrypt (stdin→stdout): {ms}  ({s})   ~ {tp:.2f} MiB/s")

                # decrypt (stdin → stdout) | stdin from ABS cipher path
                t_dec_stdin = runner.decrypt_stdin_to_stdout(cipher_abs, difficulty)
                ms, s = fmt_dur(t_dec_stdin); tp = throughput_mibs(size, t_dec_stdin)
                print(f"decrypt (stdin→stdout): {ms}  ({s})   ~ {tp:.2f} MiB/s")

                # decode (file path) | REL to repo root
                t_dec_hdr_file = runner.decode_file(cipher_rel_cli)
                ms, s = fmt_dur(t_dec_hdr_file)
                print(f"decode (file path)    : {ms}  ({s})")

                # decode (stdin) | ABS path
                t_dec_hdr_stdin = runner.decode_stdin(cipher_abs)
                ms, s = fmt_dur(t_dec_hdr_stdin)
                print(f"decode (stdin)        : {ms}  ({s})")

                case.add(Metrics(
                    encrypt_file_ns=t_enc_file,
                    decrypt_file_ns=t_dec_file,
                    encrypt_stdin_ns=t_enc_stdin,
                    decrypt_stdin_ns=t_dec_stdin,
                    decode_file_ns=t_dec_hdr_file,
                    decode_stdin_ns=t_dec_hdr_stdin,
                ))

            results.append(case)

    # summary
    print("\n=== Summary (averages) ===")
    colw = 18
    def avgfmt(ns_avg: float) -> str:
        ms = ns_avg / 1_000_000.0; s = ns_avg / 1_000_000_000.0
        return f"{ms:.0f} ms / {s:.2f} s"

    print(
        f"{'Difficulty':<10} {'Size':>10} "
        f"{'enc file→file':>{colw}} {'dec file→out':>{colw}} "
        f"{'enc in→out':>{colw}} {'dec in→out':>{colw}} "
        f"{'decode file':>{colw}} {'decode stdin':>{colw}}"
    )
    for case in results:
        def _avg(attr: str) -> float:
            vals = [getattr(m, attr) for m in case.metrics]
            return sum(vals) / len(vals) if vals else float("nan")
        print(
            f"{case.difficulty:<10} {human_bytes(case.size_bytes):>10} "
            f"{avgfmt(_avg('encrypt_file_ns')):>{colw}} {avgfmt(_avg('decrypt_file_ns')):>{colw}} "
            f"{avgfmt(_avg('encrypt_stdin_ns')):>{colw}} {avgfmt(_avg('decrypt_stdin_ns')):>{colw}} "
            f"{avgfmt(_avg('decode_file_ns')):>{colw}} {avgfmt(_avg('decode_stdin_ns')):>{colw}}"
        )

    if not args.keep:
        # remove the entire perf-work tree (safe: it's under tests/.cryptit-perf-work)
        shutil.rmtree(repo_root / "tests" / ".cryptit-perf-work", ignore_errors=True)
        print(f"\n(cleaned) Removed workspace: {repo_root / 'tests' / '.cryptit-perf-work'}")
    else:
        print(f"\n(kept) Workspace retained at: {repo_root / 'tests' / '.cryptit-perf-work'}")

if __name__ == "__main__":
    main()