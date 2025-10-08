#!/usr/bin/env python3
"""
cli-performance-benchmark.py
============================

High-level
----------
Performance analysis for the **"cryptit"** CLI (Bun).

This script exercises the CLI end-to-end (invoking it the same way users do)
and reports two kinds of results:

1) **KDF baseline per difficulty** (Argon2 via `encrypt-text` of a tiny payload)
2) **Stream-only throughput** for large inputs, which **subtracts the KDF time**
   from each wall-clock measurement to isolate the pure streaming cost
   (MiB/s that excludes key derivation).

What is measured
----------------
For each `(difficulty, size)` case and repeat, the following operations are timed:

- `encrypt (file → file)`         — plaintext on disk → ciphertext on disk
- `decrypt (file → stdout)`       — ciphertext on disk → plaintext to /dev/stdout
- `encrypt (stdin → stdout)`      — plaintext piped via stdin → ciphertext to stdout
- `decrypt (stdin → stdout)`      — ciphertext piped via stdin → plaintext to stdout
- `decode (file path)`            — header decode when passing a path
- `decode (stdin)`                — header decode when passing data via stdin

All paths passed to the CLI are **relative to the repo root** (DEFAULT_ROOT in the CLI).
The script stores inputs/outputs in a timestamped workspace under the repository:

    tests/.cryptit-perf-work/<timestamp>/

Why subtract a KDF baseline?
----------------------------
Password-based schemes pay a fixed per-operation KDF cost (Argon2) independent of
input size. For large files this cost is negligible, but for smaller sizes it can
dominate. To make stream performance comparable across sizes and I/O modes, we:

1) Measure KDF time by calling `encrypt-text <16B payload> --pass <pass>`
2) Subtract that baseline (per difficulty) from each measured wall-clock duration
   before computing **stream-only throughput** in MiB/s.

This does not capture *only* KDF (there is minor `encrypt-text` overhead), but it
serves as a stable upper bound on the KDF cost and is sufficient for comparisons.

Requirements
------------
- Python **3.12+**
- **Bun** on `PATH`
- In the repo `package.json`, a script:
    "cli:run": "bun run packages/node-runtime/src/cli.ts"

The CLI is invoked via `bun` by default (customizable with `--cli-cmd`).

Quick start
-----------
From the repository root (where `package.json` lives):

    # Default sizes 64MiB, 256MiB; 1 repeat
    ./tests/cli-performance-benchmark.py

    # More sizes, multiple repeats, keep workspace
    ./tests/cli-performance-benchmark.py \
        --sizes 64MiB 256MiB 1GiB \
        --repeats 3 \
        --keep

    # Disable sparse files (write real zeros) and set a different CLI command
    CRYPTIT_PASS=yourpass \
    ./tests/cli-performance-benchmark.py \
        --no-sparse \
        --cli-cmd "bun run cli:run"

Environment variables (optional)
--------------------------------
- `CRYPTIT_SCHEME`   → default for `--scheme` (int)
- `CRYPTIT_PASS`     → default for `--passphrase`
- `CRYPTIT_CLI_CMD`  → default for `--cli-cmd` (e.g., "bun run cli:run")

Input size syntax
-----------------
`--sizes` accepts decimal (KB/MB/GB = 1000^n) and binary (KiB/MiB/GiB = 1024^n)
suffixes. Examples: `64MiB`, `256MB`, `1GiB`.

Workspace lifecycle
-------------------
- By default, the whole `tests/.cryptit-perf-work` directory is **removed**
  after the run.
- Pass `--keep` to retain artifacts for inspection.

Exit behavior
-------------
- Fails fast if the CLI version check (`--version`) or any operation returns a
  non-zero exit code, showing stderr from the child process.

Notes & caveats
---------------
- Sparse file creation is used by default to avoid writing large zero-filled files.
  Use `--no-sparse` when you want to include disk write time in preparation or
  when benchmarking on filesystems without sparse support.
- Reported times are measured with `time.perf_counter_ns()` (monotonic, high-res).
- The **stream-only** throughput is an approximation (KDF baseline upper bound),
  but it makes comparisons across difficulties and I/O modes more actionable.
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
from typing import List, Tuple, Dict

# ---------- time / formatting helpers ----------

def now_ns() -> int:
    """Return a monotonic, high-resolution timestamp in **nanoseconds**.

    Uses :func:`time.perf_counter_ns`, suitable for short wall-clock measurements.
    """
    return time.perf_counter_ns()

def fmt_dur(ns: int) -> Tuple[str, str]:
    """Format a duration in nanoseconds into human-friendly strings.

    Parameters
    ----------
    ns : int
        Duration in nanoseconds.

    Returns
    -------
    (str, str)
        A `(ms_string, seconds_string)` tuple, e.g. `("12.34 ms", "0.012 s")`.
    """
    ms = ns / 1_000_000.0
    s  = ns / 1_000_000_000.0
    return f"{ms:.2f} ms", f"{s:.3f} s"

def human_bytes(n: int) -> str:
    """Convert a byte count into a human-readable string using binary units.

    Examples
    --------
    >>> human_bytes(1048576)
    '1.00 MiB'
    """
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    i = 0
    f = float(n)
    while f >= 1024.0 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.2f} {units[i]}"

def parse_size(s: str) -> int:
    """Parse a size string into bytes.

    Supported suffixes (case-insensitive):
      - Decimal:  KB, MB, GB  (1000^n)
      - Binary : KiB, MiB, GiB (1024^n)

    If no suffix is present, a plain number is treated as bytes.

    Examples
    --------
    >>> parse_size("64MiB")
    67108864
    >>> parse_size("256MB")
    256000000
    """
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
    """Compute throughput in **MiB/s** given a byte count and duration (ns).

    Returns NaN if `ns <= 0`.
    """
    if ns <= 0:
        return float("nan")
    mib = bytes_count / (1024**2)
    sec = ns / 1_000_000_000.0
    return mib / sec

def check_available(bin_name: str) -> None:
    """Exit with an error if `bin_name` is not found on PATH."""
    if shutil.which(bin_name) is None:
        print(f"ERROR: '{bin_name}' not found on PATH", file=sys.stderr)
        sys.exit(1)

# ---------- CLI runner ----------

@dataclass
class Runner:
    """Thin wrapper around the `cryptit` CLI invocation.

    Parameters
    ----------
    base_cmd : list[str]
        The initial command vector, e.g. `["bun", "run", "cli:run"]`.
    passphrase : str
        Passphrase supplied to the CLI via `--pass`.
    scheme : int
        Cryptographic scheme ID (forwarded via `--scheme`).
    repo_root : pathlib.Path
        Working directory for all CLI calls (expected to be the repo root).
    """
    base_cmd: List[str]
    passphrase: str
    scheme: int
    repo_root: Path  # cwd for Bun; DEFAULT_ROOT in the CLI

    def _common(self, difficulty: str) -> List[str]:
        """Common CLI flags shared by most subcommands for a given difficulty."""
        return ["--difficulty", difficulty, "--scheme", str(self.scheme)]

    def run(self, args: List[str], *, stdin=None, stdout=None, stderr=subprocess.PIPE, check=True) -> int:
        """Execute the CLI with `args` and return the exit code.

        Raises
        ------
        RuntimeError
            If `check=True` and the command returns a non-zero exit code.
        """
        cmd = self.base_cmd + args
        proc = subprocess.run(cmd, cwd=str(self.repo_root), stdin=stdin, stdout=stdout, stderr=stderr)
        if check and proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{err}")
        return proc.returncode

    # ---------- timed operations (paths relative to repo_root unless *abs noted) ----------

    def encrypt_file_to_file(self, src_rel: str, out_rel: str, difficulty: str) -> int:
        """Encrypt a file on disk to another file on disk and return elapsed ns."""
        args = self._common(difficulty) + ["encrypt", src_rel, "--pass", self.passphrase, "--out", out_rel]
        t0 = now_ns(); self.run(args, stdout=subprocess.DEVNULL); return now_ns() - t0

    def decrypt_file_to_stdout(self, src_rel: str, difficulty: str) -> int:
        """Decrypt a file on disk and discard plaintext written to stdout; return ns."""
        args = self._common(difficulty) + ["decrypt", src_rel, "--pass", self.passphrase, "--out", "-"]
        t0 = now_ns(); self.run(args, stdout=subprocess.DEVNULL); return now_ns() - t0

    def encrypt_stdin_to_stdout(self, src_abs: Path, difficulty: str) -> int:
        """Encrypt data streamed via stdin to stdout; return elapsed ns.

        Note
        ----
        `src_abs` is opened locally and piped to the CLI as stdin.
        """
        args = self._common(difficulty) + ["encrypt", "-", "--pass", self.passphrase, "--out", "-"]
        with open(src_abs, "rb") as f:
            t0 = now_ns(); self.run(args, stdin=f, stdout=subprocess.DEVNULL); return now_ns() - t0

    def decrypt_stdin_to_stdout(self, cipher_abs: Path, difficulty: str) -> int:
        """Decrypt data streamed via stdin to stdout; return elapsed ns.

        Note
        ----
        `cipher_abs` is opened locally and piped to the CLI as stdin.
        """
        args = self._common(difficulty) + ["decrypt", "-", "--pass", self.passphrase, "--out", "-"]
        with open(cipher_abs, "rb") as f:
            t0 = now_ns(); self.run(args, stdin=f, stdout=subprocess.DEVNULL); return now_ns() - t0

    def decode_file(self, src_rel: str) -> int:
        """Decode (inspect) container header when passing a path; return elapsed ns."""
        args = ["decode", src_rel]
        t0 = now_ns(); self.run(args, stdout=subprocess.DEVNULL); return now_ns() - t0

    def decode_stdin(self, src_abs: Path) -> int:
        """Decode (inspect) container header when streaming via stdin; return elapsed ns."""
        args = ["decode", "-"]
        with open(src_abs, "rb") as f:
            t0 = now_ns(); self.run(args, stdin=f, stdout=subprocess.DEVNULL); return now_ns() - t0

    def kdf_encrypt_text_small(self, difficulty: str, payload: str) -> int:
        """Measure an upper bound of KDF time using `encrypt-text` on a tiny payload.

        This captures Argon2 key derivation plus minimal command overhead.
        Suitable as a per-difficulty baseline for subtracting from full operations.
        """
        args = self._common(difficulty) + ["encrypt-text", payload, "--pass", self.passphrase]
        t0 = now_ns(); self.run(args, stdout=subprocess.DEVNULL); return now_ns() - t0

# ---------- data classes ----------

@dataclass
class Metrics:
    """Nanosecond wall-clock durations for each operation in a single iteration.

    All fields are raw wall-clock times; **no** KDF subtraction is applied here.
    """
    encrypt_file_ns: int
    decrypt_file_ns: int
    encrypt_stdin_ns: int
    decrypt_stdin_ns: int
    decode_file_ns: int
    decode_stdin_ns: int

@dataclass
class CaseResult:
    """Aggregated results for a `(difficulty, size)` case across repeats."""
    size_bytes: int
    difficulty: str
    repeats: int
    metrics: List[Metrics] = field(default_factory=list)

    def add(self, m: Metrics) -> None:
        """Append one iteration's measurements."""
        self.metrics.append(m)

    def avg(self, attr: str) -> float:
        """Average a specific Metrics attribute (nanoseconds) across repeats."""
        vals = [getattr(m, attr) for m in self.metrics]
        return sum(vals) / len(vals) if vals else float("nan")

# ---------- file creation ----------

def make_test_file(path: Path, size_bytes: int, *, sparse: bool = True) -> None:
    """Create a file of `size_bytes` at `path`.

    Parameters
    ----------
    path : Path
        Destination path (parent directories are created as needed).
    size_bytes : int
        Desired file size in bytes.
    sparse : bool, default True
        If True, create a sparse file (seek-then-write one byte). This is fast and
        avoids writing large zero buffers. If False, write real zeros, which
        includes the actual disk I/O time during preparation.

    Notes
    -----
    - Sparse files depend on filesystem support.
    - The file contents are zeros in both cases; only creation behavior differs.
    """
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
    """Parse CLI arguments, orchestrate runs, and print summaries.

    Output structure
    ----------------
    1) Configuration echo
    2) KDF Baseline (per difficulty; averaged over `--kdf-repeats`)
    3) For each size:
         - Input preparation time
         - Per-iteration timings + stream-only throughput
    4) KDF Baseline Summary table
    5) Stream-only Throughput Summary (KDF-subtracted)
    6) Wall-clock Duration Summary (raw times, no subtraction)

    Cleanup
    -------
    Unless `--keep` is provided, the workspace directory is removed at the end.
    """
    parser = argparse.ArgumentParser(
        description="Cryptit CLI performance (with KDF baseline). Workspace under tests/.cryptit-perf-work"
    )
    parser.add_argument("--sizes", nargs="+", default=["64MiB", "256MiB"],
                        help="Space-separated sizes to test, e.g. 64MiB 256MiB 1GiB. "
                             "Accepts KiB/MiB/GiB (binary) or KB/MB/GB (decimal).")
    parser.add_argument("--repeats", type=int, default=1,
                        help="Averaging repeats per (difficulty,size). Default: 1.")
    parser.add_argument("--scheme", type=int, default=int(os.environ.get("CRYPTIT_SCHEME", "0")),
                        help="Scheme ID forwarded to the CLI (default from $CRYPTIT_SCHEME or 0).")
    parser.add_argument("--passphrase", default=os.environ.get("CRYPTIT_PASS", "testpass"),
                        help="Passphrase forwarded to the CLI (default from $CRYPTIT_PASS or 'testpass').")
    parser.add_argument("--cli-cmd", default=os.environ.get("CRYPTIT_CLI_CMD", "bun run cli:run"),
                        help='Command to invoke the CLI. Example: "bun run cli:run".')
    parser.add_argument("--no-sparse", action="store_true",
                        help="Write real zeros instead of creating sparse files.")
    parser.add_argument("--keep", action="store_true",
                        help="Keep workspace after run instead of cleaning it up.")
    parser.add_argument("--kdf-repeats", type=int, default=3,
                        help="Repeats for KDF baseline per difficulty (default 3).")
    parser.add_argument("--kdf-payload", default="0123456789abcdef",
                        help="Small plaintext used for KDF timing (default 16 bytes).")
    args = parser.parse_args()

    sizes = [parse_size(s) for s in args.sizes]
    difficulties = ["low", "middle", "high"]

    # If the CLI is run via bun, make sure it is available before we start.
    if args.cli_cmd.strip().startswith("bun "):
        check_available("bun")

    # Derive repository paths:
    # script is expected under tests/, so repo_root is one level up (where package.json lives).
    script_path = Path(__file__).resolve()
    tests_dir = script_path.parent
    repo_root = tests_dir.parent

    # Workspace is INSIDE the repo root to keep relative paths valid for the CLI.
    ts = time.strftime("%Y%m%d-%H%M%S")
    ws = repo_root / "tests" / ".cryptit-perf-work" / ts
    (ws / "in").mkdir(parents=True, exist_ok=True)
    (ws / "out").mkdir(parents=True, exist_ok=True)

    base_cmd = shlex.split(args.cli_cmd)
    runner = Runner(base_cmd=base_cmd, passphrase=args.passphrase, scheme=args.scheme, repo_root=repo_root)

    # Sanity: confirm the CLI is callable from repo_root and prints a version.
    try:
        runner.run(["--version"], stdout=subprocess.DEVNULL)
    except Exception as e:
        print("ERROR: CLI version check failed.", file=sys.stderr)
        print(str(e), file=sys.stderr)
        if not args.keep: shutil.rmtree(ws, ignore_errors=True)
        sys.exit(1)

    # ---- Configuration echo -------------------------------------------------
    print("\n=== Configuration ===")
    print(f"CLI command : {' '.join(base_cmd)}")
    print(f"Scheme      : {args.scheme}")
    print(f"Difficulties: {', '.join(difficulties)}")
    print(f"Sizes       : {', '.join(human_bytes(s) for s in sizes)}")
    print(f"Repeats     : {args.repeats}")
    print(f"Repo root   : {repo_root}")
    print(f"Workspace   : {ws} (inside repo root)")
    print(f"KDF repeats : {args.kdf_repeats}   payload: {len(args.kdf_payload)} bytes")
    print(f"Passphrase  : (hidden)\n")

    # ---- KDF baseline per difficulty ---------------------------------------
    print("=== KDF Baseline (encrypt-text of small payload) ===")
    kdf_ns_map: Dict[str, float] = {}
    for diff in difficulties:
        times = []
        for _ in range(args.kdf_repeats):
            ns = runner.kdf_encrypt_text_small(diff, args.kdf_payload)
            times.append(ns)
        avg_ns = sum(times) / len(times)
        kdf_ns_map[diff] = avg_ns
        ms, s = fmt_dur(int(avg_ns))
        print(f"diff={diff:<6}  KDF(avg of {args.kdf_repeats}) : {ms}  ({s})")
    print("")

    results: List[CaseResult] = []

    # ---- Generate inputs and run cases --------------------------------------
    for size in sizes:
        # Absolute paths for local file creation; CLI receives repo-relative paths.
        in_abs  = ws / "in" / f"in_{size}.bin"
        in_rel_cli  = os.path.relpath(in_abs, start=repo_root)

        print(f"=== Prepare input ({human_bytes(size)}) ===")
        print(f"Creating {in_abs} (sparse={not args.no_sparse})")
        t0 = now_ns(); make_test_file(in_abs, size, sparse=not args.no_sparse); tprep = now_ns() - t0
        ms, s = fmt_dur(tprep); print(f"File created in {ms}  ({s})")

        for difficulty in difficulties:
            case = CaseResult(size_bytes=size, difficulty=difficulty, repeats=args.repeats)
            kdf_ns = int(kdf_ns_map[difficulty])
            kdf_ms, kdf_s = fmt_dur(kdf_ns)
            print(f"\n=== Run: difficulty={difficulty}  size={human_bytes(size)}  repeats={args.repeats} ===")
            print(f"KDF baseline for this difficulty: {kdf_ms}  ({kdf_s})")

            for r in range(args.repeats):
                print(f"-- iteration {r+1}/{args.repeats}")

                cipher_abs = ws / "out" / f"cipher_{difficulty}_{size}_{r}.bin"
                cipher_rel_cli = os.path.relpath(cipher_abs, start=repo_root)

                # encrypt (file → file)
                t_enc_file = runner.encrypt_file_to_file(in_rel_cli, cipher_rel_cli, difficulty)
                enc_stream_ns = max(t_enc_file - kdf_ns, 1)  # avoid zero/negative
                ms_wall, s_wall = fmt_dur(t_enc_file)
                tp_stream = throughput_mibs(size, enc_stream_ns)
                print(f"encrypt (file→file)   : wall {ms_wall} ({s_wall}); stream-only ~ {tp_stream:.2f} MiB/s   [KDF {kdf_ms}]")

                # decrypt (file → stdout)
                t_dec_file = runner.decrypt_file_to_stdout(cipher_rel_cli, difficulty)
                dec_stream_ns = max(t_dec_file - kdf_ns, 1)
                ms_wall, s_wall = fmt_dur(t_dec_file)
                tp_stream = throughput_mibs(size, dec_stream_ns)
                print(f"decrypt (file→stdout) : wall {ms_wall} ({s_wall}); stream-only ~ {tp_stream:.2f} MiB/s   [KDF {kdf_ms}]")

                # encrypt (stdin → stdout)
                t_enc_stdin = runner.encrypt_stdin_to_stdout(in_abs, difficulty)
                enc_stdin_stream_ns = max(t_enc_stdin - kdf_ns, 1)
                ms_wall, s_wall = fmt_dur(t_enc_stdin)
                tp_stream = throughput_mibs(size, enc_stdin_stream_ns)
                print(f"encrypt (stdin→stdout): wall {ms_wall} ({s_wall}); stream-only ~ {tp_stream:.2f} MiB/s   [KDF {kdf_ms}]")

                # decrypt (stdin → stdout)
                t_dec_stdin = runner.decrypt_stdin_to_stdout(cipher_abs, difficulty)
                dec_stdin_stream_ns = max(t_dec_stdin - kdf_ns, 1)
                ms_wall, s_wall = fmt_dur(t_dec_stdin)
                tp_stream = throughput_mibs(size, dec_stdin_stream_ns)
                print(f"decrypt (stdin→stdout): wall {ms_wall} ({s_wall}); stream-only ~ {tp_stream:.2f} MiB/s   [KDF {kdf_ms}]")

                # decode (file path)
                t_dec_hdr_file = runner.decode_file(cipher_rel_cli)
                ms_wall, s_wall = fmt_dur(t_dec_hdr_file)
                print(f"decode (file path)    : {ms_wall}  ({s_wall})")

                # decode (stdin)
                t_dec_hdr_stdin = runner.decode_stdin(cipher_abs)
                ms_wall, s_wall = fmt_dur(t_dec_hdr_stdin)
                print(f"decode (stdin)        : {ms_wall}  ({s_wall})")

                case.add(Metrics(
                    encrypt_file_ns=t_enc_file,
                    decrypt_file_ns=t_dec_file,
                    encrypt_stdin_ns=t_enc_stdin,
                    decrypt_stdin_ns=t_dec_stdin,
                    decode_file_ns=t_dec_hdr_file,
                    decode_stdin_ns=t_dec_hdr_stdin,
                ))

            results.append(case)

    # ---- Summaries ----------------------------------------------------------
    print("\n=== KDF Baseline Summary (scheme={} ) ===".format(args.scheme))
    print(f"{'Difficulty':<10} {'KDF avg':>14}")
    for diff in difficulties:
        ns = kdf_ns_map[diff]
        ms = ns / 1_000_000.0
        s  = ns / 1_000_000_000.0
        print(f"{diff:<10} {ms:>8.2f} ms / {s:>6.3f} s")

    print("\n=== Stream-only Throughput Summary (KDF-subtracted) ===")
    colw = 14
    print(
        f"{'Difficulty':<10} {'Size':>10} "
        f"{'enc f→f':>{colw}} {'dec f→out':>{colw}} "
        f"{'enc in→out':>{colw}} {'dec in→out':>{colw}}"
    )
    for case in results:
        kdf_ns = kdf_ns_map[case.difficulty]
        def avg_stream_tp(ns_list: List[int], size_bytes: int) -> float:
            """Subtract KDF per run, convert to MiB/s, then average the throughputs."""
            if not ns_list: return float("nan")
            tps = []
            for ns in ns_list:
                adj = max(ns - kdf_ns, 1)
                tps.append(throughput_mibs(size_bytes, int(adj)))
            return sum(tps) / len(tps)

        enc_ff  = avg_stream_tp([m.encrypt_file_ns  for m in case.metrics], case.size_bytes)
        dec_ff  = avg_stream_tp([m.decrypt_file_ns  for m in case.metrics], case.size_bytes)
        enc_io  = avg_stream_tp([m.encrypt_stdin_ns for m in case.metrics], case.size_bytes)
        dec_io  = avg_stream_tp([m.decrypt_stdin_ns for m in case.metrics], case.size_bytes)

        print(
            f"{case.difficulty:<10} {human_bytes(case.size_bytes):>10} "
            f"{enc_ff:>{colw}.2f} {dec_ff:>{colw}.2f} "
            f"{enc_io:>{colw}.2f} {dec_io:>{colw}.2f}"
        )

    print("\n=== Wall-clock Duration Summary (no subtraction) ===")
    colw = 18
    def avgfmt(ns_avg: float) -> str:
        """Helper to format average durations consistently in ms / s."""
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

    # ---- Cleanup ------------------------------------------------------------
    if not args.keep:
        shutil.rmtree(repo_root / "tests" / ".cryptit-perf-work", ignore_errors=True)
        print(f"\n(cleaned) Removed workspace: {repo_root / 'tests' / '.cryptit-perf-work'}")
    else:
        print(f"\n(kept) Workspace retained at: {repo_root / 'tests' / '.cryptit-perf-work'}")

if __name__ == "__main__":
    main()