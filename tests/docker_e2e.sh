#!/usr/bin/env bash
# End-to-end test for the cryptit Docker image.
set -euo pipefail
IFS=$'\n\t'

IMG="${IMG:-cryptit:test}"
DEBUG="${DEBUG:-0}"

# ---------- Logging (stderr only) ----------
timestamp() { date +"%Y-%m-%d %H:%M:%S%z"; }
log()       { printf "%s  %s\n" "$(timestamp)" "$*" >&2; }
section()   { printf "\n%s  === %s ===\n" "$(timestamp)" "$*" >&2; }
debug()     { [[ "$DEBUG" == "1" ]] && printf "%s  [debug] %s\n" "$(timestamp)" "$*" >&2 || true; }

# Run a command; on --debug it prints the exact command first.
run() {
  debug "run: $*"
  "$@"
}

# For binary pipelines where any stdout pollution would break things,
# we don’t echo the command even in debug.
run_quiet() {
  "$@"
}

# ---------- Workspace ----------
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK" || true; }
trap cleanup EXIT

# Container runs as non-root; make the mount writable.
chmod 0777 "$WORK"

section "Environment"
log "Using image: ${IMG}"
run docker version >/dev/null
run docker image inspect "$IMG" >/dev/null

section "Sanity checks"
log "Checking that --help runs"
run docker run --rm "$IMG" --help >/dev/null

log "Checking that --version looks like x.y.z"
run bash -c 'docker run --rm "'"$IMG"'" --version | grep -E "^[0-9]+\.[0-9]+\.[0-9]+$" >/dev/null'

section "Round-trip (text)"
PLAINTEXT_FILE="$WORK/plain.txt"
CIPHER_FILE="$WORK/cipher.b64"
DECRYPTED_FILE="$WORK/decrypted.txt"

echo "hello from ci $(date +%s)" > "$PLAINTEXT_FILE"

# Encrypt to Base64 text (stdout) and store in a file.
log "Encrypting plaintext to Base64"
run bash -c 'docker run --rm "'"$IMG"'" encrypt-text "$(cat "'"$PLAINTEXT_FILE"'")" --pass testpass > "'"$CIPHER_FILE"'"'

# Decrypt from Base64 file to plaintext file (preserve newlines exactly).
log "Decrypting Base64 back to plaintext"
run bash -c 'docker run --rm "'"$IMG"'" decrypt-text "$(cat "'"$CIPHER_FILE"'")" --pass testpass > "'"$DECRYPTED_FILE"'"'

# Compare exact bytes.
log "Comparing plaintext and decrypted output"
run cmp -s "$PLAINTEXT_FILE" "$DECRYPTED_FILE"

section "Round-trip (file via pipes)"
INPUT_FILE="$WORK/in.txt"
ENC_BIN="$WORK/out.enc"
OUT_TXT="$WORK/out.txt"

echo "file payload $(date +%s)" > "$INPUT_FILE"

log "Encrypting a file to stdout and capturing the ciphertext"
run bash -c 'docker run --rm -v "'"$WORK"'":/work -w /work "'"$IMG"'" \
  encrypt ./in.txt --pass testpass --out - > "'"$ENC_BIN"'"'

log "Decrypting ciphertext from stdin to a file"
run bash -c 'docker run --rm -i -v "'"$WORK"'":/work -w /work "'"$IMG"'" \
  decrypt - --pass testpass --out - < "'"$ENC_BIN"'" > "'"$OUT_TXT"'"'

log "Comparing original file and decrypted file (exact bytes)"
run cmp -s "$INPUT_FILE" "$OUT_TXT"

section "Header inspection"
log "Decoding header from a binary stream (fake-data → decode)"
run_quiet bash -c 'docker run --rm "'"$IMG"'" fake-data 1024 \
  | docker run --rm -i "'"$IMG"'" decode - \
  | grep -Eq "\"isChunked\"[[:space:]]*:[[:space:]]*false"'

log "Decoding header from a base64 stream (fake-data --base64 → decode)"
run_quiet bash -c 'docker run --rm "'"$IMG"'" fake-data 512 --base64 \
  | docker run --rm -i "'"$IMG"'" decode - \
  | grep -Eq "\"isChunked\"[[:space:]]*:[[:space:]]*false"'

section "Negative cases"
log "Invalid Base64 should fail with a non-zero exit code"
set +e
docker run --rm "$IMG" decrypt-text "not_base64!" --pass testpass >/dev/null 2>&1
RC=$?
set -e
if [[ $RC -eq 0 ]]; then
  log "Expected failure on invalid Base64, but exit code was 0"
  exit 1
fi

log "Write-guard should refuse paths outside the working directory"
mkdir -p "$WORK/sub"
set +e
docker run --rm -v "$WORK/sub":/work -w /work "$IMG" \
  encrypt-text "guard" --pass testpass --out ../leak.bin >/dev/null 2>&1
RC=$?
set -e
if [[ $RC -eq 0 ]]; then
  log "Expected refusal when attempting to write outside /work"
  exit 1
fi

section "Result"
log "All checks passed."