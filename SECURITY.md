# Security Policy

## Supported Versions

Security fixes are provided for the latest published minor release. Users should update to the newest patch before reporting a vulnerability or requesting support.

## Reporting a Vulnerability

Do not disclose suspected vulnerabilities in a public issue, discussion, or pull request.

Use [GitHub private vulnerability reporting](https://github.com/mqxym/cryptit/security/advisories/new) to submit a report. Include:

- affected version and runtime;
- a minimal reproduction or malformed ciphertext, when safe to share;
- expected and observed behavior;
- known impact and attack prerequisites;
- whether the report or proof of concept may be shared with maintainers.

## Security Boundaries

- The built-in Node and browser providers must supply a cryptographically secure `getRandomValues` implementation. Custom `CryptoProvider` implementations are trusted to provide secure randomness and a conforming WebCrypto `SubtleCrypto` implementation.
- Scheme 1 exports a WebCrypto key into JavaScript memory because `@noble/ciphers` requires raw key bytes. Use scheme 0 when non-extractable key storage is required.
- New file and stream ciphertext uses authenticated-v1 framing. Explicit legacy framing remains available for compatibility, but it does not authenticate record order, record deletion, or stream completion.
- `acceptUnauthenticatedHeader` is an opt-in migration feature for pre-1.0 ciphertext. Do not enable it for untrusted input unless that compatibility is required.
- Values supplied through the CLI `--pass` option may be visible in shell history and operating-system process listings. Prefer an interactive prompt or `--pass-file` with restrictive file permissions.
- Decryption to stdout authenticates records before emitting them, but already-emitted records cannot be retracted if a later record or the terminal marker fails authentication. Consumers must treat output as provisional until the process exits successfully.
- JavaScript string erasure is best-effort because runtimes may retain immutable string copies. Mutable byte buffers used internally are cleared where their lifecycle permits.

## Encrypted Data Compatibility

Security patches should preserve current ciphertext decoding. A format or legacy-reader removal requires a major release, documented migration guidance, and compatibility-vector coverage.
