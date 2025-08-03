# Security Audit Report for @mqxym/cryptit

This document presents a detailed security audit of the `@mqxym/cryptit` project. The audit was conducted by SecuAI, following a comprehensive security checklist.

## 1. Project Scoping & Context

*   **Project Purpose:** `@mqxym/cryptit` is a modern, cross-platform TypeScript library for file and text encryption. It is designed to work in Node.js, Bun, and modern web browsers, providing a consistent API across environments. It also includes a command-line interface (CLI) for direct use from the shell.

*   **Languages, Frameworks, and Runtimes:**
    *   **Language:** TypeScript
    *   **Runtimes:** Node.js (>=18), Bun (>=1.0), Web Browsers (evergreen)
    *   **Build Tool:** Bun

*   **Major Modules and Libraries:**
    *   **Core Logic:** `packages/core` contains the main encryption, decryption, and key derivation logic.
    *   **Node.js Runtime:** `packages/node-runtime` provides the Node.js-specific implementation, including the CLI.
    *   **Browser Runtime:** `packages/browser-runtime` provides the browser-specific implementation.
    *   **Key Dependencies:**
        *   `@noble/ciphers`: For XChaCha20-Poly1305 implementation.
        *   `argon2`: Native Argon2 bindings for Node.js.
        *   `argon2-browser`: WASM-based Argon2 implementation for browsers.
        *   `commander`: For parsing command-line arguments.

*   **Dataflow Diagram:**

    **Encryption Flow (CLI Example):**
    ```
    [File/Stdin] -> [Read Stream] -> [Encryption Transform Stream] -> [Write Stream] -> [Encrypted File/Stdout]
           ^                                      ^
           |                                      |
    [Passphrase] -> [Argon2 KDF] -> [Derived Key] -> [AES-GCM / XChaCha20]
    ```

    **Decryption Flow (Library Example):**
    ```
    [Encrypted Blob] -> [Header Parsing] -> [Scheme/Salt/Difficulty]
           |
    [Passphrase] -> [Argon2 KDF] -> [Derived Key]
           |                                |
           +-----------------> [AES-GCM / XChaCha20 Decryption] -> [Decrypted Data]
    ```

*   **Project Version:** The current version of the project under review is **0.2.12**, as specified in `package.json`.

## 2. Threat Modeling

This section outlines potential threats to the `cryptit` library, categorized by attacker profile. Each threat is assigned a risk level based on its likelihood and potential impact.

### Attacker Profiles

*   **Remote Attacker:** An individual with no prior access to the system who attempts to break the encryption or find vulnerabilities in the library from the outside. Their goal is to decrypt sensitive data without knowing the passphrase.
*   **Malicious User:** A legitimate user of the library or CLI who intentionally provides malformed inputs to crash the application, bypass security controls, or induce unintended behavior.
*   **Supply-Chain Attacker:** An attacker who compromises one of the project's dependencies (e.g., `argon2`, `@noble/ciphers`) to inject malicious code.
*   **Man-in-the-Middle (MitM) Attacker:** An attacker positioned between the user's browser and the web server, who could intercept and modify the `argon2.wasm` file during download.

### Threat Analysis

| Threat Description                                                                   | Attacker Profile        | Likelihood | Impact | Risk   | Mitigation                                                                                                                              |
| ------------------------------------------------------------------------------------ | ----------------------- | ---------- | ------ | ------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| Brute-force attack on passphrase                                                     | Remote Attacker         | Low        | High   | Medium | Use of Argon2id, a strong KDF, makes brute-forcing computationally expensive. The risk depends on the strength of the user's passphrase. |
| Side-channel attack to leak key material                                             | Remote Attacker         | Low        | High   | Low    | The use of Web Crypto API and well-vetted libraries helps, but memory clearing (`zeroKey`) is critical. The `AESGCM.zeroKey` is empty.    |
| Exploiting a vulnerability in a dependency (e.g., `argon2`, `@noble/ciphers`)        | Supply-Chain Attacker   | Low        | High   | Medium | Regular dependency scanning and using reputable libraries.                                                                             |
| Tampering with the `argon2.wasm` file during download                                | MitM Attacker           | Low        | High   | Medium | Subresource Integrity (SRI) is not used for the WASM file download, making this a potential threat on insecure (HTTP) connections.   |
| Path traversal attack via the CLI's output file parameter                            | Malicious User          | Low        | Medium | Low    | The `assertWritable` function effectively mitigates this risk by restricting writes to the current working directory tree.             |
| Denial-of-Service (DoS) by providing a very large file or malformed input            | Malicious User          | Medium     | Low    | Low    | The streaming implementation helps mitigate memory exhaustion, but large chunk sizes could still be a concern.                          |
| Leaking sensitive data through error messages or logs                                | Malicious User          | Low        | Medium | Low    | The application uses custom error types and seems to handle errors gracefully, but verbose logging could be a risk.                   |

### Threat Diagrams

**Key Derivation Threat Diagram:**

```
[Passphrase] --(User Input)--> [Argon2id KDF] --(Derived Key)--> [Cipher]
      ^                                  ^
      |                                  |
(Attacker tries to brute-force)     (Attacker tries to find implementation flaws)
```

**File Encryption Threat Diagram (Streaming):**

```
[Plaintext Stream] -> [Encrypt Transform] -> [Ciphertext Stream]
        ^                      ^                       ^
        |                      |                       |
(Attacker has no access)  (Attacker tries to tamper with the stream or exploit implementation bugs)
```

## 3. Cryptographic Review

This section reviews the cryptographic primitives and practices used in the `cryptit` library.

### Key Derivation (KDF)

*   **Algorithm:** The library uses **Argon2id**, which is a strong, memory-hard key derivation function and an excellent choice for passphrase hashing.
*   **Implementations:**
    *   **Node.js:** Uses the native `argon2` package, which provides good performance and security.
    *   **Browser:** Uses `argon2-browser`, a WASM-based implementation.
*   **Parameters:** The library offers `low`, `middle`, and `high` difficulty presets, which is a good practice. However, the parameters for Scheme 0 (the default) are relatively low (`parallelism: 1`). While this is necessary for browser compatibility, it reduces the cost of brute-force attacks.
*   **Salt:** A random salt (12 or 16 bytes) is generated for each encryption, which is correct. The salt is provided by the Web Crypto API's `getRandomValues`, which is a secure source of randomness.

### Symmetric Encryption

*   **Scheme 0 (AES-GCM):**
    *   **Algorithm:** AES-256-GCM is a standard and secure authenticated encryption cipher.
    *   **Implementation:** Uses the Web Crypto API, which is the recommended approach.
    *   **IV:** A 12-byte (96-bit) IV is generated for each encryption using `getRandomValues`. This is the recommended IV size for AES-GCM.
    *   **Key Wiping:** The `zeroKey` method in `AESGCM.ts` is **empty**. While the `CryptoKey` is managed by the Web Crypto API and marked as non-extractable, it's better to have an explicit key wiping mechanism if possible. This is a **medium-severity** finding.

*   **Scheme 1 (XChaCha20-Poly1305):**
    *   **Algorithm:** XChaCha20-Poly1305 is an excellent choice, especially for streaming encryption, due to its larger nonce size.
    *   **Implementation:** Uses the `@noble/ciphers` library, which is a well-regarded, audited cryptography library.
    *   **Nonce:** A 24-byte nonce is generated for each encryption using `getRandomValues`, which is correct.
    *   **Key Management:** The key is marked as `extractable` to be used with `@noble/ciphers`. The `README.md` correctly warns about this. The `zeroKey` method correctly wipes the exported key material from memory.

### Header Format

*   The library uses a custom binary header to store the scheme, difficulty, and salt.
*   The header format is simple and seems robust. It correctly includes all necessary information for decryption.
*   The `decodeHeader` function performs basic length checks, which helps prevent parsing errors with truncated inputs.

### Randomness

*   All cryptographic randomness (for salts and IVs/nonces) is sourced from the environment's `CryptoProvider`, which should be the Web Crypto API's `crypto.getRandomValues`. This is the correct and most secure way to obtain randomness in modern JavaScript environments.

## 4. Input Validation & Error Handling

This section assesses how the library handles user input and exceptional conditions.

### Public API Validation

*   The public methods in the `Cryptit` class generally perform good input validation. For example, `setChunkSize` ensures the input is a positive integer.
*   The library correctly handles both `string` and `Uint8Array` inputs for plaintext.
*   The `decryptText` method checks for a valid Base64 input before attempting to decrypt.

### CLI Input Validation

*   The CLI uses the `commander` library, which provides robust parsing and validation of command-line arguments.
*   The `--scheme`, `--difficulty`, `--salt-strength`, and `--chunk-size` options all have parsers that validate the input.
*   The `assertWritable` function provides strong protection against path traversal attacks by ensuring the output path is within the current working directory tree. This is a significant security feature.

### Boundary Conditions

*   **Zero-byte files:** The library correctly handles the encryption and decryption of empty files. An encrypted empty file consists of only a header.
*   **Large files:** The use of streaming APIs for file encryption and decryption is an excellent design choice, as it allows the library to handle large files without consuming excessive memory.
*   **Malformed headers:** The `decodeHeader` function has basic checks for header length and the start byte, which helps to reject malformed headers early.

### Error Handling

*   The library defines a set of custom error classes (`EncryptionError`, `DecryptionError`, `InvalidHeaderError`, etc.), which is good for structured error handling.
*   The error messages are generally informative without being overly verbose. For example, the generic "Decryption failed: wrong passphrase or corrupted ciphertext" message prevents an attacker from distinguishing between a wrong key and a tampered ciphertext.
*   The CLI has global exception handlers that catch unhandled errors and exit gracefully, writing error messages to `stderr`. This is the correct behavior for a CLI tool.
*   Verbose logging (levels 2-4) could potentially leak sensitive information about the cryptographic operations, but this is an opt-in feature for debugging and not enabled by default.

## 5. Dependency & Supply-Chain Analysis

This section analyzes the project's dependencies for potential security risks.

### Direct Dependencies

The project's direct dependencies are listed in `package.json`. The key dependencies are:

*   `@noble/ciphers`: A well-regarded cryptography library for the XChaCha20-Poly1305 implementation.
*   `argon2`: The native Node.js binding for Argon2.
*   `argon2-browser`: A WASM-based Argon2 implementation for browsers.
*   `commander`: A popular and robust library for command-line interfaces.
*   `tslib`: TypeScript runtime library.

### High-Risk Package Analysis

*   **`argon2` (native addon):** Native addons can be a source of vulnerabilities, as they involve C/C++ code. However, the `argon2` package is a widely used and well-maintained binding for the reference Argon2 implementation. The risk is considered **low**, but it's important to keep this package updated.
*   **`argon2-browser` (WASM):** This package bundles a WebAssembly binary. A supply-chain attack could replace this binary with a malicious one. The use of a lockfile (`bun.lock` or `package-lock.json`) is crucial to ensure that the same version of the package is used in all environments. Additionally, the WASM binary is loaded at runtime via a `fetch` call, which could be intercepted in a MitM attack if not served over HTTPS.

### Vulnerability Scan

A manual review of the dependencies did not reveal any known vulnerabilities in the currently used versions. However, for ongoing security, it is highly recommended to integrate an automated dependency scanning tool like `npm audit`, `snyk`, or Dependabot into the development workflow. The project already has a `dependabot.yml` file, which is excellent.

The use of a `bun.lock` file is a critical security measure, as it ensures that the exact same versions of all dependencies are used across all installations, mitigating the risk of a compromised dependency being introduced in a minor or patch version update.

## 6. Secure Coding Practices

This section evaluates the project's adherence to secure coding practices.

### TypeScript Usage

*   The project is written in TypeScript, which helps to prevent many common bugs.
*   The `tsconfig.json` files have `strict` mode enabled, which is a good practice.
*   However, there are several instances of `any` and type assertions in the codebase. For example, in `packages/core/src/index.ts`, the logger's level is set using `(this.log as any).level = level;`. While this might be necessary for practical reasons, it's important to minimize the use of `any` as it bypasses TypeScript's type safety.
*   The CLI code also uses `any` in a few places, for example, `(NodeReadable as any).toWeb(reader)`. This is likely due to limitations in the Node.js stream types.

### Memory and Buffer Handling

*   The library makes a good effort to clear sensitive data from memory. The `zeroizeString` function is used to wipe passphrases after key derivation.
*   The `XChaCha20Poly1305` implementation correctly zeroes out the key material with `this.key.fill(0)`.
*   **Finding:** The `AESGCM` implementation has an empty `zeroKey` method. This means the key material might not be cleared from memory after use. While the key is managed by the Web Crypto API and is non-extractable, this is still a potential risk.
*   Plaintext buffers are zeroed out after encryption in both cipher implementations, which is an excellent practice.

### Secure Randomness

*   The library correctly uses `crypto.getRandomValues` from the Web Crypto API to generate salts and IVs/nonces. This is the standard and secure way to obtain cryptographic randomness in JavaScript environments.

## 7. Performance & Resource Exhaustion

This section reviews the library for potential performance issues and resource exhaustion vulnerabilities.

### Streaming Implementation

*   The library's use of Web Streams (`TransformStream`, `ReadableStream`, `WritableStream`) for file encryption and decryption is a major strength. It allows for processing large files with a small, constant memory footprint, which is an effective defense against memory exhaustion DoS attacks.
*   The `chunkSize` is configurable, which gives users control over the trade-off between memory usage and performance.

### Denial-of-Service Risks

*   **Large Chunk Size:** While the `chunkSize` is configurable, a malicious user of the library could set a very large chunk size, potentially leading to memory issues. The CLI has a default chunk size, but if the library is used in a server-side application that accepts user-provided chunk sizes, this could be a risk. The application should validate and enforce a reasonable maximum chunk size.
*   **Argon2 Parameters:** The Argon2 parameters (time, memory, parallelism) can be configured. Setting these to very high values could be used to cause a DoS attack on a server that uses the library for passphrase verification. The application should enforce reasonable limits on these parameters if they are user-configurable. The library itself provides presets, which is a good practice.
*   **Regular Expressions:** The `decrypt-text` command uses a regex to validate Base64 input. While this regex is simple, complex regexes can sometimes be a source of ReDoS (Regular Expression Denial of Service) vulnerabilities. The current regex is not considered a risk.

## 8. CLI & Operational Security

This section focuses on the security of the command-line interface.

### Command-Line Parsing

*   The CLI uses the `commander` library, which is a mature and secure choice for argument parsing. It provides good validation and help generation.
*   The argument parsers for the options (`--scheme`, `--difficulty`, etc.) correctly validate the input types and ranges.

### File System Interaction

*   The `assertWritable` function is a key security control that effectively prevents path traversal attacks. It ensures that the output file is within the current working directory tree, which is a strong mitigation against writing to sensitive system files.
*   The CLI checks for the existence of input files before attempting to read them, which prevents errors.

### Passphrase Handling

*   The `promptPass` function securely reads the passphrase from the TTY by disabling echoing. This is a critical security feature to prevent shoulder-surfing.
*   The CLI correctly warns the user not to provide the passphrase via the `--pass` argument when using non-interactive shells, as it could be stored in the shell's history.

### Logging and Verbosity

*   The verbosity level is controlled by the `-v` flag, which is a good design.
*   By default, the logging level is 0 (errors only), which is a secure default.
*   Verbose logging levels (2-4) can leak information about the cryptographic operations, but they must be explicitly enabled by the user for debugging purposes.

## 9. Deployment & Configuration

This section reviews the project's build and deployment practices.

### WASM Loading

*   The `argon2-browser` implementation dynamically loads the `argon2.wasm` file via a `fetch` call to the relative path `argon2.wasm`.
*   **Finding:** This loading mechanism does not use Subresource Integrity (SRI). If the application is ever served over an insecure (HTTP) connection, a MitM attacker could intercept this `fetch` request and replace the WASM binary with a malicious one. This is a **medium-severity** finding.
*   To mitigate this, the application should use SRI to ensure the integrity of the downloaded WASM file. This would require the server to provide the hash of the file.

### Build Process

*   The project uses a custom build script `bun.build.js` with the Bun bundler.
*   The build script correctly generates different bundles for Node.js, browsers, and the CLI.
*   The build process seems straightforward and does not introduce any obvious security risks.

### CI/CD

*   The project has CI/CD pipelines configured in `.github/workflows` for continuous integration and releases.
*   The `ci.yml` workflow runs tests on every push, which is a good practice.
*   The project also has a `dependabot.yml` file, which is excellent for keeping dependencies up-to-date and patched for vulnerabilities.

## 10. Automated & Manual Test Coverage

This section reviews the project's test suite.

### Existing Test Coverage

*   The project has a good set of tests in the `__tests__` directories of the `core`, `browser-runtime`, and `node-runtime` packages.
*   The tests cover the main functionalities of the library, including:
    *   Text and file encryption/decryption.
    *   Streaming operations.
    *   Header parsing.
    *   Cross-runtime compatibility.
    *   CLI end-to-end tests.
    *   Ciphertext tampering (`cryptit.tamper.spec.ts`).

### Suggestions for New Tests

While the existing test coverage is good, the following test cases could be added to further improve the security posture of the library:

*   **Fuzz testing:** The public APIs and CLI could be fuzzed with a wide range of unexpected and malformed inputs to discover potential crashes or vulnerabilities.
*   **Malformed header tests:** More tests could be added to check how the library handles various forms of header tampering, such as incorrect lengths, invalid scheme IDs, or invalid difficulty codes.
*   **Resource exhaustion tests:** Tests could be designed to check how the library behaves when given very large chunk sizes or extreme Argon2 parameters.
*   **Key wiping tests:** While it's hard to test directly, it might be possible to write tests that check if the `zeroKey` methods are being called correctly.

## 11. Actionable Recommendations

This section provides a summary of the findings and actionable recommendations for improving the security of the `cryptit` library.

### Summary of Findings

| ID  | Finding                                             | Severity | Section                               |
| --- | --------------------------------------------------- | -------- | ------------------------------------- |
| 1   | Empty `zeroKey` method in `AESGCM` implementation   | Medium   | Cryptographic Review                  |
| 2   | Lack of Subresource Integrity (SRI) for WASM loader | Medium   | Deployment & Configuration            |

### Finding 1: Empty `zeroKey` method in `AESGCM`

*   **Severity:** Medium
*   **Description:** The `zeroKey` method in `packages/core/src/algorithms/encryption/aes-gmc/AESGCM.ts` is empty. This means that the AES-GCM key material, which is stored in a `CryptoKey` object, may not be cleared from memory after use. While the key is marked as non-extractable, relying solely on the garbage collector for clearing cryptographic keys is not a best practice.
*   **Recommendation:** It is not possible to directly "zero out" a non-extractable `CryptoKey`. A possible remediation is to re-architect the key handling to allow for more explicit key lifecycle management. However, a simpler approach is to document this behavior clearly and accept the risk, as the Web Crypto API is designed to handle key security. A more robust solution would be to avoid holding the `CryptoKey` in the class instance for longer than necessary.

### Finding 2: Lack of Subresource Integrity (SRI) for WASM loader

*   **Severity:** Medium
*   **Description:** The `argon2.wasm` file is loaded dynamically using `fetch` without Subresource Integrity (SRI). If the application is served over HTTP, a Man-in-the-Middle (MitM) attacker could inject a malicious WASM file.
*   **Recommendation:** Use SRI to ensure the integrity of the WASM file. This involves adding an `integrity` attribute to the `fetch` call.

    **Example:**
    ```typescript
    // In argon2-wrapper.ts

    // This would require the user of the library to provide the hash.
    // A better solution would be to bundle the WASM as a Base64 string.
    async function loadWasmWithSri(url: string, hash: string) {
      const response = await fetch(url, { integrity: `sha256-${hash}` });
      if (!response.ok) {
        throw new Error('Failed to load argon2.wasm');
      }
      return response.arrayBuffer();
    }
    ```
    A more practical solution for a library might be to bundle the WASM file as a Base64 string directly into the JavaScript bundle. This would increase the bundle size but would eliminate the need for a separate `fetch` call and the risk of MitM attacks.
