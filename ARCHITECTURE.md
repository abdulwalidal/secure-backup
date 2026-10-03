# Architecture and Security Specification

This document details the system architecture, component boundaries, and security model of Secure Backup.

---

## 1. System Architecture

```text
               +--------------------------------------+
               |      Desktop Webview (Native)        |
               |  (WebKitGTK Linux / WebView2 Windows)|
               |        TypeScript / HTML / CSS       |
               +-------------------+------------------+
                                   |
                       Tauri IPC Commands
                                   |
               +-------------------v------------------+
               |              Rust Core               |
               +-------------------+------------------+
                                   |
         +-------------------------+-------------------------+
         |                         |                         |
+--------v---------+      +--------v---------+      +--------v---------+
|  Backup Engine   |      |  Crypto Engine   |      |  Database Layer  |
|  (Scan & Pack)   |      |  (AES-GCM / KDF) |      |  (SQLite)        |
+------------------+      +------------------+      +------------------+
                                   |
                           Cloud Abstraction
                                   |
                          +--------v---------+
                          |  Cloud Provider  |
                          |  (Ciphertext)    |
                          +------------------+
```

---

## 2. Component Responsibilities

### Presentation Layer (`src/`)
- Handles user interactions, file selection dialog triggers, progress rendering, and status displays.
- Operates within an isolated, sandboxed Webview environment.
- Does not implement cryptographic algorithms directly and does not possess direct access to the host filesystem.

### Application Shell & IPC (`src-tauri/src/commands/`)
- Acts as the security boundary between the webview and the native host system.
- Enforces input validation on all paths and parameters before delegating to internal Rust services.
- Exposes only explicit, strongly-typed Tauri commands.

### Cryptographic Engine (`src-tauri/src/encryption/`)
- **Key Derivation Function (KDF):** Argon2id (v0x13) with memory cost 19 MiB, 2 iterations, 1 lane, and a 16-byte cryptographically secure random salt generated via OS RNG (`getrandom`).
- **Authenticated Cipher:** AES-256-GCM (NIST SP 800-38D). Uses unique 12-byte nonces per file and 16-byte GHASH authentication tags.
- **Binary File Container Format:**
  ```text
  +------------------+---------------+---------------+--------------------+
  | Magic (8 Bytes)  | Salt (16 B)   | Nonce (12 B)  | Ciphertext + Tag   |
  | SECBKP01         | Random Salt   | Unique Nonce  | AES-256-GCM (GHASH)|
  +------------------+---------------+---------------+--------------------+
  ```
- **Integrity Guarantee:** Any alteration to ciphertext, salt, or nonce results in immediate authentication failure and termination of the decryption process.

### Backup Engine (`src-tauri/src/backup/`)
- Traverses directories using non-following symlink semantics to avoid directory traversal vulnerabilities.
- Calculates streaming SHA-256 digests over 64 KB buffers to avoid memory spikes.
- Emits structured `manifest.json` containing file relative paths, sizes, timestamps, and hashes.

---

## 3. Threat Model and Mitigations

| Threat | Risk Assessment | Mitigation |
| ------ | --------------- | ---------- |
| Malicious Webview Injection | High | Strict Tauri 2 capabilities configuration. Webview cannot execute shell commands or read raw disk without explicit Rust commands. |
| Cloud Provider Compromise | High | Client-side zero-knowledge encryption. Cloud storage receives only ciphertext blobs and randomized filenames. Plaintext is never transmitted. |
| Ciphertext Tampering | High | AES-256-GCM authentication tags guarantee that altered or truncated ciphertext files fail decryption immediately. |
| Passphrase Brute-Force | High | Argon2id key derivation imposes memory and computational hardness against GPU and ASIC cracking attempts. |
| Unintended Information Leaks | Medium | Zero telemetry, analytics, or third-party network requests. Sensitive memory buffers are scoped and dropped immediately after use. |
