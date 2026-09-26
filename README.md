# Secure Backup

[![CI](https://github.com/abdulwalidal/secure-backup/actions/workflows/ci.yml/badge.svg)](https://github.com/abdulwalidal/secure-backup/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Tauri 2](https://img.shields.io/badge/Tauri-2.0-24c8db.svg)](https://tauri.app/)

Secure Backup is a lightweight, zero-knowledge desktop backup application built with Tauri 2, Rust, and TypeScript. It is designed to provide end-to-end client-side encryption, integrity-verified data snapshots, and seamless restoration across local and cloud environments while maintaining complete user privacy.

---

## Table of Contents

- [Core Principles](#core-principles)
- [How It Works](#how-it-works)
- [Technical Architecture](#technical-architecture)
- [Cryptographic Specifications](#cryptographic-specifications)
- [Repository Structure](#repository-structure)
- [Prerequisites & Build Guide](#prerequisites--build-guide)
- [End-to-End Roadmap](#end-to-end-roadmap)
- [Contributing](#contributing)
- [Security Disclosure](#security-disclosure)
- [License](#license)

---

## Core Principles

1. **Zero-Knowledge by Default:** Files are encrypted on the client device before touching local disk storage or leaving the host machine over the network. Plaintext files and master passwords are never transmitted, logged, or exposed to third-party providers.
2. **Deterministic Cryptographic Verification:** Every file is hashed using streaming SHA-256 to ensure byte-level integrity. Decryption verifies authenticated AEAD tags; modified, corrupted, or truncated files are rejected immediately.
3. **Minimal Resource Utilization:** Engineered in Rust with a native WebKit2GTK frontend via Tauri 2. Operates without the heavy memory overhead, background battery drain, or large runtime bundles common to Electron applications.
4. **Complete Privacy:** Contains zero analytics, diagnostic telemetry, third-party tracking libraries, or unsolicited external connections. Network operations only occur during user-initiated backup or restoration operations.

---

## How It Works

### The Backup Pipeline

```text
User selects directory
          |
Recursive filesystem scan (walkdir)
          |
Streamed SHA-256 integrity calculation
          |
Passphrase input -> Argon2id key derivation (random salt)
          |
AES-256-GCM authenticated encryption (unique 12-byte nonces)
          |
Write locked binary archive (.enc) & manifest to local storage
          |
[Upcoming] Upload ciphertext bundle to encrypted cloud storage
          |
[Upcoming] Index snapshot metadata in local SQLite database
```

### The Restoration Pipeline

```text
User selects historical snapshot
          |
[Upcoming] Download ciphertext archive from cloud / local storage
          |
Input master passphrase -> Argon2id key derivation
          |
Verify container headers, salt, and AES-GCM authentication tags
          |
Decrypt files back to original or chosen destination directory
          |
Re-verify recovered file SHA-256 hashes against snapshot manifest
```

---

## Technical Architecture

Secure Backup maintains a strict separation of concerns across presentation and native system operations:

```text
+-------------------------------------------------------------+
|                      Presentation Layer                     |
|            Vanilla TypeScript / HTML5 / Modern CSS          |
|  - Dashboard, Target Selection, Passphrase Input, History   |
+------------------------------+------------------------------+
                               |
                   Tauri 2 IPC Command Boundary
                               |
+------------------------------v------------------------------+
|                       Rust Core Engine                      |
|                                                             |
|  +---------------------+  +-------------------------------+ |
|  |    Backup Engine    |  |       Crypto Engine           | |
|  | - Directory scanner |  | - AES-256-GCM (AEAD)          | |
|  | - Manifest builder  |  | - Argon2id Key Derivation     | |
|  | - Archive packager  |  | - Streaming SHA-256 Hasher    | |
|  +---------------------+  +-------------------------------+ |
|                                                             |
|  +---------------------+  +-------------------------------+ |
|  |    Database Layer   |  |        Cloud Layer            | |
|  | - SQLite (rusqlite) |  | - Cloud provider abstraction  | |
|  | - Metadata & states |  | - S3 / B2 storage connectors  | |
|  +---------------------+  +-------------------------------+ |
+-------------------------------------------------------------+
```

---

## Cryptographic Specifications

Secure Backup adheres strictly to modern, audited cryptographic standards:

| Component | Standard / Algorithm | Parameters / Description |
| --------- | -------------------- | ------------------------ |
| Key Derivation | Argon2id (v0x13) | 19 MiB memory cost, 2 iterations, 1 lane, 16-byte random salt from OS CSPRNG (`getrandom`). Resistant to GPU/ASIC brute-force attacks. |
| Authenticated Cipher | AES-256-GCM | 256-bit derived key, unique 12-byte random nonce per file, 16-byte Poly1305 authentication tag. |
| Integrity Hashing | SHA-256 | Streaming 64 KB chunk buffered digest calculation for low memory consumption across files of any size. |
| Container Format | Custom Binary Header | `[ MAGIC: SECBKP01 (8B) \| Salt (16B) \| Nonce (12B) \| Ciphertext + Tag ]` |

---

## Repository Structure

```text
secure-backup/
├── src/                          # Frontend presentation layer
│   ├── index.html                # Application shell and view layouts
│   ├── styles.css                # Dark-themed desktop UI styles
│   └── main.ts                   # Event bindings, IPC invocations, and UI reactivity
├── src-tauri/                    # Core engine implementation in Rust
│   ├── src/
│   │   ├── backup/               # Filesystem traversal and snapshot creation
│   │   ├── commands/             # Tauri IPC command definitions and bridges
│   │   ├── encryption/           # AES-256-GCM and Argon2id cryptographic operations
│   │   ├── hashing/              # Streaming SHA-256 file checksums
│   │   ├── models/               # Domain structures, manifests, and command results
│   │   ├── lib.rs                # Application initialization and plugin wiring
│   │   └── main.rs               # Binary entry point
│   ├── capabilities/             # Tauri 2 least-privilege permission definitions
│   ├── Cargo.toml                # Rust dependencies and compiler optimization profiles
│   └── tauri.conf.json           # Window properties and runtime configuration
├── .github/                      # CI workflows, PR templates, and issue forms
├── ARCHITECTURE.md               # Technical design and security threat model
├── CONTRIBUTING.md               # Development workflow, conventions, and guidelines
├── CODE_OF_CONDUCT.md           # Professional community standards
├── SECURITY.md                   # Vulnerability disclosure policy
└── LICENSE                       # MIT License
```

---

## Prerequisites & Build Guide

### System Requirements (Linux / Ubuntu / Debian)

Install the required build dependencies and WebKit2GTK libraries:

```bash
sudo apt update
sudo apt install -y build-essential curl wget file libssl-dev libgtk-3-dev \
    libayatana-appindicator3-dev librsvg2-dev libwebkit2gtk-4.1-dev
```

### Development Environment

- **Node.js:** v18.0.0 or higher
- **npm:** v9.0.0 or higher
- **Rust:** v1.78.0 or higher

### Steps to Run

1. Clone the repository:
   ```bash
   git clone git@github.com:abdulwalidal/secure-backup.git
   cd secure-backup
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run the automated test suite:
   ```bash
   cargo test --manifest-path src-tauri/Cargo.toml
   ```

4. Launch the desktop application:
   ```bash
   npm run tauri dev
   ```

5. Compile a production release bundle:
   ```bash
   npm run tauri build
   ```

---

## End-to-End Roadmap

The development of Secure Backup follows an incremental, verifiable roadmap:

- [x] **Phase 1: Foundation & Desktop Shell**  
  Tauri 2 integration, WebKit2GTK backend, window management, and base application shell.
- [x] **Phase 2: UI Architecture**  
  Sidebar navigation (Dashboard, Backups, Restore, Settings), dark desktop theme, and reactive state.
- [x] **Phase 3: Directory Selection**  
  Native GTK folder picker integration via `@tauri-apps/plugin-dialog` with IPC path validation.
- [x] **Phase 4: Local Backup Engine**  
  Recursive directory traversal with `walkdir`, metadata gathering, and structured snapshot packaging.
- [x] **Phase 5: Cryptographic Hashing**  
  Streaming chunk-buffered SHA-256 fingerprinting for reliable change detection and data verification.
- [x] **Phase 6: Client-Side Authenticated Encryption**  
  AES-256-GCM file encryption, Argon2id key derivation, random salts/nonces, and `.enc` locked containers.
- [x] **Phase 7: Embedded SQLite Database**  
  Local `backup.db` integration using `rusqlite` for indexed snapshot records, file histories, and user settings.
- [ ] **Phase 8: Cloud Storage Abstraction & Google Drive**  
  Modular `CloudProvider` trait, Google Drive OAuth 2.0 PKCE flow, and encrypted remote upload engine.
- [ ] **Phase 9: Post-Upload Verification**  
  Automated validation comparing cloud-stored hashes and payload sizes against local manifests.
- [ ] **Phase 10: Complete File Restoration Engine**  
  Full download, decryption, tag verification, and file recovery workflow back to host filesystems.
- [ ] **Phase 11: Hash-Based Incremental Backups**  
  Intelligent change detection comparing current hashes to prior snapshots, uploading only modified files.
- [ ] **Phase 12: Automated Background Scheduling**  
  Configurable background scheduler for recurring and automated backups.

---

## Contributing

We welcome community contributions. Please review [CONTRIBUTING.md](CONTRIBUTING.md) for details on our trunk-based development workflow, code standards, and pull request checklist.

Direct pushes to `main` are restricted. All proposed modifications must be submitted via a pull request and pass all continuous integration tests.

---

## Security Disclosure

Security is fundamental to Secure Backup. If you identify a vulnerability, please disclose it responsibly according to our [Security Policy](SECURITY.md). Do not submit public issues for security vulnerabilities.

---

## License

This project is open-source software licensed under the [MIT License](LICENSE).
