# Secure Backup

[![CI](https://github.com/abdulwalidal/secure-backup/actions/workflows/ci.yml/badge.svg)](https://github.com/abdulwalidal/secure-backup/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Tauri 2](https://img.shields.io/badge/Tauri-2.0-24c8db.svg)](https://tauri.app/)

Secure Backup is a lightweight, zero-knowledge desktop backup application developed with Tauri 2, Rust, and TypeScript. It is designed to provide secure, verified, and client-side encrypted backups with minimal resource consumption.

---

## Key Features

- **Client-Side Authenticated Encryption:** Employs AES-256-GCM (Authenticated Encryption with Associated Data) paired with Argon2id password-based key derivation. Plaintext files never leave the local system.
- **Cryptographic Integrity Verification:** Computes chunked, streaming SHA-256 checksums to verify file contents and detect changes.
- **Lightweight Desktop Architecture:** Built using Tauri 2 and WebKit2GTK on Linux, avoiding the runtime overhead and memory footprint of Electron.
- **Structured Snapshot Engine:** Preserves directory hierarchies, file metadata, and timestamps in structured archives.
- **Privacy by Design:** Zero analytics, telemetry, user tracking, or unauthorized outbound network connections.

---

## Technical Overview

The application follows a strict separation of concerns between presentation and system operations:

```text
User selects directory
          |
Scan filesystem & collect metadata
          |
Compute streaming SHA-256 checksums
          |
Derive 256-bit key via Argon2id (salt + passphrase)
          |
Encrypt files via AES-256-GCM (unique nonces)
          |
Write encrypted payload (.enc) and manifest to storage
          |
Record snapshot in local database
```

---

## Repository Structure

```text
secure-backup/
├── src/                          # Frontend presentation layer (TypeScript, HTML, CSS)
│   ├── index.html                # Application shell and view layouts
│   ├── styles.css                # Application styles and theme definitions
│   └── main.ts                   # Tauri IPC event binding and view logic
├── src-tauri/                    # Core engine (Rust)
│   ├── src/
│   │   ├── backup/               # Filesystem traversal and snapshot packaging
│   │   ├── commands/             # Tauri IPC command definitions
│   │   ├── encryption/           # AES-256-GCM and Argon2id cryptographic operations
│   │   ├── hashing/              # Streaming SHA-256 file checksums
│   │   ├── models/               # Domain models and serializable structures
│   │   ├── lib.rs                # Application initialization and plugin registration
│   │   └── main.rs               # Binary entry point
│   ├── capabilities/             # Tauri 2 security capability definitions
│   ├── Cargo.toml                # Rust dependencies and compiler configurations
│   └── tauri.conf.json           # Window configuration and runtime settings
├── .github/                      # CI workflows and issue templates
├── ARCHITECTURE.md               # Detailed system and security specifications
├── CONTRIBUTING.md               # Development workflow and contribution guidelines
├── SECURITY.md                   # Vulnerability reporting and security policies
└── LICENSE                       # MIT License
```

---

## Getting Started

### System Requirements

#### Linux (Ubuntu / Debian)

Install the necessary compilation tools and WebKit2GTK development libraries:

```bash
sudo apt update
sudo apt install -y build-essential curl wget file libssl-dev libgtk-3-dev \
    libayatana-appindicator3-dev librsvg2-dev libwebkit2gtk-4.1-dev
```

#### Toolchain

- **Node.js:** v18.0.0 or higher
- **npm:** v9.0.0 or higher
- **Rust:** v1.78.0 or higher (stable toolchain)

### Installation & Build

1. Clone the repository:
   ```bash
   git clone git@github.com:abdulwalidal/secure-backup.git
   cd secure-backup
   ```

2. Install frontend dependencies:
   ```bash
   npm install
   ```

3. Run the automated test suite:
   ```bash
   cargo test --manifest-path src-tauri/Cargo.toml
   ```

4. Launch the desktop application in development mode:
   ```bash
   npm run tauri dev
   ```

5. Build the release binary:
   ```bash
   npm run tauri build
   ```

---

## Project Roadmap

- [x] **Milestone 1: Desktop Shell & Native Integration**  
  Tauri 2 foundation, native GTK file selection, and IPC communication.
- [x] **Milestone 2: Hashing & Local Backup Engine**  
  Recursive directory scanning, streaming SHA-256 file hashing, and manifest generation.
- [x] **Milestone 3: Client-Side Authenticated Encryption**  
  AES-256-GCM authenticated encryption, Argon2id key derivation, and ciphertext verification.
- [ ] **Milestone 4: SQLite Metadata Database**  
  Embedded SQLite engine for queryable backup history, file indexing, and configuration persistence.
- [ ] **Milestone 5: Cloud Storage Integration**  
  Abstract provider interface and integration with an S3-compatible cloud storage backend.
- [ ] **Milestone 6: File Restoration Engine**  
  End-to-end verification, download, decryption, and file recovery.
- [ ] **Milestone 7: Incremental Backups**  
  Checksum-based change detection to back up only modified or newly created files.
- [ ] **Milestone 8: Automated Scheduling**  
  Configurable background backup scheduler.

---

## Contribution Guidelines

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code standards, branching conventions, and pull request procedures.

Direct pushes to the `main` branch are restricted. All proposed changes must be submitted through a pull request and pass all continuous integration checks.

---

## Security

Please report vulnerabilities responsibly. Refer to [SECURITY.md](SECURITY.md) for our disclosure policy and reporting process.

---

## License

This project is licensed under the [MIT License](LICENSE).
