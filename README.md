# Secure Backup

[![CI](https://github.com/abdulwalidal/secure-backup/actions/workflows/ci.yml/badge.svg)](https://github.com/abdulwalidal/secure-backup/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Tauri 2](https://img.shields.io/badge/Tauri-2.0-24c8db.svg)](https://tauri.app/)

A lightweight, zero-knowledge desktop backup application that encrypts your folders locally using authenticated AES-256-GCM before syncing to the cloud, ensuring total privacy on Linux and Windows.

---

## Why Secure Backup?

Traditional cloud backup tools upload your documents, photos, and personal records in clear text or rely on server-side encryption where the cloud provider holds the keys. If their servers are breached, or if access is subpoenaed, your unencrypted data is exposed.

**Secure Backup solves this with Zero-Knowledge Architecture:**
- **Encrypted locally on your computer**: Your files are transformed into unbreakable ciphertext before they ever touch your disk or leave your machine.
- **You hold the keys**: Your master passphrase never leaves your device and is never sent over any network. 
- **Cloud providers see only scrambled bytes**: When syncing to Google Drive or any remote vault, third parties cannot inspect, read, or index your personal data.

---

## Core Highlights

- **Client-Side Zero-Knowledge Encryption**: Uses authenticated **AES-256-GCM** encryption paired with **Argon2id** password key derivation to prevent brute-force attacks.
- **Seamless Cloud Sync**: Syncs encrypted `.enc` archives directly to an isolated `"Secure Backup Vault"` folder in your Google Drive via OAuth 2.0 PKCE.
- **Ultra-Lightweight & Fast**: Built with Rust and Tauri 2 instead of resource-heavy web frameworks. Runs smoothly with minimal memory consumption and near-zero background CPU usage.
- **Cryptographic Tamper Detection**: Every file is fingerprinted with streaming **SHA-256** checksums. Any corrupted or tampered file is rejected immediately upon verification.
- **Built-in Key Generator**: Instantly generate high-entropy 256-bit random passphrases directly from the app with one click.
- **Complete Privacy by Design**: Zero telemetry, zero analytics, and zero third-party trackers. All state is stored in your private local SQLite database.

---

## How It Protects You

```text
[ Your Computer ]                                          [ Cloud Storage ]
+-----------------------+                                  +-------------------+
|  Original Files       |                                  |                   |
|  (Documents / Photos) |                                  |                   |
+-----------+-----------+                                  |                   |
            |                                              |                   |
            v                                              |                   |
+-----------------------+                                  |                   |
|  Argon2id + AES-256   |                                  |                   |
|  Local Encryption     |                                  |                   |
+-----------+-----------+                                  |                   |
            |                                              |                   |
            v                                              |                   |
+-----------------------+      Encrypted Upload (HTTPS)    |  Remote Cloud     |
|  Locked .enc Archives | ===============================> |  Vault Folder     |
|  (Unreadable Cipher)  |                                  |  (Ciphertext Only)|
+-----------------------+                                  +-------------------+
```

1. **Select**: Choose any folder on your machine you wish to protect.
2. **Lock**: Provide a passphrase or click **Generate Secure Key** to derive a cryptographic key in memory.
3. **Backup & Sync**: The app packages and encrypts the data locally, indexes it in your local database, and optionally uploads the locked archive to your cloud vault.

---

## Quick Start Guide

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **Rust**: v1.78.0 or higher
- **Linux Packages** (Ubuntu/Debian):
  ```bash
  sudo apt update && sudo apt install -y build-essential curl wget file libssl-dev libgtk-3-dev libwebkit2gtk-4.1-dev
  ```

### Installation & Launch

1. Clone the repository:
   ```bash
   git clone git@github.com:abdulwalidal/secure-backup.git
   cd secure-backup
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Launch in development mode:
   ```bash
   npm run tauri dev
   ```

4. Run the automated test suite:
   ```bash
   cargo test --manifest-path src-tauri/Cargo.toml
   ```

---

## Documentation & Deep Dive

For technical architecture, design specifications, and contributing guides, explore the repository documentation:

- [ARCHITECTURE.md](ARCHITECTURE.md): Comprehensive system architecture, data models, and cryptographic parameters.
- [ROADMAP.md](ROADMAP.md): Detailed 12-phase development milestones and feature progression.
- [CONTRIBUTING.md](CONTRIBUTING.md): Contribution guidelines, code standards, and PR workflows.
- [SECURITY.md](SECURITY.md): Security policy and responsible vulnerability disclosure.

---

## License

This project is licensed under the [MIT License](LICENSE).
