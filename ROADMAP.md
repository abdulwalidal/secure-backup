# Secure Backup Project Roadmap

This document outlines the phased engineering roadmap and long-term milestones for Secure Backup. For architecture and cryptographic specifications, see [ARCHITECTURE.md](ARCHITECTURE.md). For user instructions and getting started, see [README.md](README.md).

---

## Development Phases

### Phase 1: Foundation & Desktop Shell
- [x] Tauri 2 integration with native Rust core
- [x] WebKit2GTK desktop webview configuration (Linux & Windows)
- [x] Window lifecycle management, system tray hooks, and application shell
- [x] Initial build scripts and cross-platform compilation targets

### Phase 2: User Interface & Experience
- [x] Dark-themed desktop UI layout with modern sidebar navigation
- [x] Navigation routing between Dashboard, Backups, Restore, and Settings views
- [x] Reactive state bindings using Vanilla TypeScript
- [x] Accessibility attributes and clean SVG icon system (zero-emoji policy)

### Phase 3: Target Folder Selection
- [x] Native OS file dialog integration using `@tauri-apps/plugin-dialog`
- [x] Safe filesystem path validation and error boundaries
- [x] Target folder metadata preview (folder name, size, file count)
- [x] Folder clear and reselection handlers

### Phase 4: Local Backup Engine
- [x] Recursive filesystem scanning with `walkdir`
- [x] Structured snapshot packaging in `~/.local/share/secure-backup/backups`
- [x] Manifest generation (`manifest.json`) recording relative paths and timestamps
- [x] Automated unit tests covering scanning and packaging logic

### Phase 5: Cryptographic Integrity Hashing
- [x] Streaming SHA-256 digest computation with 64 KB memory-buffered chunks
- [x] Pre-encryption and post-decryption byte verification
- [x] Snapshot tamper detection and checksum verification tests
- [x] Known-content test vectors for empty and non-empty files

### Phase 6: Client-Side Authenticated Encryption
- [x] Authenticated AES-256-GCM encryption with unique 12-byte nonces per file
- [x] Argon2id password-based key derivation (19 MiB memory, 2 passes, random 16-byte salt)
- [x] Custom binary container format (`SECBKP01` magic header)
- [x] Automatic plaintext wiping from memory post-encryption
- [x] CSPRNG-based random key generator and clipboard export on Dashboard (PR #18)

### Phase 7: Embedded SQLite Database Ledger
- [x] Embedded SQLite integration via `rusqlite` bundled dependency
- [x] Relational schema for `snapshots`, `snapshot_files`, and `app_settings`
- [x] Transactional snapshot metadata recording upon backup completion
- [x] Database statistics queries and cascade deletion handlers
- [x] Automated unit tests for database initialization, queries, and cascade operations

### Phase 8: Cloud Provider Abstraction & Google Drive Sync
- [x] Modular `CloudProvider` Rust trait for multi-cloud extensibility
- [x] Google Drive OAuth 2.0 PKCE authentication with local loopback server
- [x] Remote root `"Secure Backup Vault"` and snapshot subfolder management
- [x] REST API v3 multipart upload engine for `.enc` ciphertext files and manifests
- [x] Cloud synchronization ledger tracking (`cloud_synced`, `cloud_file_id`) in SQLite
- [x] One-click "Sync to Google Drive" button in Backup History UI

### Phase 9: Post-Upload Verification & Remote Disaster Recovery (Current)
- [ ] Remote file size and hash validation against Google Drive API metadata
- [ ] Disaster recovery discovery: listing remote snapshots from Google Drive vault
- [x] Remote manifest downloading and local SQLite catalog reconstruction on fresh installs
- [x] Client-side backup manifest encryption (`SECBKP01`) protecting metadata before cloud upload (#27)
- [ ] Automated network retry handling with exponential backoff

### Phase 10: Complete File Restoration Engine
- [x] Snapshot download and extraction workflow from local and remote vaults
- [x] Passphrase authentication and Argon2id key derivation verification
- [x] AES-256-GCM decryption with AEAD tag integrity validation
- [x] Post-restore SHA-256 fingerprint verification against snapshot manifest
- [x] Selective and full-directory restoration options

### Phase 11: Hash-Based Incremental Backups
- [ ] Differential snapshot creation by comparing SHA-256 hashes against prior snapshots
- [ ] Deduplication of unmodified files across snapshots
- [ ] Reduced network bandwidth and cloud storage utilization
- [ ] Snapshot chain management and synthetic full backups

### Phase 12: Automated Background Scheduling
- [ ] Background daemon/service for automated backup execution
- [ ] Configurable schedules (hourly, daily, weekly)
- [ ] Native system tray notifications for backup success and warnings
- [ ] Battery and metered-network detection to defer large transfers

---

## Long-Term Multi-Cloud Roadmap

The `CloudProvider` trait is designed to allow plugging in additional storage backends without altering core encryption or backup logic:

| Provider | Status | Priority | Notes |
| -------- | ------ | -------- | ----- |
| Google Drive | Completed (Phase 8) | High | OAuth 2.0 PKCE + REST API v3 Multipart Uploads |
| Amazon S3 / S3-Compatible | Planned | High | Support for AWS S3, Cloudflare R2, MinIO, Wasabi |
| Proton Drive | Planned | Medium | Community demand for privacy-focused providers |
| Mega | Planned | Medium | End-to-end encrypted storage integration |
| Local External Drive | Planned | High | Direct backup to USB drives and external SSDs |

---

## Contributing to the Roadmap

Features and phases are tracked via [GitHub Issues](https://github.com/abdulwalidal/secure-backup/issues). If you want to propose a new feature or help implement an upcoming phase, please open an issue or check [CONTRIBUTING.md](CONTRIBUTING.md).
