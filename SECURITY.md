# Security Policy

## Supported Versions

Security updates and patches are provided for the following releases:

| Version | Supported |
| ------- | --------- |
| 0.3.x   | Yes       |
| < 0.3.0 | No        |

---

## Reporting a Security Vulnerability

If you discover a security vulnerability in Secure Backup, please report it privately. Do not open public issues, discussions, or pull requests disclosing the vulnerability.

### Reporting Procedure

1. **GitHub Security Advisories (Recommended):**  
   Submit a private report via the [GitHub Security Advisory form](https://github.com/abdulwalidal/secure-backup/security/advisories/new).
2. **Direct Contact:**  
   Alternatively, contact the repository maintainer directly through the communication channels listed on their GitHub profile.

### Information to Include

To facilitate a prompt assessment and resolution, include:

- A clear description of the vulnerability and its potential impact.
- Step-by-step instructions or minimal proof-of-concept code demonstrating the issue.
- The operating system, build version, and dependencies used.
- Any proposed remediation or patches, if available.

---

## Response Timeline

- **Initial Acknowledgment:** Within 48 hours of receipt.
- **Triage and Status Update:** Within 5 business days, including an evaluation of severity and estimated timeline for a fix.
- **Coordinated Disclosure:** Security patches will be merged and released prior to public disclosure of the vulnerability details.

---

## Core Security Commitments

1. **Client-Side Cryptography:** All cryptographic hashing (SHA-256) and authenticated encryption (AES-256-GCM / Argon2id) occur exclusively on the local machine before any data is stored or transmitted.
2. **Zero Plaintext Transmission:** The cloud storage layer receives only encrypted ciphertext blobs and randomized identifiers.
3. **No Unsolicited Telemetry:** The application contains no analytics, diagnostic beacons, third-party trackers, or background data collection mechanisms.
