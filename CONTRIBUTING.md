# Contributing Guidelines

Thank you for contributing to Secure Backup. This document details the contribution standards, development workflow, and pull request submission process for this repository.

---

## Code of Conduct

All contributors and maintainers are expected to adhere to the [Code of Conduct](CODE_OF_CONDUCT.md). Please report any unacceptable behavior to the project maintainer.

---

## Development Workflow

### Branching Model

This project follows a trunk-based pull request model. The `main` branch is protected and reflects stable, production-ready code.

Direct commits to `main` are rejected. All work must follow this sequence:

1. **Fork the Repository:** Create a fork of `abdulwalidal/secure-backup` under your GitHub account.
2. **Clone Locally:**
   ```bash
   git clone git@github.com:<your-username>/secure-backup.git
   cd secure-backup
   ```
3. **Create a Feature Branch:** Branch off the latest `main` branch using a clear, prefixed branch name:
   ```bash
   git checkout -b feature/<issue-number>-<short-description>
   # Example:
   git checkout -b feature/4-storage-path-display
   # For bug fixes:
   git checkout -b fix/<issue-number>-<short-description>
   ```
4. **Implement and Test Changes:** Write clean, modular code with accompanying unit tests.
5. **Format and Verify Locally:**
   ```bash
   npm run build
   cargo fmt --all --manifest-path src-tauri/Cargo.toml -- --check
   cargo test --manifest-path src-tauri/Cargo.toml
   ```
6. **Commit Changes:** Use structured commit messages adhering to the Conventional Commits specification.
7. **Submit a Pull Request:** Push the branch to your fork and open a pull request targeting `main`.

---

## Commit Message Conventions

Commit messages must be concise, descriptive, and follow the Conventional Commits specification:

```text
<type>(<scope>): <short description>
```

### Accepted Types:
- `feat`: A new feature or capability.
- `fix`: A bug fix.
- `docs`: Documentation updates.
- `style`: Formatting changes that do not affect runtime behavior.
- `refactor`: Code restructuring without adding features or fixing bugs.
- `test`: Adding or correcting tests.
- `chore`: Build system, configuration, or dependency updates.

### Examples:
- `feat(crypto): implement argon2id key derivation`
- `fix(scanner): correct handling of broken symbolic links`
- `docs(readme): update ubuntu build requirements`

---

## Coding Standards

### Rust Core (`src-tauri/`)

- Adhere to standard Rust idioms and pass `cargo fmt` and `cargo clippy`.
- Never use `unwrap()` or `expect()` in production application paths; propagate errors using structured `Result<T, E>` types.
- Cryptographic safety:
  - Do not introduce custom cryptographic primitives. Use established libraries (`aes-gcm`, `argon2`, `sha2`).
  - Never store or log sensitive information, passwords, or plaintext keys.
  - Zeroize sensitive memory buffers where applicable.
- Isolate system-level side effects within dedicated modules (`backup`, `encryption`, `database`).

### Frontend Layer (`src/`)

- Use modern TypeScript with strict type checking enabled (`strict: true` in `tsconfig.json`).
- Avoid unnecessary external runtime dependencies or large web frameworks. Maintain a lightweight, dependency-free vanilla TypeScript implementation.
- Keep the user interface responsive, keyboard-navigable, and accessible.

---

## Pull Request Submission Requirements

Before submitting your pull request, ensure that:

1. The change corresponds to an existing open issue. Reference the issue in your pull request description (e.g., `Closes #12`).
2. All new and existing unit tests pass without failures.
3. The change introduces no new compiler warnings, lint errors, or unused imports.
4. Documentation is updated to reflect any changes to user-facing functionality or internal APIs.
5. The pull request template is fully completed.
