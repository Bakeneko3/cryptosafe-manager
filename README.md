# CryptoSafe Manager

CryptoSafe Manager is a cross-platform desktop password manager developed as an applied cryptography project.

The application is designed to securely store password entries in a local database, provide a graphical user interface, protect sensitive data with modern cryptographic primitives, and maintain a tamper-evident history of security-related actions.

> **Current status:** Sprint 6 — Encrypted Import/Export + Secure Sharing

## Project Vision

CryptoSafe Manager aims to provide a local-first password management application with:

* encrypted password storage;
* secure master-password-based key management;
* AES-256-GCM encryption;
* secure clipboard handling;
* automatic locking;
* tamper-evident audit logging;
* encrypted import/export and secure sharing;
* backup and recovery;
* automated security testing.

Real cryptographic mechanisms are introduced incrementally according to the project sprint plan.

## Architecture

The project follows an MVC-like separation of responsibilities:

```text
┌─────────────────────────────┐
│          GUI Layer          │
│       src/gui/              │
│  Windows / Dialogs / Widgets│
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│          Core Layer         │
│       src/core/             │
│ Crypto / Vault / Clipboard /│
│ Audit / ImportExport /      │
│ Events / Settings           │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│        Database Layer       │
│      src/database/          │
│ SQLite / Schema / Backup    │
└─────────────────────────────┘
```

The GUI does not directly implement cryptographic operations. Core services provide application logic, while the database layer is responsible for persistence.

## Project Structure

```text
cryptosafe-manager/
│
├── src/
│   ├── core/
│   │   ├── crypto/
│   │   │   ├── abstract.py
│   │   │   ├── authentication.py
│   │   │   ├── key_derivation.py
│   │   │   ├── key_storage.py
│   │   │   └── placeholder.py
│   │   ├── vault/
│   │   │   ├── encryption_service.py
│   │   │   ├── entry_manager.py
│   │   │   ├── password_generator.py
│   │   │   └── search.py
│   │   ├── clipboard/
│   │   │   ├── clipboard_service.py
│   │   │   ├── clipboard_monitor.py
│   │   │   ├── clipboard_settings.py
│   │   │   └── platform_adapter.py
│   │   ├── audit/
│   │   │   ├── audit_logger.py
│   │   │   ├── log_signer.py
│   │   │   ├── log_verifier.py
│   │   │   └── log_formatters.py
│   │   ├── import_export/
│   │   │   ├── exporter.py
│   │   │   ├── importer.py
│   │   │   ├── sharing_service.py
│   │   │   ├── key_exchange.py
│   │   │   ├── qr_service.py
│   │   │   └── formats/
│   │   ├── audit_logger.py
│   │   ├── config.py
│   │   ├── events.py
│   │   ├── key_manager.py
│   │   ├── settings_manager.py
│   │   └── state_manager.py
│   │
│   ├── database/
│   │   ├── backup.py
│   │   └── db.py
│   │
│   └── gui/
│       ├── widgets/
│       ├── audit_log_viewer.py
│       ├── change_password_dialog.py
│       ├── clipboard_settings_dialog.py
│       ├── entry_dialog.py
│       ├── export_dialog.py
│       ├── import_dialog.py
│       ├── login_dialog.py
│       ├── main_window.py
│       ├── open_share_dialog.py
│       ├── password_generator_dialog.py
│       ├── qr_viewer.py
│       ├── settings_dialog.py
│       ├── setup_wizard.py
│       └── sharing_dialog.py
│
├── tests/
│
├── .github/
│   └── workflows/
│
├── requirements.txt
├── pytest.ini
├── .gitignore
└── README.md
```

## Database

The application currently uses SQLite.

The schema (version 6) contains:

* `vault_entries` — password-manager entries, each stored as a single
  opaque blob (`encrypted_data`) with a UUID primary key;
* `deleted_entries` — soft-deleted entries with an expiration timestamp;
* `audit_log` — tamper-evident log with sequence number, hash chain,
  encrypted payload, and Ed25519 signature;
* `audit_public_key` — single-row table holding the Ed25519 public key;
* `shared_entries` — metadata for created shares;
* `import_export_history` — audit trail of import/export operations;
* `contacts` — recipient records with public keys and fingerprints;
* `settings` — application configuration;
* `key_store` — master-password authentication hash, PBKDF2 salt,
  audit salt, and versioned KDF parameters.

Database schema versioning is implemented using SQLite `PRAGMA user_version`. Migrations run automatically on startup.

## Security Model

### Master password

* The master password itself is **never stored**.
* An Argon2id hash of the password is stored in `key_store` for verification.
* A PBKDF2-HMAC-SHA256 key is derived from the password and a unique
  16-byte salt to obtain the master key material.
* The master key is held only in memory (`KeyCache`) and is never
  written to disk.
* Failed login attempts trigger exponential backoff (1s / 5s / 30s).
* Password change re-encrypts all vault entries atomically and rotates
  the audit salt.

### Key separation (HKDF)

Three independent subkeys are derived from the master key material via
**HKDF-SHA256** with distinct context strings:

* `cryptosafe-vault-enc` — vault entry encryption (AES-256-GCM).
* `cryptosafe-audit-signing` — Ed25519 signing seed for the audit log.
* `cryptosafe-audit-enc` — AES-256-GCM for audit log entries at rest.

### Per-entry encryption

* Every vault entry is serialized to JSON and encrypted individually
  with **AES-256-GCM**.
* A fresh 12-byte nonce is generated per encryption using `os.urandom(12)`.
* The stored blob has the format `nonce (12 B) || ciphertext || tag (16 B)`.
* The authentication tag is verified on decryption.

### Audit log integrity

* Hash chain: each entry stores the SHA-256 hash of the previous entry's
  plaintext JSON payload; the genesis entry uses 64 zero characters.
* Every entry is signed with **Ed25519** using a key derived via HKDF
  (context `cryptosafe-audit-signing`).
* Entry payloads are **AES-256-GCM encrypted at rest** with a separate
  HKDF-derived key (context `cryptosafe-audit-enc`).
* Automatic verification on every successful login; manual verification
  available in the viewer.
* The log is **append-only**; sensitive fields are sanitized before
  writing.

### Import/Export & Sharing (Sprint 6)

* **Exports** support two encryption modes:
  * **Password-based:** PBKDF2-HMAC-SHA256 (100,000 iterations) + AES-256-GCM,
    with a fresh random salt and nonce per export.
  * **Public-key:** hybrid encryption — RSA-2048-OAEP or ECIES-style
    ephemeral ECDH P-256, both wrapping an AES-256-GCM payload.
* **Plaintext exports** are allowed only for CSV migration.
* Every export carries an **integrity hash** (SHA-256 of the plaintext)
  and an **Ed25519 signature** for provenance.
* **Imports** validate format, verify the integrity hash, and pass every
  entry through an **anti-malware filter** (script tags, executable
  magic bytes, shell commands). Files larger than 10 MB and operations
  exceeding 30 seconds are rejected.
* **Sharing** produces a single-entry package encrypted with a
  password or the recipient's public key. Packages contain only the
  shareable fields (title, username, password, URL, notes, category),
  plus permissions and expiration metadata.
* **QR codes** encode share packages in chunks with a per-chunk
  checksum, a nonce to prevent replay, and a 5-minute validity window.
* **No sensitive data is ever written to disk in plaintext.**

Argon2id parameters (configurable in `src/core/config.py`):

* time cost: 3 iterations
* memory cost: 64 MiB
* parallelism: 4 lanes
* hash length: 32 bytes

PBKDF2 parameters:

* iterations: 100,000
* salt length: 16 bytes
* key length: 32 bytes (AES-256)

### Clipboard

* All clipboard content is written **plaintext** to the system clipboard:
  obfuscation is not possible because other applications must be able to
  paste the value.
* Protection relies on **auto-clear** and explicit user actions.
* Auto-clear is **configurable** (5 s – 5 min, default 30 s, or never).
* The clipboard is cleared when:
  * the timer expires;
  * the user selects "Clear Clipboard";
  * the vault is locked (manual or automatic);
  * the application closes;
  * new content replaces old content.
* A background monitor detects **content changes** made outside the
  application and drops ownership accordingly. Detecting that another
  process *read* the clipboard is not technically possible and is
  deliberately out of scope.
* The clipboard requires the vault to be unlocked.

## Vault Features

* **CRUD:** create, read, update, and delete entries from the GUI.
* **Soft delete:** deleted entries are moved to `deleted_entries` with a
  30-day expiration before permanent removal.
* **Password generator:** CSPRNG-based (`secrets`), configurable length
  and character sets, one-per-set guarantees, optional ambiguous-character
  exclusion, and a rolling 20-entry history to prevent recent duplicates.
* **Search:** in-memory full-text search across title, username, URL,
  notes, category, and tags. Field-specific filters (`title:work`,
  `tag:important`) and optional fuzzy matching for typo tolerance.
* **Table:** multi-select, sortable columns, context menu, global
  username toggle (`Ctrl+Shift+P`).

## Clipboard Features

* **Copy Password / Username / All** from the toolbar, menu, or context
  menu.
* **Auto-clear** with a live countdown in the status bar.
* **Warning** shown a few seconds before the automatic clear.
* **Clear Clipboard** action available in the toolbar, menu, and context
  menu (`Ctrl+Shift+C`).
* **Preset profiles**: *Standard* (30 s), *Secure* (15 s),
  *Public Computer* (5 s).
* **Platform adapters**: Windows (`win32clipboard`) and generic
  (`pyperclip`).
* **Monitor**: detects external content changes; degrades gracefully.

## Audit Log Features

* **Tamper-evident**: hash chain + Ed25519 signatures + AES-GCM at rest.
* **Viewer** (`View → Audit Log`, `Ctrl+L`): sortable, filterable,
  searchable, with details panel.
* **Manual verification** and **automatic verification** on every login.
* **Export** to signed JSON (independently verifiable), CSV, and PDF.
* **Severity levels**: `INFO`, `WARN`, `ERROR`, `CRITICAL`.

## Import / Export & Sharing Features

* **Export formats:**
  * CryptoSafe native JSON (encrypted);
  * CSV (plaintext or encrypted);
  * Bitwarden JSON (compatible);
  * LastPass CSV (compatible).
* **Export options:**
  * whole vault or selected entries;
  * include/exclude individual fields;
  * password / public-key / plaintext encryption;
  * optional GZIP compression.
* **Import:**
  * format auto-detection;
  * merge / replace / dry-run modes;
  * duplicate skipping;
  * sanitization of malicious content;
  * file size and processing time limits.
* **Sharing:**
  * password-protected or public-key encrypted single-entry packages;
  * permissions and expiration metadata;
  * recipient-side import without affecting the existing vault.
* **QR codes:**
  * chunked generation for large packages;
  * per-chunk checksum;
  * 5-minute validity, nonce-based replay protection;
  * decoding via `pyzbar` from image files or in-memory PNGs.

## Setup

### Requirements

* Python 3.14+
* Git
* Tkinter

### Create virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Run the Application

From the project root:

```powershell
python -m src.gui.main_window
```

On first run, a setup wizard will ask for a master password. On subsequent runs, a login dialog will request the same password to unlock the vault.

### Keyboard shortcuts

* `Ctrl+N` — add a new entry
* `Ctrl+E` — edit the selected entry
* `Delete` — delete the selected entries
* `Ctrl+F` — focus the search bar
* `Ctrl+L` — open the audit log viewer
* `Ctrl+I` — import vault
* `Ctrl+Shift+E` — export vault
* `Ctrl+Shift+O` — open share package
* `Ctrl+Shift+P` — toggle username visibility
* `Ctrl+Shift+C` — clear the clipboard

## Run Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

The current test suite covers crypto, key management, vault CRUD,
search, password generation, clipboard behaviour, audit signing and
verification, log export, import/export round-trips, sharing, QR
generation and decoding, and GUI smoke tests.

## Sprint Roadmap

### Sprint 1 — Secure Database + GUI Shell (done)

* project architecture;
* SQLite database;
* schema and migrations;
* placeholder encryption service;
* key-manager stub;
* configuration management;
* settings dialog;
* event system;
* audit logging foundation;
* GUI shell;
* backup/restore stubs;
* automated tests.

### Sprint 2 — Master Password + Key Management (done)

* master password setup;
* Argon2id password hashing;
* PBKDF2-HMAC-SHA256 encryption key derivation;
* PBKDF2 salt generation and storage;
* versioned KDF parameters in `key_store`;
* secure in-memory key caching with zeroing;
* exponential backoff on failed logins;
* login dialog and vault unlock;
* password change with atomic vault re-encryption;
* database migration system;
* expanded test coverage.

### Sprint 3 — Vault CRUD + AES-256-GCM (done)

* per-entry AES-256-GCM with unique nonces;
* JSON payload with version identifier;
* authentication-tag verification on decryption;
* create / read / update / delete entries;
* soft delete with expiration;
* secure password generator (CSPRNG, configurable);
* in-memory search with field filters and fuzzy matching;
* entry dialog with URL validation and password strength feedback;
* password generator dialog with live preview;
* main window integration (toolbar, context menu, sorting, status bar);
* database schema v3 migration.

### Sprint 4 — Secure Clipboard (done)

* clipboard service with auto-clear timer;
* configurable timeout (5 s – 5 min, default 30 s, or never);
* persistent settings stored in the `settings` table;
* clipboard settings dialog with presets;
* platform adapters for Windows (`win32clipboard`) and generic
  (`pyperclip`);
* background monitor detecting external clipboard changes;
* integration with the event bus;
* audit logging of every clipboard operation;
* toolbar, menu, and context-menu actions for copy / clear;
* live countdown in the status bar;
* clipboard cleared on lock and on application close;
* integration tests for timing, concurrency, recovery, and performance.

### Sprint 5 — Audit Logs + Integrity (done)

* separate audit salt and HKDF-derived subkeys for signing and
  log encryption;
* database schema v4 with tamper-evident `audit_log` and
  `audit_public_key`;
* Ed25519 signatures over each entry's plaintext payload;
* SHA-256 hash chain;
* AES-256-GCM encryption of entry payloads at rest;
* sanitization of sensitive details;
* automatic verification on every successful login;
* `LogVerifier` with full and range-based verification;
* audit log viewer with filters, search, details panel, and manual
  verification;
* export to signed JSON, CSV, and PDF;
* integration tests for performance, export, recovery, and security.

### Sprint 6 — Encrypted Import/Export + Secure Sharing (done)

* password-based and public-key encryption for exports
  (PBKDF2 + AES-256-GCM, RSA-2048-OAEP, ECIES P-256);
* export formats: CryptoSafe JSON, CSV, Bitwarden JSON, LastPass CSV;
* field selection, GZIP compression, integrity hash, Ed25519 signature;
* import with format auto-detection, merge/replace/dry-run modes,
  duplicate skipping, anti-malware sanitization, size and timeout limits;
* share packages with permissions, expiration, and recipient metadata;
* recipient-side import (save or use temporarily);
* QR codes with chunking, checksum, nonce, and 5-minute validity;
* GUI dialogs: Export, Import, Sharing, Open Share, QR Viewer;
* integration into the main window (menu, toolbar, context menu);
* database schema v5/v6 with `shared_entries`, `import_export_history`,
  `contacts`.

### Sprint 7 — Hardening + UX

* constant-time comparisons;
* memory wiping;
* automatic locking;
* inactivity detection;
* system tray integration;
* panic mode;
* OS keychain integration;
* security and usability improvements.

### Sprint 8 — Integration, Testing + Documentation

* complete integration testing;
* expanded pytest coverage;
* backup and restore;
* PyInstaller packaging;
* CI/CD;
* final documentation;
* user guide;
* recovery procedures;
* demonstration build.

## Security Development Model

Cryptographic functionality is introduced progressively.

Sprint 1 introduced intentionally insecure placeholders where required by the architecture. Sprint 2 introduced the real master-password and key derivation layer. Sprint 3 replaced the placeholder entry encryption with real AES-256-GCM. Sprint 4 added secure clipboard handling with auto-clear and monitoring. Sprint 5 made the audit log tamper-evident with Ed25519 signatures, a SHA-256 hash chain, and per-entry AES-GCM encryption at rest. Sprint 6 introduced encrypted import/export, secure sharing, and QR-code key exchange.

The final application uses established cryptographic primitives from maintained libraries rather than custom cryptographic algorithms.

## Development Status

| Component              | Sprint 1    | Sprint 2          | Sprint 3          | Sprint 4          | Sprint 5          | Sprint 6          |
| ---------------------- | ----------- | ----------------- | ----------------- | ----------------- | ----------------- | ----------------- |
| SQLite database        | Implemented | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Schema versioning      | Implemented | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Migration system       | Basic       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| GUI shell              | Implemented | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Settings               | Implemented | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Event bus              | Implemented | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Key manager            | Stub        | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Backup/restore         | Stub        | Stub              | Stub              | Stub              | Stub              | Stub              |
| Master password        | Planned     | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Argon2id hashing       | Planned     | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| PBKDF2 key derivation  | Planned     | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| HKDF key separation    | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       | Implemented       |
| AES-256-GCM (vault)    | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       | Implemented       |
| Vault CRUD             | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       | Implemented       |
| Search / filter        | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       | Implemented       |
| Secure clipboard       | Planned     | Planned (S4)      | Planned (S4)      | Implemented       | Implemented       | Implemented       |
| Signed audit log       | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       | Implemented       |
| Audit viewer + export  | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       | Implemented       |
| Import / export        | Planned     | Planned (S6)      | Planned (S6)      | Planned (S6)      | Planned (S6)      | Implemented       |
| Secure sharing         | Planned     | Planned (S6)      | Planned (S6)      | Planned (S6)      | Planned (S6)      | Implemented       |
| QR key exchange        | Planned     | Planned (S6)      | Planned (S6)      | Planned (S6)      | Planned (S6)      | Implemented       |
| Auto-lock              | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (Sprint 7)|
| OS keychain            | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (Sprint 7)|
| Packaging              | Planned     | Planned (S8)      | Planned (S8)      | Planned (S8)      | Planned (S8)      | Planned (Sprint 8)|

## License

This project is developed as an applied cryptography project.