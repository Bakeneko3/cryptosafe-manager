# CryptoSafe Manager

CryptoSafe Manager is a cross-platform desktop password manager developed as an applied cryptography project.

The application is designed to securely store password entries in a local database, provide a graphical user interface, protect sensitive data with modern cryptographic primitives, and maintain a tamper-evident history of security-related actions.

> **Current status:** Sprint 5 — Audit Logs + Integrity

## Project Vision

CryptoSafe Manager aims to provide a local-first password management application with:

* encrypted password storage;
* secure master-password-based key management;
* AES-256-GCM encryption;
* secure clipboard handling;
* automatic locking;
* tamper-evident audit logging;
* encrypted import/export;
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
│ Audit / Events / Settings   │
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
│       ├── login_dialog.py
│       ├── main_window.py
│       ├── password_generator_dialog.py
│       ├── settings_dialog.py
│       └── setup_wizard.py
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

The schema (version 4) contains:

* `vault_entries` — password-manager entries, each stored as a single
  opaque blob (`encrypted_data`) with a UUID primary key;
* `deleted_entries` — soft-deleted entries with an expiration timestamp;
* `audit_log` — tamper-evident log with sequence number, hash chain,
  encrypted payload, and Ed25519 signature;
* `audit_public_key` — single-row table holding the Ed25519 public key
  used to verify the audit log;
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

### Audit log integrity (Sprint 5)

* The audit log is a **hash chain**: each entry stores the SHA-256 hash
  of the previous entry's plaintext JSON payload. The first entry uses
  64 zero characters as the genesis hash.
* Every entry is signed with **Ed25519** using a key derived via HKDF
  from the master key material (context `cryptosafe-audit-signing`).
* Entry payloads are additionally **AES-256-GCM encrypted at rest**
  using a separate HKDF-derived key (context `cryptosafe-audit-enc`).
* The public key is stored once in `audit_public_key` and can be exported
  for independent verification.
* **Automatic verification** runs on every successful login (VER-1).
  If tampering is detected, the user is notified and a `tampering_detected`
  event is logged.
* **Manual verification** is available in the audit log viewer.
* The log is **append-only** by API: there are no update or delete
  operations exposed by `AuditLogger` or `AuditExporter`.
* Sensitive values (`password`, `encryption_key`, etc.) are **sanitized**
  before being written — replaced with `[REDACTED]`.

### Clipboard (Sprint 4)

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

Argon2id parameters (configurable in `src/core/config.py`):

* time cost: 3 iterations
* memory cost: 64 MiB
* parallelism: 4 lanes
* hash length: 32 bytes

PBKDF2 parameters:

* iterations: 100,000
* salt length: 16 bytes
* key length: 32 bytes (AES-256)

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
* **Viewer** (`View → Audit Log`, `Ctrl+L`):
  * sortable table with sequence number, timestamp, type, severity,
    source, entry id;
  * filters by event type and severity;
  * full-text search across all fields;
  * details panel showing the full decrypted payload, previous hash,
    and signature prefix.
* **Manual verification** (Verify button) — checks signature and chain
  for every entry and reports errors with sequence numbers.
* **Automatic verification** on every successful login.
* **Export:**
  * **Signed JSON** — full log with signatures and public key, suitable
    for independent verification.
  * **CSV** — flat view for spreadsheets.
  * **PDF** — human-readable report with summary and entries table.
* **Severity levels**: `INFO`, `WARN`, `ERROR`, `CRITICAL`.
* **Event categories** (integrated via the event bus):
  * *system* — genesis, startup, shutdown, tampering;
  * *authentication* — login, logout;
  * *vault* — entry created/updated/deleted;
  * *clipboard* — copied, cleared (with reason).

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
* `Ctrl+Shift+P` — toggle username visibility
* `Ctrl+Shift+C` — clear the clipboard

## Run Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

The current test suite covers crypto, key management, vault CRUD,
search, password generation, clipboard behaviour, audit signing and
verification, log export, and GUI smoke tests.

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
* integration with the event bus (`ClipboardCopied`, `ClipboardCleared`);
* audit logging of every clipboard operation;
* toolbar, menu, and context-menu actions for copy / clear;
* live countdown in the status bar;
* clipboard cleared on lock and on application close;
* integration tests for timing, concurrency, recovery, and performance.

### Sprint 5 — Audit Logs + Integrity (done)

* separate audit salt and HKDF-derived subkeys for signing and
  log encryption (key separation);
* database schema v4 with tamper-evident `audit_log`
  (sequence number, previous hash, encrypted payload, signature) and
  `audit_public_key` table;
* Ed25519 signatures over each entry's plaintext payload;
* SHA-256 hash chain linking every entry to its predecessor;
* AES-256-GCM encryption of entry payloads at rest;
* sanitization of sensitive details (`password`, `encryption_key`, ...)
  before logging;
* automatic verification on every successful login (VER-1);
* `LogVerifier` with full and range-based verification;
* audit log viewer with filters, search, details panel, and manual
  verification (VER-3);
* export to signed JSON (independently verifiable), CSV, and PDF;
* `system_startup`, `system_shutdown`, and `tampering_detected` events;
* integration tests for performance, export, recovery, and security.

### Sprint 6 — Encrypted Import/Export

* encrypted exports;
* secure sharing;
* RSA/ECC-based key exchange/encryption;
* CSV import;
* JSON import/export.

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

Sprint 1 introduced intentionally insecure placeholders where required by the architecture. Sprint 2 introduced the real master-password and key derivation layer. Sprint 3 replaced the placeholder entry encryption with real AES-256-GCM. Sprint 4 added secure clipboard handling with auto-clear and monitoring. Sprint 5 made the audit log tamper-evident with Ed25519 signatures, a SHA-256 hash chain, and per-entry AES-GCM encryption at rest.

The final application uses established cryptographic primitives from maintained libraries rather than custom cryptographic algorithms.

## Development Status

| Component              | Sprint 1    | Sprint 2          | Sprint 3          | Sprint 4          | Sprint 5          |
| ---------------------- | ----------- | ----------------- | ----------------- | ----------------- | ----------------- |
| SQLite database        | Implemented | Implemented       | Implemented       | Implemented       | Implemented       |
| Schema versioning      | Implemented | Implemented       | Implemented       | Implemented       | Implemented       |
| Migration system       | Basic       | Implemented       | Implemented       | Implemented       | Implemented       |
| GUI shell              | Implemented | Implemented       | Implemented       | Implemented       | Implemented       |
| Settings               | Implemented | Implemented       | Implemented       | Implemented       | Implemented       |
| Event bus              | Implemented | Implemented       | Implemented       | Implemented       | Implemented       |
| Key manager            | Stub        | Implemented       | Implemented       | Implemented       | Implemented       |
| Backup/restore         | Stub        | Stub              | Stub              | Stub              | Stub              |
| Master password        | Planned     | Implemented       | Implemented       | Implemented       | Implemented       |
| Argon2id hashing       | Planned     | Implemented       | Implemented       | Implemented       | Implemented       |
| PBKDF2 key derivation  | Planned     | Implemented       | Implemented       | Implemented       | Implemented       |
| HKDF key separation    | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       |
| Key caching            | Planned     | Implemented       | Implemented       | Implemented       | Implemented       |
| Failed-login backoff   | Planned     | Implemented       | Implemented       | Implemented       | Implemented       |
| Password change        | Planned     | Implemented       | Implemented       | Implemented       | Implemented       |
| AES-256-GCM (vault)    | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       |
| Vault CRUD             | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       |
| Password generator     | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       |
| Search / filter        | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       |
| Soft delete            | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       |
| Secure clipboard       | Planned     | Planned (S4)      | Planned (S4)      | Implemented       | Implemented       |
| Clipboard auto-clear   | Planned     | Planned (S4)      | Planned (S4)      | Implemented       | Implemented       |
| Clipboard monitor      | Planned     | Planned (S4)      | Planned (S4)      | Implemented       | Implemented       |
| Signed audit log       | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       |
| Hash chain             | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       |
| Audit at-rest encrypt  | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       |
| Audit viewer + verify  | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       |
| Audit export (J/C/PDF) | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       |
| Import/export          | Planned     | Planned (S6)      | Planned (S6)      | Planned (S6)      | Planned (Sprint 6)|
| Auto-lock              | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (Sprint 7)|
| OS keychain            | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (Sprint 7)|
| Packaging              | Planned     | Planned (S8)      | Planned (S8)      | Planned (S8)      | Planned (Sprint 8)|

## License

This project is developed as an applied cryptography project.