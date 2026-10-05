# CryptoSafe Manager

CryptoSafe Manager is a cross-platform desktop password manager developed as an applied cryptography project.

The application is designed to securely store password entries in a local database, provide a graphical user interface, protect sensitive data with modern cryptographic primitives, and maintain an auditable history of security-related actions.

> **Current status:** Sprint 4 — Secure Clipboard

## Project Vision

CryptoSafe Manager aims to provide a local-first password management application with:

* encrypted password storage;
* secure master-password-based key management;
* AES-256-GCM encryption;
* secure clipboard handling;
* automatic locking;
* audit logging and integrity protection;
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
│ Events / Settings / Keys    │
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

The schema (version 3) contains:

* `vault_entries` — password-manager entries, each stored as a single
  opaque blob (`encrypted_data`) with a UUID primary key;
* `deleted_entries` — soft-deleted entries with an expiration timestamp;
* `audit_log` — application event history;
* `settings` — application configuration;
* `key_store` — master-password authentication hash, PBKDF2 salt, and
  versioned KDF parameters.

Database schema versioning is implemented using SQLite `PRAGMA user_version`. Migrations run automatically on startup.

## Security Model

### Master password

* The master password itself is **never stored**.
* An Argon2id hash of the password is stored in `key_store` for verification.
* A PBKDF2-HMAC-SHA256 key is derived from the password and a unique
  16-byte salt to obtain the AES-256 encryption key.
* The encryption key is held only in memory (`KeyCache`) and is never
  written to disk.
* Failed login attempts trigger exponential backoff (1s / 5s / 30s).
* Password change re-encrypts all vault entries atomically.

### Per-entry encryption

* Every vault entry is serialized to JSON and encrypted individually
  with **AES-256-GCM** (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`).
* A fresh 12-byte nonce is generated per encryption using `os.urandom(12)`.
* The stored blob has the format `nonce (12 B) || ciphertext || tag (16 B)`.
* The authentication tag is verified on decryption; tampering is detected
  and rejected.

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
* The clipboard requires the vault to be unlocked; copy operations are
  blocked on a locked vault.

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
* **Preset profiles** for quick configuration:
  * *Standard* — 30 s timeout, basic security.
  * *Secure* — 15 s timeout, advanced security.
  * *Public Computer* — 5 s timeout, paranoid mode.
* **Platform adapters**:
  * Windows: `win32clipboard` (native `EmptyClipboard`).
  * Fallback: `pyperclip` for other platforms.
* **Monitor:** detects external content changes and drops ownership;
  degrades gracefully if the clipboard cannot be read.

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
* `Ctrl+Shift+P` — toggle username visibility
* `Ctrl+Shift+C` — clear the clipboard

## Run Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

The current test suite covers crypto, key management, vault CRUD,
search, password generation, clipboard behaviour, and GUI smoke tests.

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
* clipboard settings dialog with presets
  (*Standard*, *Secure*, *Public Computer*);
* platform adapters for Windows (`win32clipboard`) and generic
  (`pyperclip`);
* background monitor detecting external clipboard changes;
* integration with the event bus (`ClipboardCopied`, `ClipboardCleared`);
* audit logging of every clipboard operation;
* toolbar, menu, and context-menu actions for copy / clear;
* live countdown in the status bar;
* clipboard cleared on lock and on application close;
* integration tests for timing, concurrency, recovery, and performance.

### Sprint 5 — Audit Logs + Integrity

* authenticated audit records;
* HMAC/Ed25519 integrity mechanisms;
* tamper detection;
* signed JSON export.

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

Sprint 1 introduced intentionally insecure placeholders where required by the architecture. Sprint 2 introduced the real master-password and key derivation layer. Sprint 3 replaced the placeholder entry encryption with real AES-256-GCM. Sprint 4 added secure clipboard handling with auto-clear and monitoring.

The final application uses established cryptographic primitives from maintained libraries rather than custom cryptographic algorithms.

## Development Status

| Component              | Sprint 1    | Sprint 2          | Sprint 3          | Sprint 4          |
| ---------------------- | ----------- | ----------------- | ----------------- | ----------------- |
| SQLite database        | Implemented | Implemented       | Implemented       | Implemented       |
| Schema versioning      | Implemented | Implemented       | Implemented       | Implemented       |
| Migration system       | Basic       | Implemented       | Implemented       | Implemented       |
| GUI shell              | Implemented | Implemented       | Implemented       | Implemented       |
| Settings               | Implemented | Implemented       | Implemented       | Implemented       |
| Event bus              | Implemented | Implemented       | Implemented       | Implemented       |
| Audit logger           | Implemented | Implemented       | Implemented       | Implemented       |
| Key manager            | Stub        | Implemented       | Implemented       | Implemented       |
| Backup/restore         | Stub        | Stub              | Stub              | Stub              |
| Master password        | Planned     | Implemented       | Implemented       | Implemented       |
| Argon2id hashing       | Planned     | Implemented       | Implemented       | Implemented       |
| PBKDF2 key derivation  | Planned     | Implemented       | Implemented       | Implemented       |
| Key caching            | Planned     | Implemented       | Implemented       | Implemented       |
| Failed-login backoff   | Planned     | Implemented       | Implemented       | Implemented       |
| Password change        | Planned     | Implemented       | Implemented       | Implemented       |
| AES-256-GCM            | Planned     | Planned (S3)      | Implemented       | Implemented       |
| Vault CRUD             | Planned     | Planned (S3)      | Implemented       | Implemented       |
| Password generator     | Planned     | Planned (S3)      | Implemented       | Implemented       |
| Search / filter        | Planned     | Planned (S3)      | Implemented       | Implemented       |
| Soft delete            | Planned     | Planned (S3)      | Implemented       | Implemented       |
| Secure clipboard       | Planned     | Planned (S4)      | Planned (S4)      | Implemented       |
| Clipboard auto-clear   | Planned     | Planned (S4)      | Planned (S4)      | Implemented       |
| Clipboard settings     | Planned     | Planned (S4)      | Planned (S4)      | Implemented       |
| Clipboard monitor      | Planned     | Planned (S4)      | Planned (S4)      | Implemented       |
| Signed audit logs      | Planned     | Planned (S5)      | Planned (S5)      | Planned (Sprint 5)|
| Import/export          | Planned     | Planned (S6)      | Planned (S6)      | Planned (Sprint 6)|
| Auto-lock              | Planned     | Planned (S7)      | Planned (S7)      | Planned (Sprint 7)|
| OS keychain            | Planned     | Planned (S7)      | Planned (S7)      | Planned (Sprint 7)|
| Packaging              | Planned     | Planned (S8)      | Planned (S8)      | Planned (Sprint 8)|

## License

This project is developed as an applied cryptography project.