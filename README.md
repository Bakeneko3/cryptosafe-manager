# CryptoSafe Manager

CryptoSafe Manager is a cross-platform desktop password manager developed as an applied cryptography project.

The application is designed to securely store password entries in a local database, provide a graphical user interface, protect sensitive data with modern cryptographic primitives, and maintain a tamper-evident history of security-related actions.

> **Current status:** Sprint 7 — Security Hardening + UX

## Project Vision

CryptoSafe Manager aims to provide a local-first password management application with:

* encrypted password storage;
* secure master-password-based key management;
* AES-256-GCM encryption;
* secure clipboard handling;
* automatic locking with inactivity detection;
* tamper-evident audit logging;
* encrypted import/export and secure sharing;
* memory protection and panic mode;
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
│ Security / Events / Settings│
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
│   │   ├── vault/
│   │   ├── clipboard/
│   │   ├── audit/
│   │   ├── import_export/
│   │   ├── security/
│   │   │   ├── activity_monitor.py
│   │   │   ├── memory_guard.py
│   │   │   ├── panic_mode.py
│   │   │   ├── security_profiles.py
│   │   │   ├── side_channel_protection.py
│   │   │   └── tray_icon.py
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
│       ├── security_settings_dialog.py
│       ├── settings_dialog.py
│       ├── setup_wizard.py
│       └── sharing_dialog.py
│
├── tests/
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

### Import/Export & Sharing

* **Exports** support two encryption modes:
  * **Password-based:** PBKDF2-HMAC-SHA256 (100,000 iterations) + AES-256-GCM,
    with a fresh random salt and nonce per export.
  * **Public-key:** hybrid encryption — RSA-2048-OAEP or ECIES-style
    ephemeral ECDH P-256, both wrapping an AES-256-GCM payload.
* **Plaintext exports** are allowed only for CSV migration.
* Every export carries an **integrity hash** (SHA-256 of the plaintext)
  and an **Ed25519 signature** for provenance.
* **Imports** validate format, verify the integrity hash, and pass every
  entry through an **anti-malware filter**.
* **Sharing** produces a single-entry package encrypted with a
  password or the recipient's public key.
* **QR codes** encode share packages in chunks with a per-chunk
  checksum, a nonce to prevent replay, and a 5-minute validity window.

### Clipboard

* All clipboard content is written **plaintext** to the system clipboard.
* Protection relies on **auto-clear** and explicit user actions.
* Auto-clear is **configurable** (5 s – 5 min, default 30 s, or never).
* The clipboard is cleared on timer expiry, manual clear, lock, close,
  or new content replacement.
* A background monitor detects **content changes** made outside the
  application and drops ownership accordingly.

### Sprint 7 — Security hardening

* **Constant-time primitives** (`side_channel_protection.py`):
  * `constant_time_compare` wraps `secrets.compare_digest` for byte
    and string comparison in security-critical paths;
  * `constant_time_select` for branch-free small selections;
  * secure randomness helpers built on `secrets`.

* **Secure memory management** (`memory_guard.py`):
  * best-effort `mlock` (Unix) / `VirtualLock` (Windows) to prevent
    swapping sensitive buffers to disk;
  * explicit zeroing via `ctypes.memset` on free;
  * `SecretHolder` copies bytes into a locked buffer and wipes the
    original if it was mutable.

* **Activity monitoring and auto-lock** (`activity_monitor.py`):
  * tracks application-level activity (mouse, keyboard, focus);
  * on Windows, also uses `GetLastInputInfo` for system-wide idle time;
  * fires a lock callback when the configured timeout is exceeded;
  * timeout configurable (1 minute to 8 hours, default 5 minutes).

* **Panic mode** (`panic_mode.py`):
  * hotkey `Ctrl+Shift+Q` and tray menu entry;
  * registered handlers run in order: lock vault, wipe memory,
    clear clipboard, hide windows;
  * optional stealth mode shows a fake error message;
  * logs a `panic_activated` event to the audit log.

* **Security profiles** (`security_profiles.py`):
  * *Standard*: 5-minute auto-lock, 30-second clipboard.
  * *Enhanced*: 2-minute auto-lock, 15-second clipboard, starts to tray.
  * *Paranoid*: 1-minute auto-lock, 5-second clipboard, stealth panic.

* **System tray** (`tray_icon.py`):
  * icon color reflects lock state (red locked, green unlocked);
  * menu with Show / Lock / Clear Clipboard / Panic / Settings / Exit;
  * notifications for security events;
  * all callbacks dispatched to the Tk main thread.

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
  notes, category, and tags. Field-specific filters and optional fuzzy
  matching.
* **Table:** multi-select, sortable columns, context menu, global
  username toggle.

## Clipboard Features

* **Copy Password / Username / All** from toolbar, menu, or context menu.
* **Auto-clear** with a live countdown in the status bar.
* **Warning** shown a few seconds before the automatic clear.
* **Clear Clipboard** action available in the toolbar, menu, and context
  menu.
* **Preset profiles**: *Standard*, *Secure*, *Public Computer*.
* **Platform adapters**: Windows (`win32clipboard`) and generic
  (`pyperclip`).
* **Monitor**: detects external content changes; degrades gracefully.

## Audit Log Features

* **Tamper-evident**: hash chain + Ed25519 signatures + AES-GCM at rest.
* **Viewer**: sortable, filterable, searchable, with details panel.
* **Manual verification** and **automatic verification** on every login.
* **Export** to signed JSON (independently verifiable), CSV, and PDF.
* **Severity levels**: `INFO`, `WARN`, `ERROR`, `CRITICAL`.

## Import / Export & Sharing Features

* **Export formats:** CryptoSafe native JSON, CSV, Bitwarden JSON,
  LastPass CSV.
* **Export options:** whole vault or selected entries, include/exclude
  individual fields, password / public-key / plaintext encryption,
  optional GZIP compression.
* **Import:** format auto-detection, merge / replace / dry-run modes,
  duplicate skipping, anti-malware sanitization, file size and time
  limits.
* **Sharing:** password-protected or public-key encrypted single-entry
  packages with permissions and expiration metadata.
* **QR codes:** chunked generation, per-chunk checksum, nonce-based
  replay protection, 5-minute validity, decoding via `pyzbar`.

## Security Hardening Features

* **Constant-time comparison** for security-critical byte/string
  equality.
* **Best-effort memory locking** (`mlock` / `VirtualLock`) with explicit
  zeroing of sensitive buffers.
* **Auto-lock** based on application and system inactivity, with
  configurable timeouts.
* **Panic mode** triggered by hotkey or tray, immediately locking the
  vault and clearing sensitive state.
* **Security profiles** that bundle timeouts, memory locking, and panic
  behaviour.
* **System tray integration** with quick lock / unlock, panic, and
  status indication.

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
* `Ctrl+Shift+Q` — activate panic mode

## Run Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

The current test suite covers crypto, key management, vault CRUD,
search, password generation, clipboard behaviour, audit signing and
verification, log export, import/export round-trips, sharing, QR
generation and decoding, security primitives, auto-lock, panic mode,
and GUI smoke tests.

## Sprint Roadmap

### Sprint 1 — Secure Database + GUI Shell (done)

### Sprint 2 — Master Password + Key Management (done)

### Sprint 3 — Vault CRUD + AES-256-GCM (done)

### Sprint 4 — Secure Clipboard (done)

### Sprint 5 — Audit Logs + Integrity (done)

### Sprint 6 — Encrypted Import/Export + Secure Sharing (done)

### Sprint 7 — Hardening + UX (done)

* constant-time comparison primitives;
* secure memory handling with best-effort mlock/VirtualLock;
* automatic locking with inactivity detection;
* panic mode with hotkey, tray, and audit logging;
* security profiles (Standard, Enhanced, Paranoid);
* system tray integration with lock state and quick actions;
* security settings dialog and profile persistence.

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

Sprint 1 introduced intentionally insecure placeholders where required by the architecture. Sprint 2 introduced the real master-password and key derivation layer. Sprint 3 replaced the placeholder entry encryption with real AES-256-GCM. Sprint 4 added secure clipboard handling with auto-clear and monitoring. Sprint 5 made the audit log tamper-evident with Ed25519 signatures, a SHA-256 hash chain, and per-entry AES-GCM encryption at rest. Sprint 6 introduced encrypted import/export, secure sharing, and QR-code key exchange. Sprint 7 added side-channel and memory hardening, auto-lock, panic mode, security profiles, and system tray integration.

The final application uses established cryptographic primitives from maintained libraries rather than custom cryptographic algorithms.

## Development Status

| Component              | S1          | S2                | S3                | S4                | S5                | S6                | S7                |
| ---------------------- | ----------- | ----------------- | ----------------- | ----------------- | ----------------- | ----------------- | ----------------- |
| SQLite database        | Implemented | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Migration system       | Basic       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| GUI shell              | Implemented | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Settings               | Implemented | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Event bus              | Implemented | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Key manager            | Stub        | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Backup/restore         | Stub        | Stub              | Stub              | Stub              | Stub              | Stub              | Stub              |
| Master password        | Planned     | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Argon2id hashing       | Planned     | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| PBKDF2 key derivation  | Planned     | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| HKDF key separation    | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       | Implemented       | Implemented       |
| AES-256-GCM (vault)    | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Vault CRUD             | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Search / filter        | Planned     | Planned (S3)      | Implemented       | Implemented       | Implemented       | Implemented       | Implemented       |
| Secure clipboard       | Planned     | Planned (S4)      | Planned (S4)      | Implemented       | Implemented       | Implemented       | Implemented       |
| Signed audit log       | Planned     | Planned (S5)      | Planned (S5)      | Planned (S5)      | Implemented       | Implemented       | Implemented       |
| Import / export        | Planned     | Planned (S6)      | Planned (S6)      | Planned (S6)      | Planned (S6)      | Implemented       | Implemented       |
| Secure sharing         | Planned     | Planned (S6)      | Planned (S6)      | Planned (S6)      | Planned (S6)      | Implemented       | Implemented       |
| QR key exchange        | Planned     | Planned (S6)      | Planned (S6)      | Planned (S6)      | Planned (S6)      | Implemented       | Implemented       |
| Constant-time prims    | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Implemented       |
| Secure memory          | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Implemented       |
| Auto-lock              | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Implemented       |
| Panic mode             | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Implemented       |
| Security profiles      | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Implemented       |
| System tray            | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Implemented       |
| OS keychain            | Planned     | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (S7)      | Planned (Sprint 8)|
| Packaging              | Planned     | Planned (S8)      | Planned (S8)      | Planned (S8)      | Planned (S8)      | Planned (S8)      | Planned (Sprint 8)|

## License

This project is developed as an applied cryptography project.