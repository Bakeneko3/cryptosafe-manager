# CryptoSafe Manager

CryptoSafe Manager is a cross-platform desktop password manager developed as an applied cryptography project.

The application securely stores password entries in a local database, provides a graphical user interface, protects sensitive data with modern cryptographic primitives, and maintains a tamper-evident history of security-related actions.

> **Current status:** Sprint 8 — Final Integration, Testing + Documentation

## Project Vision

CryptoSafe Manager is a local-first password management application with:

* encrypted password storage;
* secure master-password-based key management;
* AES-256-GCM encryption;
* secure clipboard handling;
* automatic locking with inactivity detection;
* tamper-evident audit logging;
* encrypted import/export and secure sharing;
* memory protection and panic mode;
* automated security testing.

Real cryptographic mechanisms were introduced incrementally across eight sprints.

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
│   └── report/
│
├── docs/
│   ├── user_guide.md
│   └── technical.md
│
├── run.py
├── CryptoSafeManager.spec
├── requirements.txt
├── pytest.ini
├── .gitignore
└── README.md
```

## Database

The application uses SQLite.

Schema version 6 contains:

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

Schema versioning uses SQLite `PRAGMA user_version`. Migrations run automatically on startup.

## Security Model

### Master password

* The master password is **never stored**.
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
* Every entry is signed with **Ed25519** using an HKDF-derived key.
* Entry payloads are **AES-256-GCM encrypted at rest** with a separate
  HKDF-derived key.
* Automatic verification on every successful login; manual verification
  available in the viewer.
* The log is **append-only**; sensitive fields are sanitized before
  writing.

### Import/Export & Sharing

* **Exports** support password-based (PBKDF2 + AES-256-GCM) and
  public-key (RSA-2048-OAEP or ECIES P-256 + AES-256-GCM) encryption.
* **Plaintext exports** are allowed only for CSV migration.
* Every export carries an **integrity hash** and an **Ed25519 signature**.
* **Imports** validate format, verify integrity, and pass every entry
  through an **anti-malware filter**.
* **Sharing** produces single-entry packages with permissions and
  expiration metadata.
* **QR codes** encode share packages in chunks with per-chunk checksums,
  nonce-based replay protection, and a 5-minute validity window.

### Clipboard

* Clipboard content is written **plaintext** to the system clipboard.
* Protection relies on **auto-clear** and explicit user actions.
* Auto-clear is **configurable** (5 s – 5 min, default 30 s, or never).
* The clipboard is cleared on timer expiry, manual clear, lock, close,
  or new content replacement.
* A background monitor detects external content changes and drops
  ownership accordingly.

### Security hardening

* **Constant-time primitives** (`side_channel_protection.py`) for
  security-critical comparisons.
* **Secure memory management** (`memory_guard.py`): best-effort
  `mlock` / `VirtualLock`, explicit zeroing, `SecretHolder`.
* **Activity monitoring and auto-lock** (`activity_monitor.py`):
  application-level activity plus Windows `GetLastInputInfo`.
* **Panic mode** (`panic_mode.py`): hotkey `Ctrl+Shift+Q` and tray menu;
  runs registered handlers in order (lock, wipe, clear, hide); optional
  stealth; logs `panic_activated`.
* **Security profiles** (`security_profiles.py`):
  * *Standard* — 5-minute auto-lock, 30-second clipboard.
  * *Enhanced* — 2-minute auto-lock, 15-second clipboard, tray.
  * *Paranoid* — 1-minute auto-lock, 5-second clipboard, stealth panic.
* **System tray** (`tray_icon.py`) with lock state, quick actions, and
  notifications.

Argon2id parameters:

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
* **Soft delete:** deleted entries go to `deleted_entries` with a 30-day
  expiration before permanent removal.
* **Password generator:** CSPRNG-based (`secrets`), configurable length
  and character sets, one-per-set guarantees, optional ambiguous-character
  exclusion, rolling 20-entry history.
* **Search:** in-memory full-text search across title, username, URL,
  notes, category, and tags; field-specific filters and optional fuzzy
  matching.
* **Table:** multi-select, sortable columns, context menu, global
  username toggle.

## Clipboard Features

* **Copy Password / Username / All** from toolbar, menu, or context menu.
* **Auto-clear** with live countdown in the status bar.
* **Warning** shown a few seconds before the automatic clear.
* **Clear Clipboard** in toolbar, menu, and context menu.
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
  fields, password / public-key / plaintext encryption, optional GZIP.
* **Import:** format auto-detection, merge / replace / dry-run, duplicate
  skipping, anti-malware sanitization, size and timeout limits.
* **Sharing:** password-protected or public-key encrypted single-entry
  packages with permissions and expiration metadata.
* **QR codes:** chunked generation, per-chunk checksum, nonce-based
  replay protection, 5-minute validity, decoding via `pyzbar`.

## Security Hardening Features

* Constant-time comparison for security-critical equality.
* Best-effort memory locking (`mlock` / `VirtualLock`) with explicit
  zeroing.
* Auto-lock based on application and system inactivity.
* Panic mode via hotkey or tray.
* Security profiles that bundle timeouts, memory locking, and panic
  behaviour.
* System tray integration with lock state and quick actions.

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

## Run from Source

From the project root:

```powershell
python run.py
```

or, equivalently:

```powershell
python -m src.gui.main_window
```

On first run, a setup wizard asks for a master password. On subsequent
runs, a login dialog requests the same password to unlock the vault.

## Build the Executable

A PyInstaller spec is provided. From the project root:

```powershell
pyinstaller --clean --noconfirm CryptoSafeManager.spec
```

Output:

```text
dist/CryptoSafeManager/CryptoSafeManager.exe
```

The database is created next to the executable, in
`dist/CryptoSafeManager/data/cryptosafe.db`.

## Run Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

Coverage:

```powershell
python -m pytest --cov=src --cov-report=term-missing
```

Generate an HTML coverage report into `tests/report/htmlcov/`:

```powershell
python -m pytest --cov=src --cov-report=html:tests/report/htmlcov --cov-report=term-missing -v 2>&1 | Tee-Object -FilePath tests/report/pytest_output.txt
```

The test suite currently contains over 700 tests covering crypto, key
management, vault CRUD, search, password generation, clipboard
behaviour, audit signing and verification, log export, import/export
round-trips, sharing, QR generation and decoding, security primitives,
auto-lock, panic mode, and GUI smoke tests. Overall coverage is 80%.

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

## Documentation

Additional documentation lives under `docs/`:

* `docs/user_guide.md` — end-user guide (installation, first run,
  daily usage, import/export, sharing, clipboard, panic mode).
* `docs/technical.md` — architecture, cryptographic design, database
  schema, and implementation notes.

## Sprint Roadmap

### Sprint 1 — Secure Database + GUI Shell (done)

### Sprint 2 — Master Password + Key Management (done)

### Sprint 3 — Vault CRUD + AES-256-GCM (done)

### Sprint 4 — Secure Clipboard (done)

### Sprint 5 — Audit Logs + Integrity (done)

### Sprint 6 — Encrypted Import/Export + Secure Sharing (done)

### Sprint 7 — Hardening + UX (done)

### Sprint 8 — Final Integration, Testing + Documentation (done)

* all modules from Sprints 1-7 integrated and tested together;
* test suite expanded and verified at 80% overall coverage;
* HTML coverage report generated into `tests/report/`;
* PyInstaller packaging with a reproducible spec file
  (`CryptoSafeManager.spec`);
* `run.py` entry point for running from source;
* database path resolution updated to work in frozen bundles;
* README finalised with setup, usage, packaging, and testing
  instructions.

## Security Development Model

Cryptographic functionality was introduced progressively:

* **Sprint 1** — architecture, SQLite schema, placeholder encryption.
* **Sprint 2** — Argon2id hashing, PBKDF2 key derivation, key cache,
  authentication, password rotation.
* **Sprint 3** — AES-256-GCM per-entry encryption, vault CRUD, secure
  password generator, search.
* **Sprint 4** — secure clipboard with auto-clear, monitor, presets.
* **Sprint 5** — tamper-evident audit log with hash chain, Ed25519
  signatures, and per-entry AES-GCM at rest.
* **Sprint 6** — encrypted import/export, secure sharing, QR key
  exchange.
* **Sprint 7** — side-channel and memory hardening, auto-lock, panic
  mode, security profiles, system tray.
* **Sprint 8** — integration, testing, packaging, documentation.

The final application uses established cryptographic primitives from
maintained libraries rather than custom cryptographic algorithms.

## Known Limitations

* The executable is built for the developer's own OS (Windows) only.
* Backup/restore is still a stub; only the audit log can be exported.
* No network features: sharing uses local files or QR codes.
* macOS and Linux platform-specific hardening (Keychain Services,
  kernel keyring, Touch ID) is out of scope.
* QR decoding depends on `pyzbar` and the system `zbar` library.

## Development Status

| Component              | Sprint 8    |
| ---------------------- | ----------- |
| SQLite database        | Implemented |
| Migration system       | Implemented |
| GUI shell              | Implemented |
| Settings               | Implemented |
| Event bus              | Implemented |
| Key manager            | Implemented |
| Master password        | Implemented |
| Argon2id hashing       | Implemented |
| PBKDF2 key derivation  | Implemented |
| HKDF key separation    | Implemented |
| AES-256-GCM (vault)    | Implemented |
| Vault CRUD             | Implemented |
| Search / filter        | Implemented |
| Secure clipboard       | Implemented |
| Signed audit log       | Implemented |
| Import / export        | Implemented |
| Secure sharing         | Implemented |
| QR key exchange        | Implemented |
| Constant-time prims    | Implemented |
| Secure memory          | Implemented |
| Auto-lock              | Implemented |
| Panic mode             | Implemented |
| Security profiles      | Implemented |
| System tray            | Implemented |
| Test suite             | 700+ tests  |
| Test coverage          | 80%         |
| PyInstaller build      | Implemented |
| Backup/restore         | Stub        |
| OS keychain            | Planned     |

## License

This project is developed as an applied cryptography project.