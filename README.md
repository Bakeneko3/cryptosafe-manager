# CryptoSafe Manager

CryptoSafe Manager is a cross-platform desktop password manager developed as an applied cryptography project.

The application is designed to securely store password entries in a local database, provide a graphical user interface, protect sensitive data with modern cryptographic primitives, and maintain an auditable history of security-related actions.

> **Current status:** Sprint 1 — Secure Database + GUI Shell

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
│ Crypto / Events / State /   │
│ Settings / Key Management   │
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
│       ├── main_window.py
│       └── settings_dialog.py
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

The Sprint 1 schema contains:

* `vault_entries` — password-manager entries;
* `audit_log` — application event history;
* `settings` — application configuration;
* `key_store` — placeholder storage for future key-management data.

Database schema versioning is implemented using SQLite `PRAGMA user_version`.

Sensitive fields are passed through a placeholder encryption service during Sprint 1. The placeholder uses XOR only for architectural testing and **must not be considered secure encryption**.

Real AES-256-GCM encryption will be implemented in Sprint 3.

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

## Run Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

The Sprint 1 test suite currently contains 23 tests.

## Sprint Roadmap

### Sprint 1 — Secure Database + GUI Shell

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

### Sprint 2 — Master Password + Key Management

* master password setup;
* Argon2 key derivation;
* salt generation;
* key storage;
* key loading;
* key rotation;
* secure memory handling improvements.

### Sprint 3 — Vault CRUD + AES-256-GCM

* create/read/update/delete vault entries;
* AES-256-GCM encryption;
* password generator;
* search and filtering;
* secure encrypted database fields.

### Sprint 4 — Secure Clipboard

* secure clipboard service;
* automatic clipboard clearing;
* configurable timeout;
* clipboard state management;
* clipboard-related events.

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

Sprint 1 contains intentionally insecure placeholders where required by the architecture. These placeholders are temporary and are explicitly marked in the source code.

The final application will use established cryptographic primitives from maintained libraries rather than custom cryptographic algorithms.

## Development Status

| Component              | Sprint 1    |
| ---------------------- | ----------- |
| SQLite database        | Implemented |
| Schema versioning      | Implemented |
| GUI shell              | Implemented |
| Settings               | Implemented |
| Event bus              | Implemented |
| Audit logger           | Implemented |
| Placeholder encryption | Implemented |
| Key manager            | Stub        |
| Backup/restore         | Stub        |
| Master password        | Planned     |
| Argon2                 | Planned     |
| AES-256-GCM            | Planned     |
| Secure clipboard       | Planned     |
| Signed audit logs      | Planned     |
| Import/export          | Planned     |
| Auto-lock              | Planned     |
| Packaging              | Planned     |

## License

This project is developed as an academic applied cryptography project.
