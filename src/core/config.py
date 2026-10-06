from pathlib import Path


import sys


def _get_project_root() -> Path:
    """
    Return the project root directory.

    When running from source, this is the repository root (two levels
    above this file).

    When running from a PyInstaller bundle, this is the directory that
    contains the executable, so that `data/` is written next to the
    `.exe` and not inside the temporary extraction folder.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller bundle: use the executable's directory.
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


PROJECT_ROOT = _get_project_root()

DATA_DIR = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_DIR / "cryptosafe.db"

ENCRYPTION_ALGORITHM = "AES-256-GCM"
ENCRYPTION_PLACEHOLDER = False

DEFAULT_CLIPBOARD_TIMEOUT = 30
DEFAULT_AUTO_LOCK_TIMEOUT = 300

APP_ENV = "development"


# --- Sprint 2: Argon2 parameters (HASH-2, SEC-4) ---
# Argon2id — recommended variant. Secure defaults per OWASP/RFC 9106.
# NOTE: memory_cost is in KiB (65536 KiB = 64 MiB).
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

# Hard upper bounds to prevent DoS via maliciously large settings (SEC-4).
ARGON2_MAX_TIME_COST = 10
ARGON2_MAX_MEMORY_COST = 262144  # 256 MiB
ARGON2_MAX_PARALLELISM = 8


# --- Sprint 2: PBKDF2 parameters (KEY-2) ---
PBKDF2_ITERATIONS = 100_000
PBKDF2_SALT_LEN = 16
PBKDF2_KEY_LEN = 32  # AES-256

# Hard upper bound to prevent DoS (SEC-4).
PBKDF2_MAX_ITERATIONS = 1_000_000


# --- Sprint 2: password policy (HASH-4) ---
PASSWORD_MIN_LENGTH = 12
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SYMBOL = True


# --- Sprint 2: authentication / session (AUTH-3, AUTH-4) ---
AUTH_BACKOFF_DELAYS = {
    1: 1,
    2: 1,
    3: 5,
    4: 5,
    5: 30,
}
AUTH_BACKOFF_DEFAULT = 30


# --- Sprint 2: key cache (CACHE-2) ---
KEY_CACHE_INACTIVITY_TIMEOUT = 3600
KEY_CACHE_DROP_ON_FOCUS_LOSS = False


# --- Sprint 2: key_store schema versioning (KEY-3, DB-1) ---
KEY_STORE_VERSION = 1


# --- Sprint 4: clipboard (CLIP-2, CFG-1, CFG-3) ---
# Auto-clear timeout range and default.
CLIPBOARD_TIMEOUT_DEFAULT = 30
CLIPBOARD_TIMEOUT_MIN = 5
CLIPBOARD_TIMEOUT_MAX = 300  # 5 minutes
CLIPBOARD_TIMEOUT_NEVER = 0  # 0 means "never auto-clear"

# Warning shown N seconds before clearing (UI-3).
CLIPBOARD_WARNING_SECONDS = 5

# How often the monitor polls the system clipboard (seconds).
CLIPBOARD_MONITOR_POLL_INTERVAL = 0.5

# Preset profiles (CFG-3).
CLIPBOARD_PRESETS = {
    "Standard": {
        "timeout": 30,
        "notifications": True,
        "security_level": "basic",
    },
    "Secure": {
        "timeout": 15,
        "notifications": True,
        "security_level": "advanced",
    },
    "Public Computer": {
        "timeout": 5,
        "notifications": True,
        "security_level": "paranoid",
    },
}
CLIPBOARD_DEFAULT_PRESET = "Standard"

# Security levels recognized by the service.
CLIPBOARD_SECURITY_LEVELS = ("basic", "advanced", "paranoid")