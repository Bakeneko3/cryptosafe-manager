"""
Authentication helpers: password strength validation, session tracking,
and exponential backoff for failed login attempts.

This module is pure business logic: no database, no GUI, no events.
The KeyManager facade wires it together with storage and the event bus.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.core import config


# --------------------------------------------------------------------- #
# Password strength
# --------------------------------------------------------------------- #


# Common weak patterns (case-insensitive substring match).
COMMON_PATTERNS: tuple[str, ...] = (
    "password",
    "passwd",
    "qwerty",
    "qwerty123",
    "123456",
    "12345678",
    "123456789",
    "111111",
    "000000",
    "abc123",
    "letmein",
    "welcome",
    "admin",
    "root",
    "login",
    "iloveyou",
    "monkey",
    "dragon",
    "master",
    "shadow",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "superman",
    "trustno1",
)


@dataclass(frozen=True)
class ValidationResult:
    """Result of a password strength check."""

    valid: bool
    reasons: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.valid


class PasswordStrengthValidator:
    """
    Validates master-password strength against a policy.

    Policy is read from `src.core.config`:
      * minimum length,
      * required character classes,
      * rejected common patterns.
    """

    def __init__(
        self,
        *,
        min_length: int = config.PASSWORD_MIN_LENGTH,
        require_uppercase: bool = config.PASSWORD_REQUIRE_UPPERCASE,
        require_lowercase: bool = config.PASSWORD_REQUIRE_LOWERCASE,
        require_digit: bool = config.PASSWORD_REQUIRE_DIGIT,
        require_symbol: bool = config.PASSWORD_REQUIRE_SYMBOL,
        common_patterns: tuple[str, ...] = COMMON_PATTERNS,
    ) -> None:
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_symbol = require_symbol
        self.common_patterns = tuple(p.lower() for p in common_patterns)

    def validate(self, password: str) -> ValidationResult:
        reasons: list[str] = []

        if not password:
            return ValidationResult(False, ("password must not be empty",))

        if len(password) < self.min_length:
            reasons.append(
                f"password must be at least {self.min_length} characters"
            )

        if self.require_uppercase and not re.search(r"[A-Z]", password):
            reasons.append("password must contain an uppercase letter")

        if self.require_lowercase and not re.search(r"[a-z]", password):
            reasons.append("password must contain a lowercase letter")

        if self.require_digit and not re.search(r"[0-9]", password):
            reasons.append("password must contain a digit")

        if self.require_symbol and not re.search(r"[^A-Za-z0-9]", password):
            reasons.append("password must contain a symbol")

        lowered = password.lower()
        for pattern in self.common_patterns:
            if pattern in lowered:
                reasons.append(
                    f"password must not contain the common pattern "
                    f"'{pattern}'"
                )
                break

        if reasons:
            return ValidationResult(False, tuple(reasons))
        return ValidationResult(True, ())


# --------------------------------------------------------------------- #
# Session state
# --------------------------------------------------------------------- #


@dataclass
class SessionState:
    """Authentication session metadata (AUTH-4)."""

    login_at: datetime | None = None
    last_activity_at: datetime | None = None
    failed_attempts: int = 0

    @property
    def is_active(self) -> bool:
        return self.login_at is not None


class AuthSession:
    """
    Tracks login timestamp, last activity, and failed attempt count.

    The session does not decide *when* to lock; it only records state.
    Locking policy belongs to StateManager / KeyManager.
    """

    def __init__(self) -> None:
        self._state = SessionState()

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def failed_attempts(self) -> int:
        return self._state.failed_attempts

    @property
    def is_active(self) -> bool:
        return self._state.is_active

    def record_login(self) -> None:
        now = datetime.now(timezone.utc)
        self._state.login_at = now
        self._state.last_activity_at = now
        self._state.failed_attempts = 0

    def record_logout(self) -> None:
        self._state.login_at = None
        self._state.last_activity_at = None

    def record_activity(self) -> None:
        if self._state.is_active:
            self._state.last_activity_at = datetime.now(timezone.utc)

    def record_failure(self) -> int:
        self._state.failed_attempts += 1
        return self._state.failed_attempts

    def reset_failures(self) -> None:
        self._state.failed_attempts = 0


# --------------------------------------------------------------------- #
# Exponential backoff
# --------------------------------------------------------------------- #


class BackoffPolicy:
    """
    Maps a failed-attempt count to a delay (AUTH-3).

    The delay is *returned*, not applied: the caller decides whether to
    sleep, block the UI, or just inform the user. This keeps the policy
    trivially testable.
    """

    def __init__(
        self,
        delays: dict[int, int] | None = None,
        default: int | None = None,
    ) -> None:
        self.delays = dict(delays or config.AUTH_BACKOFF_DELAYS)
        self.default = (
            default if default is not None else config.AUTH_BACKOFF_DEFAULT
        )

    def delay_for(self, failed_attempts: int) -> int:
        if failed_attempts <= 0:
            return 0
        return self.delays.get(failed_attempts, self.default)