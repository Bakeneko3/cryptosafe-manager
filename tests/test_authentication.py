"""Tests for src/core/crypto/authentication.py (HASH-4, AUTH-3, AUTH-4)."""

import pytest

from src.core import config
from src.core.crypto.authentication import (
    AuthSession,
    BackoffPolicy,
    PasswordStrengthValidator,
    ValidationResult,
)


# --------------------------------------------------------------------- #
# PasswordStrengthValidator (HASH-4)
# --------------------------------------------------------------------- #


@pytest.fixture
def validator() -> PasswordStrengthValidator:
    return PasswordStrengthValidator()


def test_valid_strong_password(validator: PasswordStrengthValidator) -> None:
    result = validator.validate("Correct-Horse-Battery-42!")
    assert result.valid
    assert bool(result) is True
    assert result.reasons == ()


def test_rejects_too_short(validator: PasswordStrengthValidator) -> None:
    result = validator.validate("Ab1!x")
    assert not result.valid
    assert any("at least" in r for r in result.reasons)


def test_rejects_missing_uppercase(validator: PasswordStrengthValidator) -> None:
    result = validator.validate("lowercase-1234!")
    assert not result.valid
    assert any("uppercase" in r for r in result.reasons)


def test_rejects_missing_lowercase(validator: PasswordStrengthValidator) -> None:
    result = validator.validate("UPPERCASE-1234!")
    assert not result.valid
    assert any("lowercase" in r for r in result.reasons)


def test_rejects_missing_digit(validator: PasswordStrengthValidator) -> None:
    result = validator.validate("NoDigitsHere!!")
    assert not result.valid
    assert any("digit" in r for r in result.reasons)


def test_rejects_missing_symbol(validator: PasswordStrengthValidator) -> None:
    result = validator.validate("NoSymbols1234")
    assert not result.valid
    assert any("symbol" in r for r in result.reasons)


def test_rejects_empty(validator: PasswordStrengthValidator) -> None:
    result = validator.validate("")
    assert not result.valid


@pytest.mark.parametrize(
    "password",
    [
        "Password123!abc",       # contains 'password'
        "QWERTY-strong-1!",      # contains 'qwerty'
        "LetMeIn-12345!",        # contains 'letmein'
        "Admin-123456!",         # contains 'admin'
        "superman-Strong-1!",    # contains 'superman'
    ],
)
def test_rejects_common_patterns_case_insensitive(
    validator: PasswordStrengthValidator, password: str
) -> None:
    result = validator.validate(password)
    assert not result.valid
    assert any("common pattern" in r for r in result.reasons)


def test_accepts_password_without_common_patterns(
    validator: PasswordStrengthValidator,
) -> None:
    result = validator.validate("Zx9-Lm4-Qw7-Po2!")
    assert result.valid


def test_validation_result_is_falsy_when_invalid() -> None:
    r = ValidationResult(False, ("reason",))
    assert not r
    assert r.valid is False


# --------------------------------------------------------------------- #
# AuthSession (AUTH-4)
# --------------------------------------------------------------------- #


def test_session_starts_inactive() -> None:
    s = AuthSession()
    assert s.is_active is False
    assert s.failed_attempts == 0
    assert s.state.login_at is None


def test_record_login_activates_session() -> None:
    s = AuthSession()
    s.record_login()
    assert s.is_active is True
    assert s.state.login_at is not None
    assert s.state.last_activity_at is not None
    assert s.failed_attempts == 0


def test_record_logout_deactivates_session() -> None:
    s = AuthSession()
    s.record_login()
    s.record_logout()
    assert s.is_active is False
    assert s.state.login_at is None


def test_record_failure_increments() -> None:
    s = AuthSession()
    assert s.record_failure() == 1
    assert s.record_failure() == 2
    assert s.failed_attempts == 2


def test_reset_failures_zeroes_counter() -> None:
    s = AuthSession()
    s.record_failure()
    s.record_failure()
    s.reset_failures()
    assert s.failed_attempts == 0


def test_record_login_resets_failures() -> None:
    s = AuthSession()
    s.record_failure()
    s.record_failure()
    s.record_login()
    assert s.failed_attempts == 0


def test_record_activity_ignored_when_inactive() -> None:
    s = AuthSession()
    s.record_activity()
    assert s.state.last_activity_at is None


def test_record_activity_updates_timestamp() -> None:
    s = AuthSession()
    s.record_login()
    first = s.state.last_activity_at
    s.record_activity()
    assert s.state.last_activity_at >= first


# --------------------------------------------------------------------- #
# BackoffPolicy (AUTH-3)
# --------------------------------------------------------------------- #


def test_backoff_zero_attempts_no_delay() -> None:
    assert BackoffPolicy().delay_for(0) == 0


@pytest.mark.parametrize(
    "attempts, expected",
    [
        (1, 1),
        (2, 1),
        (3, 5),
        (4, 5),
        (5, 30),
    ],
)
def test_backoff_follows_config(attempts: int, expected: int) -> None:
    assert BackoffPolicy().delay_for(attempts) == expected


def test_backoff_uses_default_beyond_table() -> None:
    assert BackoffPolicy().delay_for(6) == config.AUTH_BACKOFF_DEFAULT
    assert BackoffPolicy().delay_for(99) == config.AUTH_BACKOFF_DEFAULT


def test_backoff_accepts_custom_table() -> None:
    policy = BackoffPolicy(delays={1: 2, 2: 4}, default=100)
    assert policy.delay_for(1) == 2
    assert policy.delay_for(2) == 4
    assert policy.delay_for(3) == 100