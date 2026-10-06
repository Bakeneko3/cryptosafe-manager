"""Tests for src/core/vault/password_generator.py (GEN-1..3, GEN-5, TEST-4)."""

import string

import pytest

from src.core.vault.password_generator import (
    AMBIGUOUS,
    DIGITS,
    LOWERCASE,
    MAX_LENGTH,
    MIN_LENGTH,
    SYMBOLS,
    UPPERCASE,
    GeneratorConfig,
    PasswordGenerator,
)


# --------------------------------------------------------------------- #
# Configuration validation (GEN-2)
# --------------------------------------------------------------------- #


def test_default_config_is_valid() -> None:
    GeneratorConfig().validate()


@pytest.mark.parametrize("length", [MIN_LENGTH, 12, 16, 32, 64, MAX_LENGTH])
def test_valid_lengths(length: int) -> None:
    GeneratorConfig(length=length).validate()


@pytest.mark.parametrize("length", [7, 0, -1, 65, 100])
def test_invalid_lengths_rejected(length: int) -> None:
    with pytest.raises(ValueError):
        GeneratorConfig(length=length).validate()


def test_no_charset_selected_rejected() -> None:
    cfg = GeneratorConfig(
        uppercase=False,
        lowercase=False,
        digits=False,
        symbols=False,
    )
    with pytest.raises(ValueError):
        cfg.validate()


def test_too_short_for_selected_sets_rejected() -> None:
    # 4 sets selected, length 3 cannot include one of each.
    cfg = GeneratorConfig(
        length=MIN_LENGTH,
        uppercase=True,
        lowercase=True,
        digits=True,
        symbols=True,
    )
    cfg.length = 3
    with pytest.raises(ValueError):
        cfg.validate()


# --------------------------------------------------------------------- #
# GEN-1: CSPRNG — no crashes, output non-empty
# --------------------------------------------------------------------- #


def test_generate_returns_string_of_correct_length() -> None:
    gen = PasswordGenerator(GeneratorConfig(length=20))
    pw = gen.generate()
    assert isinstance(pw, str)
    assert len(pw) == 20


@pytest.mark.parametrize("length", [8, 12, 16, 24, 32, 64])
def test_generate_respects_length(length: int) -> None:
    gen = PasswordGenerator(GeneratorConfig(length=length))
    assert len(gen.generate()) == length


# --------------------------------------------------------------------- #
# GEN-3: at least one char from each selected set
# --------------------------------------------------------------------- #


def test_generate_contains_all_selected_sets() -> None:
    gen = PasswordGenerator(
        GeneratorConfig(length=32),
    )
    for _ in range(50):
        pw = gen.generate()
        assert any(c in UPPERCASE for c in pw)
        assert any(c in LOWERCASE for c in pw)
        assert any(c in DIGITS for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_generate_only_lowercase_when_others_disabled() -> None:
    gen = PasswordGenerator(
        GeneratorConfig(
            length=16,
            uppercase=False,
            digits=False,
            symbols=False,
        )
    )
    pw = gen.generate()
    assert all(c in LOWERCASE for c in pw)


def test_generate_two_sets_only() -> None:
    gen = PasswordGenerator(
        GeneratorConfig(
            length=16,
            uppercase=False,
            symbols=False,
            lowercase=True,
            digits=True,
        )
    )
    for _ in range(20):
        pw = gen.generate()
        assert any(c in LOWERCASE for c in pw)
        assert any(c in DIGITS for c in pw)
        assert not any(c in UPPERCASE for c in pw)
        assert not any(c in SYMBOLS for c in pw)


# --------------------------------------------------------------------- #
# GEN-2: exclude ambiguous
# --------------------------------------------------------------------- #


def test_exclude_ambiguous_removes_chars() -> None:
    gen = PasswordGenerator(
        GeneratorConfig(length=32, exclude_ambiguous=True),
    )
    for _ in range(50):
        pw = gen.generate()
        for ch in AMBIGUOUS:
            assert ch not in pw


def test_exclude_ambiguous_keeps_required_sets() -> None:
    gen = PasswordGenerator(
        GeneratorConfig(
            length=64,
            exclude_ambiguous=True,
        )
    )
    pw = gen.generate()
    assert any(c in UPPERCASE for c in pw)
    assert any(c in LOWERCASE for c in pw)
    assert any(c in DIGITS for c in pw)
    assert any(c in SYMBOLS for c in pw)


# --------------------------------------------------------------------- #
# GEN-5: history prevents recent duplicates
# --------------------------------------------------------------------- #


def test_history_size_default() -> None:
    gen = PasswordGenerator()
    assert len(gen.history) == 0
    for _ in range(5):
        gen.generate()
    assert len(gen.history) == 5


def test_history_is_bounded() -> None:
    gen = PasswordGenerator(GeneratorConfig(length=16), history_size=5)
    for _ in range(20):
        gen.generate()
    assert len(gen.history) == 5


def test_no_duplicates_in_history_short_window() -> None:
    gen = PasswordGenerator(GeneratorConfig(length=32), history_size=20)
    for _ in range(200):
        gen.generate()
    # Because deque only keeps last 20, check within that window.
    assert len(set(gen.history)) == len(gen.history)


# --------------------------------------------------------------------- #
# TEST-4: bulk generation
# --------------------------------------------------------------------- #


@pytest.mark.slow
@pytest.mark.perf
def test_bulk_generation_unique_and_compliant() -> None:
    """TEST-4 (reduced): 1000 generations, check uniqueness + policy."""
    gen = PasswordGenerator(GeneratorConfig(length=16), history_size=20)
    seen: set[str] = set()
    for _ in range(1000):
        pw = gen.generate()
        assert len(pw) == 16
        assert any(c in UPPERCASE for c in pw)
        assert any(c in LOWERCASE for c in pw)
        assert any(c in DIGITS for c in pw)
        assert any(c in SYMBOLS for c in pw)
        # Global uniqueness in 1000 draws.
        assert pw not in seen
        seen.add(pw)


def test_all_printable_chars_belong_to_pool() -> None:
    gen = PasswordGenerator(GeneratorConfig(length=64))
    allowed = set(UPPERCASE + LOWERCASE + DIGITS + SYMBOLS)
    for _ in range(20):
        pw = gen.generate()
        assert set(pw) <= allowed


# --------------------------------------------------------------------- #
# Config mutation is caught
# --------------------------------------------------------------------- #


def test_config_mutated_to_invalid_raises_on_generate() -> None:
    cfg = GeneratorConfig(length=16)
    gen = PasswordGenerator(cfg)
    cfg.length = 3
    with pytest.raises(ValueError):
        gen.generate()