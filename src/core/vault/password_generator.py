"""
Secure password generator.

Uses secrets.choice / secrets.randbelow for all randomness (GEN-1).
Supports configurable length, character sets, and ambiguous character
exclusion (GEN-2). Guarantees at least one character from each selected
set (GEN-3). Keeps a short history of recent outputs to avoid repeats
(GEN-5).
"""

from __future__ import annotations

import secrets
from collections import deque
from dataclasses import dataclass, field


# --------------------------------------------------------------------- #
# Character sets (GEN-2)
# --------------------------------------------------------------------- #

UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*"
AMBIGUOUS = "lI10O"

MIN_LENGTH = 8
MAX_LENGTH = 64
DEFAULT_LENGTH = 16
DEFAULT_HISTORY_SIZE = 20


# --------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------- #


@dataclass
class GeneratorConfig:
    """
    Configuration for the password generator.

    length: total number of characters, inclusive of one-per-set
            guarantees (see GEN-3).
    """
    length: int = DEFAULT_LENGTH
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False

    def validate(self) -> None:
        if not (MIN_LENGTH <= self.length <= MAX_LENGTH):
            raise ValueError(
                f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}, "
                f"got {self.length}"
            )
        selected = self.selected_sets()
        if not selected:
            raise ValueError("At least one character set must be enabled.")
        if self.length < len(selected):
            raise ValueError(
                f"Length {self.length} is too short to include at least "
                f"one character from each of the {len(selected)} selected "
                f"sets."
            )

    def selected_sets(self) -> list[str]:
        sets: list[str] = []
        if self.uppercase:
            sets.append(UPPERCASE)
        if self.lowercase:
            sets.append(LOWERCASE)
        if self.digits:
            sets.append(DIGITS)
        if self.symbols:
            sets.append(SYMBOLS)
        return sets


# --------------------------------------------------------------------- #
# Generator
# --------------------------------------------------------------------- #


class PasswordGenerator:
    def __init__(
        self,
        config: GeneratorConfig | None = None,
        history_size: int = DEFAULT_HISTORY_SIZE,
    ) -> None:
        self.config = config or GeneratorConfig()
        self.config.validate()
        self._history: deque[str] = deque(maxlen=history_size)
        self._rng = secrets.SystemRandom()

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def history(self) -> list[str]:
        return list(self._history)

    # ------------------------------------------------------------------ #
    # Generation
    # ------------------------------------------------------------------ #

    def generate(self) -> str:
        """
        Generate a password matching the configured policy.

        Ensures at least one character from each selected set (GEN-3).
        Avoids duplicates of the last `history_size` outputs (GEN-5).
        """
        # Guard against pathological configs (validated in __init__, but
        # a caller may mutate self.config in place).
        self.config.validate()

        selected = [
            self._filter(s) for s in self.config.selected_sets()
        ]
        selected = [s for s in selected if s]

        # Theoretically possible if exclude_ambiguous removes everything
        # from a set (won't happen with our sets, but be defensive).
        if not selected:
            raise RuntimeError("No usable characters after filtering.")

        pool = "".join(selected)

        # Try a bounded number of times to avoid history collisions.
        for _ in range(100):
            candidate = self._build(selected, pool)
            if candidate not in self._history:
                self._history.append(candidate)
                return candidate

        # Extremely unlikely; fall back to accepting the last candidate.
        self._history.append(candidate)
        return candidate

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _build(self, selected_sets: list[str], pool: str) -> str:
        chars: list[str] = []

        # GEN-3: guarantee at least one from each selected set.
        for charset in selected_sets:
            chars.append(secrets.choice(charset))

        # Fill the rest from the combined pool.
        remaining = self.config.length - len(chars)
        for _ in range(remaining):
            chars.append(secrets.choice(pool))

        # Shuffle so the guaranteed characters are not at fixed positions.
        self._rng.shuffle(chars)
        return "".join(chars)

    def _filter(self, charset: str) -> str:
        if not self.config.exclude_ambiguous:
            return charset
        return "".join(c for c in charset if c not in AMBIGUOUS)