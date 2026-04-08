"""Dictionary generator with mutations for MikroTik credential testing."""

import itertools
import os
from typing import Generator, List, Set, Tuple


MIKROTIK_DEFAULTS: List[Tuple[str, str]] = [
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "mikrotik"),
    ("admin", "changeme"),
    ("admin", "default"),
    ("admin", "master"),
    ("admin", "router"),
    ("admin", "public"),
    ("admin", "private"),
    ("admin", "letmein"),
]

LEET_MAP = {
    "a": "4", "e": "3", "i": "1", "o": "0",
    "s": "5", "t": "7", "g": "9", "b": "8",
}

YEARS = [str(y) for y in range(2020, 2027)]


class PasswordMutator:
    """Applies various mutations to base passwords."""

    @staticmethod
    def leet_speak(word: str) -> str:
        """Convert a word to leet speak."""
        return "".join(LEET_MAP.get(c.lower(), c) for c in word)

    @staticmethod
    def append_years(word: str) -> List[str]:
        """Append common years to a word."""
        return [word + year for year in YEARS]

    @staticmethod
    def case_variations(word: str) -> List[str]:
        """Generate case variations of a word."""
        results = set()
        results.add(word.lower())
        results.add(word.upper())
        results.add(word.capitalize())
        results.add(word.swapcase())
        if len(word) > 1:
            results.add(word[0].upper() + word[1:].lower())
        return list(results)

    @classmethod
    def mutate(cls, word: str) -> Set[str]:
        """Apply all mutations to a word and return deduplicated results."""
        if not word:
            return {word}

        results = set()
        results.add(word)

        # Case variations
        for var in cls.case_variations(word):
            results.add(var)

        # Leet speak
        leet = cls.leet_speak(word)
        results.add(leet)

        # Year appending (on original and leet)
        for base in [word, word.capitalize(), leet]:
            for yr in cls.append_years(base):
                results.add(yr)

        # Common suffixes
        for suffix in ["!", "123", "@", "#", "$", "1"]:
            results.add(word + suffix)
            results.add(word.capitalize() + suffix)

        return results


class WordlistGenerator:
    """Generates credential pairs from defaults, wordlists, and mutations."""

    def __init__(self, usernames: List[str], wordlist_file: str = None,
                 use_defaults: bool = False, mutate: bool = False):
        self._usernames = usernames
        self._wordlist_file = wordlist_file
        self._use_defaults = use_defaults
        self._mutate = mutate

    def _load_passwords_from_file(self) -> Generator[str, None, None]:
        """Load passwords from a wordlist file (one per line)."""
        if not self._wordlist_file or not os.path.isfile(self._wordlist_file):
            return
        with open(self._wordlist_file, "r", encoding="utf-8",
                  errors="ignore") as f:
            for line in f:
                pwd = line.rstrip("\n\r")
                yield pwd

    def _default_passwords(self) -> Generator[Tuple[str, str], None, None]:
        """Yield default MikroTik credential pairs."""
        for user, pwd in MIKROTIK_DEFAULTS:
            yield user, pwd

    def _default_password_values(self) -> Generator[str, None, None]:
        """Yield just the password values from defaults."""
        seen = set()
        for _, pwd in MIKROTIK_DEFAULTS:
            if pwd not in seen:
                seen.add(pwd)
                yield pwd

    def generate(self) -> Generator[Tuple[str, str], None, None]:
        """
        Yield (username, password) pairs.

        Priority order:
        1. Default credential pairs (exact user:pass from known defaults)
        2. Default passwords applied to all requested usernames
        3. Wordlist passwords (optionally mutated) applied to all usernames
        """
        seen = set()

        # 1. Known default pairs first
        if self._use_defaults:
            for user, pwd in self._default_passwords():
                pair = (user, pwd)
                if pair not in seen:
                    seen.add(pair)
                    yield pair

        # 2. Default password values applied to all usernames
        if self._use_defaults:
            for pwd in self._default_password_values():
                passwords = (
                    PasswordMutator.mutate(pwd) if self._mutate else [pwd]
                )
                for username in self._usernames:
                    for p in passwords:
                        pair = (username, p)
                        if pair not in seen:
                            seen.add(pair)
                            yield pair

        # 3. Wordlist passwords
        for pwd in self._load_passwords_from_file():
            passwords = (
                PasswordMutator.mutate(pwd) if self._mutate else [pwd]
            )
            for username in self._usernames:
                for p in passwords:
                    pair = (username, p)
                    if pair not in seen:
                        seen.add(pair)
                        yield pair

    def count_estimate(self) -> int:
        """Estimate total credential pairs (for progress reporting)."""
        base_count = 0

        if self._use_defaults:
            base_count += len(MIKROTIK_DEFAULTS)
            base_count += len(set(p for _, p in MIKROTIK_DEFAULTS)) * len(
                self._usernames
            )

        if self._wordlist_file and os.path.isfile(self._wordlist_file):
            with open(self._wordlist_file, "r", encoding="utf-8",
                      errors="ignore") as f:
                line_count = sum(1 for _ in f)
            base_count += line_count * len(self._usernames)

        # Mutations roughly multiply by ~25x per password
        if self._mutate:
            base_count = int(base_count * 25)

        return max(base_count, 1)
