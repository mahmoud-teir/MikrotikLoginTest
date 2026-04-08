"""Tests for the dictionary generator and password mutation engine."""

import os
import tempfile

import pytest

from mikrotik_tester.wordlist import (
    MIKROTIK_DEFAULTS,
    PasswordMutator,
    WordlistGenerator,
)


class TestPasswordMutator:
    """Test password mutation operations."""

    def test_leet_speak_basic(self):
        assert PasswordMutator.leet_speak("admin") == "4dm1n"

    def test_leet_speak_password(self):
        result = PasswordMutator.leet_speak("password")
        assert "4" not in result or result == "p455w0rd"
        # 'p' has no leet mapping, 'a'->4, 's'->5, 'w' has no mapping, 'o'->0, 'r' none, 'd' none
        assert result == "p455w0rd"

    def test_leet_speak_empty(self):
        assert PasswordMutator.leet_speak("") == ""

    def test_leet_speak_no_replacements(self):
        assert PasswordMutator.leet_speak("xyz") == "xyz"

    def test_leet_speak_preserves_case_mapping(self):
        # Uppercase letters: leet_speak lowercases before lookup
        result = PasswordMutator.leet_speak("Admin")
        assert result == "4dm1n"

    def test_append_years(self):
        results = PasswordMutator.append_years("admin")
        assert len(results) == 7  # 2020-2026
        assert "admin2020" in results
        assert "admin2026" in results

    def test_append_years_empty(self):
        results = PasswordMutator.append_years("")
        assert "2020" in results

    def test_case_variations(self):
        results = PasswordMutator.case_variations("admin")
        assert "admin" in results  # lower
        assert "ADMIN" in results  # upper
        assert "Admin" in results  # capitalize
        assert "ADMIN" in results or "aDMIN" in results  # swapcase

    def test_case_variations_single_char(self):
        results = PasswordMutator.case_variations("a")
        assert "a" in results
        assert "A" in results

    def test_mutate_produces_variations(self):
        results = PasswordMutator.mutate("admin")
        # Should include original
        assert "admin" in results
        # Should include leet
        assert "4dm1n" in results
        # Should include uppercase
        assert "ADMIN" in results
        # Should include year appends
        assert "admin2024" in results
        # Should include suffixes
        assert "admin!" in results
        assert "admin123" in results

    def test_mutate_empty_password(self):
        results = PasswordMutator.mutate("")
        assert "" in results
        assert len(results) == 1

    def test_mutate_returns_set(self):
        results = PasswordMutator.mutate("test")
        assert isinstance(results, set)
        # No duplicates
        assert len(results) == len(set(results))


class TestWordlistGenerator:
    """Test credential pair generation."""

    def test_defaults_only(self):
        gen = WordlistGenerator(
            usernames=["admin"],
            use_defaults=True,
        )
        pairs = list(gen.generate())
        # Should include all default pairs
        assert ("admin", "") in pairs
        assert ("admin", "admin") in pairs
        assert ("admin", "mikrotik") in pairs
        assert len(pairs) >= len(MIKROTIK_DEFAULTS)

    def test_defaults_with_custom_username(self):
        gen = WordlistGenerator(
            usernames=["root"],
            use_defaults=True,
        )
        pairs = list(gen.generate())
        # Default pairs use "admin", but passwords should also map to "root"
        admin_pairs = [(u, p) for u, p in pairs if u == "admin"]
        root_pairs = [(u, p) for u, p in pairs if u == "root"]
        assert len(admin_pairs) > 0
        assert len(root_pairs) > 0

    def test_wordlist_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as f:
            f.write("secret\nletmein\nqwerty\n")
            f.flush()
            tmp_path = f.name

        try:
            gen = WordlistGenerator(
                usernames=["admin"],
                wordlist_file=tmp_path,
            )
            pairs = list(gen.generate())
            assert ("admin", "secret") in pairs
            assert ("admin", "letmein") in pairs
            assert ("admin", "qwerty") in pairs
        finally:
            os.unlink(tmp_path)

    def test_wordlist_with_mutations(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as f:
            f.write("admin\n")
            f.flush()
            tmp_path = f.name

        try:
            gen = WordlistGenerator(
                usernames=["admin"],
                wordlist_file=tmp_path,
                mutate=True,
            )
            pairs = list(gen.generate())
            passwords = [p for _, p in pairs]
            assert "admin" in passwords
            assert "4dm1n" in passwords
            assert "ADMIN" in passwords
        finally:
            os.unlink(tmp_path)

    def test_no_duplicates(self):
        gen = WordlistGenerator(
            usernames=["admin"],
            use_defaults=True,
            mutate=True,
        )
        pairs = list(gen.generate())
        assert len(pairs) == len(set(pairs))

    def test_empty_wordlist_with_defaults(self):
        gen = WordlistGenerator(
            usernames=["admin"],
            use_defaults=True,
        )
        pairs = list(gen.generate())
        assert len(pairs) > 0

    def test_multiple_usernames(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as f:
            f.write("pass1\n")
            f.flush()
            tmp_path = f.name

        try:
            gen = WordlistGenerator(
                usernames=["admin", "root", "user"],
                wordlist_file=tmp_path,
            )
            pairs = list(gen.generate())
            assert ("admin", "pass1") in pairs
            assert ("root", "pass1") in pairs
            assert ("user", "pass1") in pairs
        finally:
            os.unlink(tmp_path)

    def test_count_estimate(self):
        gen = WordlistGenerator(
            usernames=["admin"],
            use_defaults=True,
        )
        estimate = gen.count_estimate()
        assert estimate > 0

    def test_generator_behavior(self):
        """Verify generate() returns a generator (lazy evaluation)."""
        gen = WordlistGenerator(
            usernames=["admin"],
            use_defaults=True,
        )
        result = gen.generate()
        import types
        assert isinstance(result, types.GeneratorType)
