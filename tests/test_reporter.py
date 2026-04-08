"""Tests for the report generator."""

import time
from io import StringIO
from unittest.mock import patch

import pytest

from mikrotik_tester.reporter import Reporter


class TestReporter:
    """Test report formatting and statistics."""

    def test_initial_state(self):
        r = Reporter(total_estimate=100)
        assert r.attempts == 0
        assert r.found_count == 0

    def test_record_attempt(self):
        r = Reporter(total_estimate=100)
        r.record_attempt(False)
        r.record_attempt(False, error_type="timeout")
        r.record_attempt(True, credential={
            "username": "admin", "password": "test", "protocol": "ssh"
        })
        assert r.attempts == 3
        assert r.found_count == 1

    def test_found_credentials_list(self):
        r = Reporter()
        r.record_attempt(True, credential={"user": "a"})
        r.record_attempt(True, credential={"user": "b"})
        creds = r.found_credentials
        assert len(creds) == 2
        assert creds[0]["user"] == "a"

    def test_set_found_from_checkpoint(self):
        r = Reporter()
        r.set_found([{"user": "x"}, {"user": "y"}])
        assert r.found_count == 2

    def test_format_duration_seconds(self):
        assert Reporter._format_duration(5) == "5s"

    def test_format_duration_minutes(self):
        assert Reporter._format_duration(125) == "2m 5s"

    def test_format_duration_hours(self):
        assert Reporter._format_duration(3665) == "1h 1m 5s"

    def test_format_duration_zero(self):
        assert Reporter._format_duration(0) == "0s"

    def test_format_duration_negative(self):
        assert Reporter._format_duration(-1) == "0s"

    def test_print_final_report_no_results(self):
        r = Reporter(total_estimate=100)
        for _ in range(5):
            r.record_attempt(False)

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            r.print_final_report()
            output = mock_out.getvalue()

        assert "MIKROTIK CREDENTIAL TEST REPORT" in output
        assert "No credentials found" in output
        assert "5 / 100" in output

    def test_print_final_report_with_results(self):
        r = Reporter(total_estimate=10)
        r.record_attempt(True, credential={
            "username": "admin",
            "password": "secret",
            "protocol": "ssh",
            "method": "password",
        })
        r.record_attempt(False)

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            r.print_final_report()
            output = mock_out.getvalue()

        assert "FOUND CREDENTIALS (1)" in output
        assert "admin" in output
        assert "secret" in output
        assert "ssh" in output

    def test_print_final_report_with_errors(self):
        r = Reporter(total_estimate=10)
        r.record_attempt(False, error_type="timeout")
        r.record_attempt(False, error_type="timeout")
        r.record_attempt(False, error_type="auth_failed")

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            r.print_final_report()
            output = mock_out.getvalue()

        assert "ERROR SUMMARY" in output
        assert "timeout" in output

    def test_rate_calculation(self):
        r = Reporter(total_estimate=100)
        # Record some attempts
        for _ in range(10):
            r.record_attempt(False)
        # Rate should be positive
        rate = r._rate()
        assert rate > 0

    def test_print_progress(self):
        r = Reporter(total_estimate=100)
        r.record_attempt(False)
        # Should not raise
        with patch("builtins.print"):
            r.print_progress()
