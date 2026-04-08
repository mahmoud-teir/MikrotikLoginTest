"""Tests for adaptive rate limiter."""

import threading
import time

from mikrotik_tester.rate_limiter import AdaptiveRateLimiter


class TestAdaptiveRateLimiter:
    """Tests for the AdaptiveRateLimiter."""

    def test_initial_delay(self):
        rl = AdaptiveRateLimiter(base_delay=1.0)
        assert rl.current_delay == 1.0

    def test_normal_auth_failure_keeps_base_delay(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        rl.report_result("auth_failed")
        assert rl.current_delay == 0.5
        assert rl.consecutive_blocks == 0

    def test_success_keeps_base_delay(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        rl.report_result(None, success=True)
        assert rl.current_delay == 0.5
        assert rl.consecutive_blocks == 0

    def test_timeout_increases_delay(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        initial_delay = rl.current_delay
        rl.report_result("timeout")
        assert rl.current_delay > initial_delay
        assert rl.consecutive_blocks == 1

    def test_connection_refused_increases_delay(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        rl.report_result("connection_refused")
        assert rl.current_delay > 0.5
        assert rl.consecutive_blocks == 1

    def test_consecutive_blocks_accumulate(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        for _ in range(3):
            rl.report_result("timeout")
        assert rl.consecutive_blocks == 3

    def test_normal_response_resets_consecutive_blocks(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        for _ in range(3):
            rl.report_result("timeout")
        assert rl.consecutive_blocks == 3
        rl.report_result("auth_failed")
        assert rl.consecutive_blocks == 0

    def test_delay_recovery_after_blocking(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        # Drive delay up
        for _ in range(3):
            rl.report_result("connection_refused")
        high_delay = rl.current_delay

        # Recover
        for _ in range(10):
            rl.report_result("auth_failed")
        assert rl.current_delay < high_delay
        assert rl.current_delay >= 0.5  # Never goes below base

    def test_delay_capped_at_max(self):
        rl = AdaptiveRateLimiter(base_delay=1.0)
        for _ in range(50):
            rl.report_result("timeout")
        assert rl.current_delay <= rl.MAX_DELAY

    def test_blacklist_detection(self):
        rl = AdaptiveRateLimiter(base_delay=0.1)
        assert not rl.is_blacklisted
        for _ in range(rl.CONSECUTIVE_BLOCK_PAUSE):
            rl.report_result("timeout")
        assert rl.is_blacklisted

    def test_blacklist_clears_on_normal_response(self):
        rl = AdaptiveRateLimiter(base_delay=0.1)
        for _ in range(rl.CONSECUTIVE_BLOCK_PAUSE):
            rl.report_result("timeout")
        assert rl.is_blacklisted
        rl.report_result("auth_failed")
        assert not rl.is_blacklisted

    def test_status_normal(self):
        rl = AdaptiveRateLimiter(base_delay=1.0)
        status = rl.get_status()
        assert "normal" in status

    def test_status_backing_off(self):
        rl = AdaptiveRateLimiter(base_delay=1.0)
        rl.report_result("timeout")
        status = rl.get_status()
        assert "backing off" in status

    def test_empty_error_treated_as_normal(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        rl.report_result("")
        assert rl.consecutive_blocks == 0

    def test_none_error_treated_as_normal(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        rl.report_result(None)
        assert rl.consecutive_blocks == 0

    def test_account_disabled_treated_as_normal(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        rl.report_result("account_disabled")
        assert rl.consecutive_blocks == 0

    def test_rate_limited_error_triggers_backoff(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        rl.report_result("rate_limited")
        assert rl.consecutive_blocks == 1
        assert rl.current_delay > 0.5

    def test_os_error_triggers_backoff(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        rl.report_result("os_error")
        assert rl.consecutive_blocks == 1

    def test_thread_safety(self):
        """Multiple threads reporting results concurrently."""
        rl = AdaptiveRateLimiter(base_delay=0.01)
        errors = []

        def report_loop(error_type, count):
            for _ in range(count):
                try:
                    rl.report_result(error_type)
                except Exception as e:
                    errors.append(e)

        threads = [
            threading.Thread(target=report_loop, args=("timeout", 20)),
            threading.Thread(target=report_loop, args=("auth_failed", 20)),
            threading.Thread(target=report_loop, args=("connection_refused", 20)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_wait_enforces_minimum_delay(self):
        rl = AdaptiveRateLimiter(base_delay=0.1)
        start = time.monotonic()
        rl.wait_before_attempt()
        rl.wait_before_attempt()
        elapsed = time.monotonic() - start
        # Second call should have waited at least base_delay
        assert elapsed >= 0.08  # Allow small tolerance

    def test_slow_mode_flag(self):
        rl = AdaptiveRateLimiter(base_delay=3.0, slow_mode=True)
        assert rl.current_delay == 3.0

    def test_backoff_factor_applied_correctly(self):
        rl = AdaptiveRateLimiter(base_delay=1.0)
        rl.report_result("timeout")
        expected = 1.0 * rl.BACKOFF_FACTOR
        assert abs(rl.current_delay - expected) < 0.01

    def test_recovery_factor_applied_correctly(self):
        rl = AdaptiveRateLimiter(base_delay=0.5)
        # Increase delay
        for _ in range(3):
            rl.report_result("timeout")
        high = rl.current_delay
        # One recovery
        rl.report_result("auth_failed")
        expected = max(0.5, high * rl.RECOVERY_FACTOR)
        assert abs(rl.current_delay - expected) < 0.01
