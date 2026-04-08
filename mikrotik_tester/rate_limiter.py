"""Adaptive rate limiter for MikroTik bruteforce prevention evasion.

MikroTik routers have several layers of bruteforce protection:
  - SSH: max 3 login attempts per connection, then disconnect
  - RouterOS 7+: built-in bruteforce detection that blacklists IPs
  - Firewall rules: admin-configured address-list based blocking

This module detects when the router is blocking us and backs off
automatically, so the user doesn't need to change any RouterOS settings.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("mikrotik_tester")

# Error types that indicate the router is blocking/rate-limiting us
BLOCKING_ERRORS = frozenset({
    "timeout",
    "connection_refused",
    "connection_error",
    "rate_limited",
    "os_error",
})

# Error types that indicate a normal auth failure (not blocking)
NORMAL_ERRORS = frozenset({
    "auth_failed",
    "account_disabled",
})


@dataclass
class RateLimiterState:
    """Tracks the current rate limiting state."""
    consecutive_blocks: int = 0
    total_blocks: int = 0
    current_delay: float = 1.0
    last_attempt_time: float = 0.0
    is_paused: bool = False
    pause_until: float = 0.0


class AdaptiveRateLimiter:
    """Detects router-side blocking and adjusts attempt timing automatically.

    Strategy:
      - Start with a base delay between attempts (default 1s)
      - On connection failure (timeout/refused/error), increase delay exponentially
      - On auth failure (normal response), decrease delay back toward base
      - After N consecutive blocks, pause for a longer cooldown
      - Warn the user when we detect blacklisting

    This allows testing to proceed without modifying the router's config.
    """

    # Thresholds
    CONSECUTIVE_BLOCK_PAUSE = 5      # Pause after this many consecutive blocks
    PAUSE_DURATION_BASE = 30.0       # Base pause duration in seconds
    PAUSE_DURATION_MAX = 300.0       # Max pause duration (5 minutes)
    MAX_DELAY = 30.0                 # Max per-attempt delay
    BACKOFF_FACTOR = 1.5             # Exponential backoff multiplier
    RECOVERY_FACTOR = 0.8            # Delay reduction on successful response

    def __init__(self, base_delay: float = 1.0, slow_mode: bool = False):
        """Initialize the rate limiter.

        Args:
            base_delay: Minimum delay between attempts in seconds.
            slow_mode: If True, use larger delays (2-5s range).
        """
        self._base_delay = base_delay
        self._slow_mode = slow_mode
        self._state = RateLimiterState(current_delay=base_delay)
        self._lock = threading.Lock()
        self._blacklist_warned = False

    @property
    def current_delay(self) -> float:
        with self._lock:
            return self._state.current_delay

    @property
    def consecutive_blocks(self) -> int:
        with self._lock:
            return self._state.consecutive_blocks

    @property
    def is_blacklisted(self) -> bool:
        """Heuristic: likely blacklisted if many consecutive blocks."""
        with self._lock:
            return self._state.consecutive_blocks >= self.CONSECUTIVE_BLOCK_PAUSE

    def wait_before_attempt(self):
        """Block the calling thread until it's safe to attempt a connection.

        Enforces the current delay and respects any active pause.
        """
        with self._lock:
            now = time.monotonic()

            # If we're in a pause period, wait it out
            if self._state.is_paused and now < self._state.pause_until:
                wait_time = self._state.pause_until - now
                logger.warning(
                    "Rate limiter: paused for %.0fs (router may be blocking us)",
                    wait_time,
                )
                self._lock.release()
                time.sleep(wait_time)
                self._lock.acquire()
                self._state.is_paused = False

            # Enforce minimum delay since last attempt
            elapsed = now - self._state.last_attempt_time
            if elapsed < self._state.current_delay:
                sleep_time = self._state.current_delay - elapsed
                self._lock.release()
                time.sleep(sleep_time)
                self._lock.acquire()

            self._state.last_attempt_time = time.monotonic()

    def report_result(self, error_type: Optional[str], success: bool = False):
        """Report the result of an attempt to update rate limiting state.

        Args:
            error_type: The error classification from the tester, or None/empty.
            success: Whether the login was successful.
        """
        with self._lock:
            if success or error_type in NORMAL_ERRORS or not error_type:
                # Normal response — router is talking to us, reduce delay
                self._state.consecutive_blocks = 0
                self._state.current_delay = max(
                    self._base_delay,
                    self._state.current_delay * self.RECOVERY_FACTOR,
                )
                self._blacklist_warned = False

            elif error_type in BLOCKING_ERRORS:
                # Router may be blocking us
                self._state.consecutive_blocks += 1
                self._state.total_blocks += 1
                self._state.current_delay = min(
                    self.MAX_DELAY,
                    self._state.current_delay * self.BACKOFF_FACTOR,
                )

                logger.debug(
                    "Rate limiter: consecutive blocks=%d, delay=%.1fs",
                    self._state.consecutive_blocks,
                    self._state.current_delay,
                )

                # Check if we should pause
                if self._state.consecutive_blocks >= self.CONSECUTIVE_BLOCK_PAUSE:
                    pause_multiplier = min(
                        self._state.consecutive_blocks
                        // self.CONSECUTIVE_BLOCK_PAUSE,
                        10,
                    )
                    pause_duration = min(
                        self.PAUSE_DURATION_BASE * pause_multiplier,
                        self.PAUSE_DURATION_MAX,
                    )
                    self._state.is_paused = True
                    self._state.pause_until = (
                        time.monotonic() + pause_duration
                    )

                    if not self._blacklist_warned:
                        self._blacklist_warned = True
                        logger.warning(
                            "BLOCKED: %d consecutive connection failures — "
                            "router is likely blocking this IP. "
                            "Pausing for %.0fs before retrying. "
                            "No RouterOS changes needed, we'll wait it out.",
                            self._state.consecutive_blocks,
                            pause_duration,
                        )

    def get_status(self) -> str:
        """Return a human-readable status string."""
        with self._lock:
            if self._state.is_paused:
                remaining = max(
                    0, self._state.pause_until - time.monotonic()
                )
                return (
                    f"PAUSED ({remaining:.0f}s remaining) — "
                    f"router blocking detected"
                )
            if self._state.consecutive_blocks > 0:
                return (
                    f"backing off (delay={self._state.current_delay:.1f}s, "
                    f"blocks={self._state.consecutive_blocks})"
                )
            return f"normal (delay={self._state.current_delay:.1f}s)"
