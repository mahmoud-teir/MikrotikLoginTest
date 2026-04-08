"""Report generation for credential testing results."""

import threading
import time
from datetime import datetime, timezone
from typing import Dict, List


class Reporter:
    """Tracks and reports credential testing progress and results."""

    def __init__(self, total_estimate: int = 0):
        self._start_time = time.monotonic()
        self._start_dt = datetime.now(timezone.utc)
        self._total_estimate = total_estimate
        self._attempts = 0
        self._found: List[Dict] = []
        self._lock = threading.Lock()
        self._errors: Dict[str, int] = {}

    def record_attempt(self, success: bool, credential: Dict = None,
                       error_type: str = ""):
        """Record a single test attempt."""
        with self._lock:
            self._attempts += 1
            if success and credential:
                self._found.append(credential)
            if error_type:
                self._errors[error_type] = (
                    self._errors.get(error_type, 0) + 1
                )

    def set_found(self, found: List[Dict]):
        """Restore found credentials from checkpoint."""
        with self._lock:
            self._found = list(found)

    @property
    def attempts(self) -> int:
        with self._lock:
            return self._attempts

    @property
    def found_count(self) -> int:
        with self._lock:
            return len(self._found)

    @property
    def found_credentials(self) -> List[Dict]:
        with self._lock:
            return list(self._found)

    def _elapsed(self) -> float:
        return time.monotonic() - self._start_time

    def _rate(self) -> float:
        elapsed = self._elapsed()
        if elapsed <= 0:
            return 0.0
        with self._lock:
            return self._attempts / elapsed

    def _eta_seconds(self) -> float:
        rate = self._rate()
        if rate <= 0:
            return 0.0
        with self._lock:
            remaining = max(0, self._total_estimate - self._attempts)
        return remaining / rate

    @staticmethod
    def _format_duration(seconds: float) -> str:
        if seconds <= 0:
            return "0s"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        parts = []
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        parts.append(f"{secs}s")
        return " ".join(parts)

    def print_progress(self):
        """Print a one-line progress update."""
        with self._lock:
            attempts = self._attempts
            found = len(self._found)

        elapsed = self._elapsed()
        rate = self._rate()
        eta = self._eta_seconds()

        print(
            f"\r[Progress] {attempts}/{self._total_estimate} attempts | "
            f"{found} found | {rate:.1f}/s | "
            f"Elapsed: {self._format_duration(elapsed)} | "
            f"ETA: {self._format_duration(eta)}",
            end="", flush=True,
        )

    def print_final_report(self):
        """Print the complete final report."""
        elapsed = self._elapsed()
        rate = self._rate()
        eta = self._eta_seconds()

        with self._lock:
            attempts = self._attempts
            found = list(self._found)
            errors = dict(self._errors)

        print("\n")
        print("=" * 65)
        print("  MIKROTIK CREDENTIAL TEST REPORT")
        print("=" * 65)
        print(f"  Started:    {self._start_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Duration:   {self._format_duration(elapsed)}")
        print(f"  Attempts:   {attempts} / {self._total_estimate}")
        print(f"  Rate:       {rate:.2f} attempts/sec")
        if attempts < self._total_estimate:
            print(f"  Est. remaining: {self._format_duration(eta)}")
        print("-" * 65)

        if found:
            print(f"\n  FOUND CREDENTIALS ({len(found)}):\n")
            print(f"  {'Username':<15} {'Password':<20} {'Protocol':<10} {'Method'}")
            print(f"  {'-'*15} {'-'*20} {'-'*10} {'-'*15}")
            for cred in found:
                print(
                    f"  {cred.get('username', ''):<15} "
                    f"{cred.get('password', ''):<20} "
                    f"{cred.get('protocol', ''):<10} "
                    f"{cred.get('method', '')}"
                )
        else:
            print("\n  No credentials found.")

        if errors:
            print(f"\n  ERROR SUMMARY:")
            for err_type, count in sorted(errors.items(),
                                           key=lambda x: -x[1]):
                print(f"    {err_type}: {count}")

        print("\n" + "=" * 65)
