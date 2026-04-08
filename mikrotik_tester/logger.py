"""Thread-safe logging setup for MikroTik credential tester."""

import csv
import io
import logging
import threading
from datetime import datetime, timezone


def setup_logging(log_file: str, verbose: bool = False) -> logging.Logger:
    """Configure and return the application logger."""
    logger = logging.getLogger("mikrotik_tester")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if logger.handlers:
        return logger

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s %(message)s",
                          datefmt="%H:%M:%S")
    )
    logger.addHandler(console)

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s|%(levelname)s|%(message)s")
    )
    logger.addHandler(file_handler)

    return logger


class AttemptLogger:
    """Thread-safe CSV logger for credential test attempts."""

    def __init__(self, log_file: str):
        self._lock = threading.Lock()
        self._log_file = log_file.replace(".log", "_attempts.csv")
        self._init_file()

    def _init_file(self):
        with open(self._log_file, "a", newline="") as f:
            if f.tell() == 0:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "username", "password_masked",
                    "protocol", "result", "proxy", "error"
                ])

    @staticmethod
    def _mask_password(password: str) -> str:
        if len(password) <= 2:
            return "*" * len(password)
        return password[0] + "*" * (len(password) - 2) + password[-1]

    def log_attempt(self, username: str, password: str, protocol: str,
                    success: bool, proxy: str = "", error: str = ""):
        """Log a single credential test attempt."""
        row = [
            datetime.now(timezone.utc).isoformat(),
            username,
            self._mask_password(password),
            protocol,
            "SUCCESS" if success else "FAILED",
            proxy,
            error,
        ]
        buf = io.StringIO()
        csv.writer(buf).writerow(row)
        line = buf.getvalue()
        with self._lock:
            with open(self._log_file, "a", newline="") as f:
                f.write(line)
