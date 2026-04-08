"""Checkpoint manager for pause/resume of credential testing sessions."""

import json
import logging
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("mikrotik_tester")


@dataclass
class CheckpointState:
    """Serializable state of a testing session."""
    last_index: int = 0
    total_attempts: int = 0
    start_time: str = ""
    found_credentials: List[Dict] = field(default_factory=list)
    protocol: str = "both"
    target: str = ""


class CheckpointManager:
    """Thread-safe checkpoint manager with atomic writes."""

    def __init__(self, filepath: str, auto_save_interval: int = 50):
        self._filepath = filepath
        self._auto_save_interval = auto_save_interval
        self._state = CheckpointState()
        self._lock = threading.Lock()
        self._unsaved_count = 0

    @property
    def state(self) -> CheckpointState:
        return self._state

    def load(self) -> Optional[CheckpointState]:
        """Load checkpoint from file.

        Returns:
            CheckpointState if file exists and is valid, else None.
        """
        if not os.path.isfile(self._filepath):
            return None
        try:
            with open(self._filepath, "r") as f:
                data = json.load(f)
            self._state = CheckpointState(**data)
            logger.info(
                "Resumed from checkpoint: index=%d, attempts=%d, found=%d",
                self._state.last_index,
                self._state.total_attempts,
                len(self._state.found_credentials),
            )
            return self._state
        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.warning("Failed to load checkpoint: %s", e)
            return None

    def save(self):
        """Atomically save checkpoint state to file."""
        with self._lock:
            data = asdict(self._state)
            self._unsaved_count = 0

        # Atomic write: write to temp file, then rename
        dir_name = os.path.dirname(self._filepath) or "."
        try:
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, self._filepath)
        except OSError as e:
            logger.error("Failed to save checkpoint: %s", e)
            # Clean up temp file if replace failed
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def update(self, index: int, credential_found: Optional[Dict] = None):
        """Update checkpoint state after a test attempt.

        Args:
            index: Current position in the wordlist.
            credential_found: If not None, a dict with found credential info.
        """
        with self._lock:
            self._state.last_index = index
            self._state.total_attempts += 1
            if credential_found:
                self._state.found_credentials.append(credential_found)
            self._unsaved_count += 1

        if self._unsaved_count >= self._auto_save_interval:
            self.save()

    def set_metadata(self, start_time: str, protocol: str, target: str):
        """Set session metadata on checkpoint."""
        with self._lock:
            self._state.start_time = start_time
            self._state.protocol = protocol
            self._state.target = target
