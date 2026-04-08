"""Tests for the checkpoint manager."""

import json
import os
import tempfile
import threading

import pytest

from mikrotik_tester.checkpoint import CheckpointManager, CheckpointState


class TestCheckpointManager:
    """Test checkpoint save/load/resume functionality."""

    def _tmp_path(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)  # Start with no file
        return path

    def test_save_and_load_roundtrip(self):
        path = self._tmp_path()
        try:
            mgr = CheckpointManager(path)
            mgr.set_metadata("2024-01-01T00:00:00Z", "both", "192.168.1.1")
            mgr.update(0)
            mgr.update(1)
            mgr.update(2, credential_found={
                "username": "admin", "password": "test", "protocol": "ssh"
            })
            mgr.save()

            # Load in a new manager
            mgr2 = CheckpointManager(path)
            state = mgr2.load()
            assert state is not None
            assert state.last_index == 2
            assert state.total_attempts == 3
            assert len(state.found_credentials) == 1
            assert state.found_credentials[0]["username"] == "admin"
            assert state.protocol == "both"
            assert state.target == "192.168.1.1"
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_load_nonexistent_file(self):
        mgr = CheckpointManager("/tmp/nonexistent_checkpoint_test.json")
        result = mgr.load()
        assert result is None

    def test_load_corrupt_file(self):
        path = self._tmp_path()
        try:
            with open(path, "w") as f:
                f.write("not valid json{{{")
            mgr = CheckpointManager(path)
            result = mgr.load()
            assert result is None
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_resume_index(self):
        path = self._tmp_path()
        try:
            mgr = CheckpointManager(path)
            for i in range(10):
                mgr.update(i)
            mgr.save()

            mgr2 = CheckpointManager(path)
            state = mgr2.load()
            assert state.last_index == 9
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_found_credentials_accumulation(self):
        path = self._tmp_path()
        try:
            mgr = CheckpointManager(path)
            mgr.update(0, credential_found={"user": "a", "pass": "1"})
            mgr.update(1, credential_found={"user": "b", "pass": "2"})
            mgr.update(2)  # No credential found
            mgr.update(3, credential_found={"user": "c", "pass": "3"})
            mgr.save()

            mgr2 = CheckpointManager(path)
            state = mgr2.load()
            assert len(state.found_credentials) == 3
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_auto_save(self):
        path = self._tmp_path()
        try:
            mgr = CheckpointManager(path, auto_save_interval=5)
            for i in range(6):
                mgr.update(i)
            # After 5 updates, auto-save should have triggered
            assert os.path.exists(path)
            with open(path) as f:
                data = json.load(f)
            assert data["last_index"] >= 4
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_thread_safety(self):
        """Test that concurrent updates don't corrupt state."""
        path = self._tmp_path()
        try:
            mgr = CheckpointManager(path, auto_save_interval=1000)
            errors = []

            def worker(start, count):
                try:
                    for i in range(start, start + count):
                        mgr.update(i)
                except Exception as e:
                    errors.append(e)

            threads = [
                threading.Thread(target=worker, args=(i * 100, 100))
                for i in range(5)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0
            assert mgr.state.total_attempts == 500
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_atomic_write(self):
        """Verify save creates a valid JSON file."""
        path = self._tmp_path()
        try:
            mgr = CheckpointManager(path)
            mgr.update(42)
            mgr.save()

            with open(path) as f:
                data = json.load(f)
            assert data["last_index"] == 42
            assert isinstance(data["found_credentials"], list)
        finally:
            if os.path.exists(path):
                os.unlink(path)
