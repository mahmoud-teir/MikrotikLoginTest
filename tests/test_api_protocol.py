"""Tests for the RouterOS API wire protocol implementation."""

import hashlib
import io
import struct
from unittest.mock import MagicMock, patch

import pytest

from mikrotik_tester.api_protocol import ApiConnection, ApiError


class TestEncodeLength:
    """Test RouterOS variable-length encoding."""

    def test_one_byte_zero(self):
        assert ApiConnection.encode_length(0) == b"\x00"

    def test_one_byte_max(self):
        # 0x7F = 127
        assert ApiConnection.encode_length(0x7F) == b"\x7f"

    def test_two_byte_min(self):
        # 0x80 -> should encode as 2 bytes with 0x80 flag
        result = ApiConnection.encode_length(0x80)
        assert len(result) == 2
        assert result[0] & 0x80 == 0x80

    def test_two_byte_max(self):
        result = ApiConnection.encode_length(0x3FFF)
        assert len(result) == 2

    def test_three_byte_min(self):
        result = ApiConnection.encode_length(0x4000)
        assert len(result) == 3
        assert result[0] & 0xE0 == 0xC0

    def test_three_byte_max(self):
        result = ApiConnection.encode_length(0x1FFFFF)
        assert len(result) == 3

    def test_four_byte_min(self):
        result = ApiConnection.encode_length(0x200000)
        assert len(result) == 4
        assert result[0] & 0xF0 == 0xE0

    def test_four_byte_max(self):
        result = ApiConnection.encode_length(0xFFFFFFF)
        assert len(result) == 4

    def test_five_byte(self):
        result = ApiConnection.encode_length(0x10000000)
        assert len(result) == 5
        assert result[0] == 0xF0


class TestDecodeLength:
    """Test RouterOS length decoding from socket."""

    def _make_conn_with_data(self, data: bytes) -> ApiConnection:
        """Create an ApiConnection with a mock socket that returns data."""
        conn = ApiConnection()
        sock = MagicMock()
        pos = [0]

        def fake_recv(n):
            result = data[pos[0]:pos[0] + n]
            pos[0] += n
            return result

        sock.recv = fake_recv
        conn._sock = sock
        return conn

    def test_one_byte(self):
        conn = self._make_conn_with_data(b"\x05")
        assert conn.decode_length() == 5

    def test_one_byte_zero(self):
        conn = self._make_conn_with_data(b"\x00")
        assert conn.decode_length() == 0

    def test_two_byte(self):
        # Encode 0x100 (256) as 2 bytes
        encoded = ApiConnection.encode_length(0x100)
        conn = self._make_conn_with_data(encoded)
        assert conn.decode_length() == 0x100

    def test_three_byte(self):
        encoded = ApiConnection.encode_length(0x5000)
        conn = self._make_conn_with_data(encoded)
        assert conn.decode_length() == 0x5000

    def test_four_byte(self):
        encoded = ApiConnection.encode_length(0x300000)
        conn = self._make_conn_with_data(encoded)
        assert conn.decode_length() == 0x300000

    def test_roundtrip_various_sizes(self):
        """Encode then decode various lengths to verify roundtrip."""
        test_values = [0, 1, 127, 128, 255, 256, 0x3FFF, 0x4000,
                       0x1FFFFF, 0x200000, 0xFFFFFFF]
        for val in test_values:
            encoded = ApiConnection.encode_length(val)
            conn = self._make_conn_with_data(encoded)
            decoded = conn.decode_length()
            assert decoded == val, f"Roundtrip failed for {val}: got {decoded}"


class TestSendSentence:
    """Test API sentence encoding and sending."""

    def test_send_single_word(self):
        conn = ApiConnection()
        sock = MagicMock()
        conn._sock = sock

        conn.send_sentence(["/login"])
        sock.sendall.assert_called_once()
        data = sock.sendall.call_args[0][0]
        # Should contain length-encoded "/login" + empty terminator
        assert b"/login" in data
        assert data[-1:] == b"\x00"  # empty word terminator

    def test_send_multiple_words(self):
        conn = ApiConnection()
        sock = MagicMock()
        conn._sock = sock

        conn.send_sentence(["/login", "=name=admin", "=password=test"])
        data = sock.sendall.call_args[0][0]
        assert b"/login" in data
        assert b"=name=admin" in data
        assert b"=password=test" in data

    def test_send_not_connected_raises(self):
        conn = ApiConnection()
        with pytest.raises(ConnectionError):
            conn.send_sentence(["/login"])


class TestReadSentence:
    """Test reading API sentences from socket."""

    def test_read_simple_sentence(self):
        # Build raw data: length-encoded "!done" + zero terminator
        word = b"!done"
        data = ApiConnection.encode_length(len(word)) + word
        data += b"\x00"  # terminator

        conn = ApiConnection()
        sock = MagicMock()
        pos = [0]

        def fake_recv(n):
            result = data[pos[0]:pos[0] + n]
            pos[0] += n
            return result

        sock.recv = fake_recv
        conn._sock = sock

        result = conn.read_sentence()
        assert result == ["!done"]

    def test_read_multi_word_sentence(self):
        words = ["!done", "=ret=abc123"]
        data = b""
        for w in words:
            encoded = w.encode("utf-8")
            data += ApiConnection.encode_length(len(encoded)) + encoded
        data += b"\x00"

        conn = ApiConnection()
        sock = MagicMock()
        pos = [0]

        def fake_recv(n):
            result = data[pos[0]:pos[0] + n]
            pos[0] += n
            return result

        sock.recv = fake_recv
        conn._sock = sock

        result = conn.read_sentence()
        assert result == words


class TestLegacyLoginMD5:
    """Test MD5 challenge-response computation for legacy login."""

    def test_md5_computation(self):
        """Verify MD5 hash matches expected RouterOS legacy login hash."""
        password = "admin"
        challenge_hex = "d41d8cd98f00b204e9800998ecf8427e"
        challenge = bytes.fromhex(challenge_hex)

        md5 = hashlib.md5()
        md5.update(b"\x00")
        md5.update(password.encode("utf-8"))
        md5.update(challenge)
        response = "00" + md5.hexdigest()

        # Verify format: starts with "00", followed by 32 hex chars
        assert response.startswith("00")
        assert len(response) == 34  # "00" + 32 hex digits

    def test_empty_password_md5(self):
        """Test MD5 computation with empty password."""
        password = ""
        challenge_hex = "abcdef0123456789abcdef0123456789"
        challenge = bytes.fromhex(challenge_hex)

        md5 = hashlib.md5()
        md5.update(b"\x00")
        md5.update(password.encode("utf-8"))
        md5.update(challenge)
        response = "00" + md5.hexdigest()

        assert len(response) == 34


class TestCheckLoginResponse:
    """Test login response checking."""

    def test_done_is_success(self):
        assert ApiConnection._check_login_response(["!done"]) is True

    def test_done_with_extras(self):
        assert ApiConnection._check_login_response(
            ["!done", "=ret="]
        ) is True

    def test_trap_is_failure(self):
        assert ApiConnection._check_login_response(
            ["!trap", "=message=invalid user"]
        ) is False

    def test_empty_is_failure(self):
        assert ApiConnection._check_login_response([]) is False


class TestExtractError:
    """Test error message extraction."""

    def test_message_extraction(self):
        assert ApiConnection._extract_error(
            ["!trap", "=message=cannot log in"]
        ) == "cannot log in"

    def test_trap_without_message(self):
        assert "Authentication failed" in ApiConnection._extract_error(
            ["!trap"]
        )

    def test_no_trap(self):
        assert ApiConnection._extract_error(["!done"]) == "Unknown error"
