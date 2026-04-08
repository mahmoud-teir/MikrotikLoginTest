"""Tests for WebFig /jsproxy protocol — MD4, DES, MS-CHAP-V2."""

import hashlib
import struct
from unittest.mock import MagicMock

from mikrotik_tester.webfig_protocol import (
    PEER_CHALLENGE,
    RC4,
    WebfigConnection,
    _expand_des_key,
    des_encrypt_ecb,
    derive_session_keys,
    generate_challenge_hash,
    generate_nt_response,
    md4,
    nt_hash,
    pack_bytes,
    unpack_bytes,
)


# ------------------------------------------------------------------ #
#  MD4 tests (RFC 1320 test vectors)                                  #
# ------------------------------------------------------------------ #


class TestMD4:
    """Test pure Python MD4 against RFC 1320 test vectors."""

    def test_empty_string(self):
        assert md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_single_a(self):
        assert md4(b"a").hex() == "bde52cb31de33e46245e05fbdbd6fb24"

    def test_abc(self):
        assert md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"

    def test_message_digest(self):
        assert md4(b"message digest").hex() == "d9130a8164549fe818874806e1c7014b"

    def test_lowercase_alphabet(self):
        assert (
            md4(b"abcdefghijklmnopqrstuvwxyz").hex()
            == "d79e1c308aa5bbcdeea8ed63df412da9"
        )

    def test_alphanumeric(self):
        data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        assert md4(data).hex() == "043f8582f241db351ce627e153e7f0e4"

    def test_numeric_sequence(self):
        data = b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        assert md4(data).hex() == "e33b4ddc9c38f2199c3e7b164fcc0536"

    def test_returns_16_bytes(self):
        result = md4(b"test")
        assert len(result) == 16

    def test_deterministic(self):
        assert md4(b"hello") == md4(b"hello")

    def test_different_inputs_differ(self):
        assert md4(b"hello") != md4(b"world")


# ------------------------------------------------------------------ #
#  NT Hash tests                                                       #
# ------------------------------------------------------------------ #


class TestNTHash:
    """Test NT hash (MD4 of UTF-16LE password)."""

    def test_empty_password(self):
        # NT hash of "" = MD4("") = 31d6cfe0...
        result = nt_hash("")
        assert result.hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_known_password(self):
        # Known NT hash for "password" = MD4(UTF-16LE("password"))
        result = nt_hash("password")
        assert result.hex() == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_admin(self):
        # NT hash of "admin"
        result = nt_hash("admin")
        assert len(result) == 16

    def test_unicode_password(self):
        # Should not crash with unicode
        result = nt_hash("p\u00e4ssw\u00f6rd")
        assert len(result) == 16


# ------------------------------------------------------------------ #
#  DES key expansion tests                                             #
# ------------------------------------------------------------------ #


class TestDESKeyExpansion:
    """Test 7-byte to 8-byte DES key expansion."""

    def test_output_length(self):
        key_7 = b"\x00" * 7
        result = _expand_des_key(key_7)
        assert len(result) == 8

    def test_all_zeros(self):
        key_7 = b"\x00" * 7
        result = _expand_des_key(key_7)
        # All zeros input → each byte should have just a parity bit
        assert len(result) == 8
        for byte in result:
            assert byte in (0, 1)

    def test_all_ones(self):
        key_7 = b"\xff" * 7
        result = _expand_des_key(key_7)
        assert len(result) == 8
        # Each output byte should have odd parity
        for byte in result:
            assert bin(byte).count("1") % 2 == 1

    def test_parity_bits_are_odd(self):
        """Every DES key byte must have odd parity."""
        key_7 = b"\x12\x34\x56\x78\x9a\xbc\xde"
        result = _expand_des_key(key_7)
        for byte in result:
            assert bin(byte).count("1") % 2 == 1

    def test_deterministic(self):
        key_7 = b"\xab\xcd\xef\x01\x23\x45\x67"
        assert _expand_des_key(key_7) == _expand_des_key(key_7)


# ------------------------------------------------------------------ #
#  DES encryption tests                                                #
# ------------------------------------------------------------------ #


class TestDESEncrypt:
    """Test DES-ECB encryption with 7-byte keys."""

    def test_output_length(self):
        result = des_encrypt_ecb(b"\x00" * 7, b"\x00" * 8)
        assert len(result) == 8

    def test_different_keys_different_output(self):
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        r1 = des_encrypt_ecb(b"\x00" * 7, data)
        r2 = des_encrypt_ecb(b"\xff" * 7, data)
        assert r1 != r2

    def test_different_data_different_output(self):
        key = b"\x12\x34\x56\x78\x9a\xbc\xde"
        r1 = des_encrypt_ecb(key, b"\x00" * 8)
        r2 = des_encrypt_ecb(key, b"\xff" * 8)
        assert r1 != r2

    def test_deterministic(self):
        key = b"\xab\xcd\xef\x01\x23\x45\x67"
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        assert des_encrypt_ecb(key, data) == des_encrypt_ecb(key, data)


# ------------------------------------------------------------------ #
#  Challenge hash tests                                                #
# ------------------------------------------------------------------ #


class TestChallengeHash:
    """Test MS-CHAP-V2 challenge hash generation."""

    def test_output_length(self):
        result = generate_challenge_hash(
            b"\x00" * 16, b"\x11" * 16, "admin"
        )
        assert len(result) == 8

    def test_uses_sha1(self):
        """Verify it's SHA1(peer + server + username)[:8]."""
        peer = b"\xaa" * 16
        server = b"\xbb" * 16
        username = "testuser"
        expected = hashlib.sha1(
            peer + server + username.encode("utf-8")
        ).digest()[:8]
        assert generate_challenge_hash(peer, server, username) == expected

    def test_different_challenges_differ(self):
        r1 = generate_challenge_hash(b"\x00" * 16, b"\x11" * 16, "admin")
        r2 = generate_challenge_hash(b"\x00" * 16, b"\x22" * 16, "admin")
        assert r1 != r2

    def test_different_usernames_differ(self):
        chal = b"\x00" * 16
        r1 = generate_challenge_hash(chal, chal, "admin")
        r2 = generate_challenge_hash(chal, chal, "root")
        assert r1 != r2


# ------------------------------------------------------------------ #
#  NT Response (full MS-CHAP-V2) tests                                 #
# ------------------------------------------------------------------ #


class TestNTResponse:
    """Test complete MS-CHAP-V2 NT response generation."""

    def test_output_length(self):
        result = generate_nt_response(b"\x00" * 16, "admin", "password")
        assert len(result) == 24

    def test_three_des_blocks(self):
        """24 bytes = 3 × 8-byte DES blocks."""
        result = generate_nt_response(b"\x11" * 16, "admin", "test123")
        block1 = result[0:8]
        block2 = result[8:16]
        block3 = result[16:24]
        # All three blocks should be different (different DES keys)
        assert block1 != block2
        assert block2 != block3

    def test_deterministic(self):
        challenge = b"\xaa\xbb\xcc\xdd" * 4
        r1 = generate_nt_response(challenge, "admin", "password")
        r2 = generate_nt_response(challenge, "admin", "password")
        assert r1 == r2

    def test_different_passwords_differ(self):
        challenge = b"\x00" * 16
        r1 = generate_nt_response(challenge, "admin", "password1")
        r2 = generate_nt_response(challenge, "admin", "password2")
        assert r1 != r2

    def test_different_challenges_differ(self):
        r1 = generate_nt_response(b"\x00" * 16, "admin", "password")
        r2 = generate_nt_response(b"\xff" * 16, "admin", "password")
        assert r1 != r2

    def test_uses_peer_challenge(self):
        """Verify the hardcoded peer challenge is used."""
        assert len(PEER_CHALLENGE) == 16
        assert PEER_CHALLENGE == (
            b"\x21\x40\x23\x24\x25\x5e\x26\x2a"
            b"\x28\x29\x5f\x2b\x3a\x33\x7c\x7e"
        )


# ------------------------------------------------------------------ #
#  Session key derivation tests                                        #
# ------------------------------------------------------------------ #


class TestSessionKeys:
    """Test MPPE session key derivation."""

    def test_output_lengths(self):
        nt_resp = generate_nt_response(b"\x00" * 16, "admin", "password")
        send_key, recv_key = derive_session_keys("password", nt_resp)
        assert len(send_key) == 16
        assert len(recv_key) == 16

    def test_send_recv_differ(self):
        nt_resp = generate_nt_response(b"\x00" * 16, "admin", "test")
        send_key, recv_key = derive_session_keys("test", nt_resp)
        assert send_key != recv_key

    def test_deterministic(self):
        nt_resp = generate_nt_response(b"\x00" * 16, "admin", "pass")
        k1 = derive_session_keys("pass", nt_resp)
        k2 = derive_session_keys("pass", nt_resp)
        assert k1 == k2


# ------------------------------------------------------------------ #
#  RC4 tests                                                           #
# ------------------------------------------------------------------ #


class TestRC4:
    """Test RC4 stream cipher with drop(768)."""

    def test_encrypt_decrypt_roundtrip(self):
        key = b"0123456789abcdef"
        rc4_enc = RC4(key)
        rc4_dec = RC4(key)
        plaintext = b"Hello, WebFig!"
        ciphertext = rc4_enc.encrypt(plaintext)
        assert ciphertext != plaintext
        decrypted = rc4_dec.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_different_keys_different_output(self):
        data = b"test data"
        r1 = RC4(b"key1_padded_16xx").encrypt(data)
        r2 = RC4(b"key2_padded_16xx").encrypt(data)
        assert r1 != r2

    def test_output_same_length(self):
        data = b"exactly 16 bytes"
        result = RC4(b"0123456789abcdef").encrypt(data)
        assert len(result) == len(data)


# ------------------------------------------------------------------ #
#  UTF-16LE encoding/decoding tests                                    #
# ------------------------------------------------------------------ #


class TestUTF16Encoding:
    """Test WebFig wire format encoding (UTF-16LE)."""

    def test_pack_bytes_basic(self):
        # UTF-16LE: [0x41, 0x00, 0x42, 0x00] → [0x41, 0x42]
        assert pack_bytes(b"\x41\x00\x42\x00") == b"\x41\x42"

    def test_unpack_bytes_basic(self):
        # [0x41, 0x42] → [0x41, 0x00, 0x42, 0x00]
        assert unpack_bytes(b"\x41\x42") == b"\x41\x00\x42\x00"

    def test_roundtrip(self):
        original = b"\x01\x02\x03\x04\x05"
        assert pack_bytes(unpack_bytes(original)) == original

    def test_empty(self):
        assert pack_bytes(b"") == b""
        assert unpack_bytes(b"") == b""

    def test_unpack_doubles_length(self):
        data = b"\xaa\xbb\xcc"
        assert len(unpack_bytes(data)) == len(data) * 2


# ------------------------------------------------------------------ #
#  HTTP parsing tests                                                  #
# ------------------------------------------------------------------ #


class TestHTTPParsing:
    """Test HTTP response parsing in WebfigConnection."""

    def test_parse_200_ok(self):
        conn = WebfigConnection()
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"hello"
        )
        status, headers, body = conn._parse_http_response(raw)
        assert status == 200
        assert headers["content-type"] == "text/plain"
        assert body == b"hello"

    def test_parse_403(self):
        conn = WebfigConnection()
        raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        status, headers, body = conn._parse_http_response(raw)
        assert status == 403
        assert body == b""

    def test_parse_with_body(self):
        conn = WebfigConnection()
        body_data = b"\x00\x01\x02\x03"
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 4\r\n"
            b"\r\n"
        ) + body_data
        status, headers, body = conn._parse_http_response(raw)
        assert status == 200
        assert body == body_data


# ------------------------------------------------------------------ #
#  HTTP POST framing tests                                             #
# ------------------------------------------------------------------ #


class TestHTTPPostFraming:
    """Test HTTP POST request construction."""

    def test_send_post_format(self):
        conn = WebfigConnection()
        sock = MagicMock()
        conn._sock = sock
        conn._host = "192.168.88.1"

        conn._send_http_post("/jsproxy", b"test body")

        sent = sock.sendall.call_args[0][0]
        assert b"POST /jsproxy HTTP/1.1\r\n" in sent
        assert b"Host: 192.168.88.1\r\n" in sent
        assert b"Content-Length: 9\r\n" in sent
        assert sent.endswith(b"test body")

    def test_send_empty_body(self):
        conn = WebfigConnection()
        sock = MagicMock()
        conn._sock = sock
        conn._host = "10.0.0.1"

        conn._send_http_post("/jsproxy")

        sent = sock.sendall.call_args[0][0]
        assert b"Content-Length: 0\r\n" in sent

    def test_not_connected_raises(self):
        conn = WebfigConnection()
        try:
            conn._send_http_post("/jsproxy")
            assert False, "Should have raised"
        except ConnectionError:
            pass
