"""MikroTik WebFig /jsproxy authentication protocol implementation.

Implements the custom MS-CHAP-V2 challenge-response protocol used by
MikroTik's WebFig web interface on port 80. This is NOT standard HTTP
Basic Auth — WebFig uses PPTP-style crypto (MS-CHAP-V2 + MPPE + RC4)
even over plain HTTP.

Protocol flow:
    1. POST /jsproxy (empty body) → server returns challenge
    2. Extract session ID + server challenge from response
    3. Compute MS-CHAP-V2 response (MD4 + DES + SHA1)
    4. POST /jsproxy with response payload
    5. Server validates → establishes encrypted session

Reference: https://github.com/takeshixx/webfixy (libfixy/webfig.py)

Crypto note: MD4 is implemented in pure Python because OpenSSL 3.x
removed MD4 support, and it's not available via hashlib or cryptography.
"""

import hashlib
import socket
import struct
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ------------------------------------------------------------------ #
#  Pure Python MD4 (RFC 1320)                                         #
# ------------------------------------------------------------------ #

def _left_rotate(n: int, b: int) -> int:
    """Left rotate a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def md4(data: bytes) -> bytes:
    """Compute MD4 hash (RFC 1320). Returns 16-byte digest.

    Implemented in pure Python because OpenSSL 3.x dropped MD4 support.
    """
    # Initial hash values
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476

    # Pre-processing: add padding
    msg = bytearray(data)
    msg_len = len(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    # Append original length in bits as 64-bit little-endian
    msg += struct.pack("<Q", msg_len * 8)

    # Process each 512-bit (64-byte) block
    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        # Break block into 16 little-endian 32-bit words
        x = list(struct.unpack("<16I", block))

        a, b, c, d = h0, h1, h2, h3

        # Round 1: F(b, c, d) = (b & c) | (~b & d)
        for k, s in [(0, 3), (1, 7), (2, 11), (3, 19),
                      (4, 3), (5, 7), (6, 11), (7, 19),
                      (8, 3), (9, 7), (10, 11), (11, 19),
                      (12, 3), (13, 7), (14, 11), (15, 19)]:
            f = (b & c) | (~b & d)
            a = _left_rotate((a + (f & 0xFFFFFFFF) + x[k]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        # Round 2: G(b, c, d) = (b & c) | (b & d) | (c & d)
        for k, s in [(0, 3), (4, 5), (8, 9), (12, 13),
                      (1, 3), (5, 5), (9, 9), (13, 13),
                      (2, 3), (6, 5), (10, 9), (14, 13),
                      (3, 3), (7, 5), (11, 9), (15, 13)]:
            g = (b & c) | (b & d) | (c & d)
            a = _left_rotate(
                (a + (g & 0xFFFFFFFF) + x[k] + 0x5A827999) & 0xFFFFFFFF, s
            )
            a, b, c, d = d, a, b, c

        # Round 3: H(b, c, d) = b ^ c ^ d
        for k, s in [(0, 3), (8, 9), (4, 11), (12, 15),
                      (2, 3), (10, 9), (6, 11), (14, 15),
                      (1, 3), (9, 9), (5, 11), (13, 15),
                      (3, 3), (11, 9), (7, 11), (15, 15)]:
            h = b ^ c ^ d
            a = _left_rotate(
                (a + (h & 0xFFFFFFFF) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s
            )
            a, b, c, d = d, a, b, c

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF

    return struct.pack("<4I", h0, h1, h2, h3)


# ------------------------------------------------------------------ #
#  NT Hash and DES key expansion                                      #
# ------------------------------------------------------------------ #

def nt_hash(password: str) -> bytes:
    """Compute the NT hash of a password: MD4(UTF-16LE(password)).

    Returns 16-byte hash.
    """
    return md4(password.encode("utf-16-le"))


def _expand_des_key(key_7: bytes) -> bytes:
    """Expand a 7-byte key to an 8-byte DES key with parity bits.

    DES uses 56-bit keys but expects 8 bytes (with every 8th bit as parity).
    This takes 7 bytes (56 bits) and spreads them into 8 bytes.
    """
    assert len(key_7) == 7
    k = int.from_bytes(key_7, "big")
    # Spread 56 bits into 8 groups of 7 bits, each in the high 7 bits of a byte
    result = []
    for i in range(8):
        shift = 49 - (i * 7)
        if shift >= 0:
            val = (k >> shift) & 0xFE
        else:
            val = (k << (-shift)) & 0xFE
        # Set parity bit (odd parity)
        bits = bin(val).count("1")
        if bits % 2 == 0:
            val |= 1
        result.append(val)
    return bytes(result)


def des_encrypt_ecb(key_7: bytes, data: bytes) -> bytes:
    """DES-ECB encrypt an 8-byte block using a 7-byte key.

    Expands the 7-byte key to 8-byte DES key, then uses TripleDES
    with k1=k2=k3 (effectively single DES) via the cryptography library.
    """
    des_key = _expand_des_key(key_7)
    # TripleDES with 3 identical keys = single DES
    cipher = Cipher(algorithms.TripleDES(des_key * 3), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# ------------------------------------------------------------------ #
#  MS-CHAP-V2 Challenge-Response                                      #
# ------------------------------------------------------------------ #

# Hardcoded peer challenge from MikroTik WebFig (ASCII: !@#$%^&*()_+:3|~)
PEER_CHALLENGE = b"\x21\x40\x23\x24\x25\x5e\x26\x2a\x28\x29\x5f\x2b\x3a\x33\x7c\x7e"


def generate_challenge_hash(
    peer_challenge: bytes, server_challenge: bytes, username: str
) -> bytes:
    """SHA1(peer_challenge + server_challenge + username)[:8].

    Returns 8-byte challenge hash used in MS-CHAP-V2.
    """
    h = hashlib.sha1()
    h.update(peer_challenge)
    h.update(server_challenge)
    h.update(username.encode("utf-8"))
    return h.digest()[:8]


def generate_nt_response(
    server_challenge: bytes, username: str, password: str
) -> bytes:
    """Generate the 24-byte MS-CHAP-V2 NT response.

    Steps:
        1. challenge_hash = SHA1(peer_chal + server_chal + username)[:8]
        2. nt_hash_val = MD4(password_UTF16LE) → 16 bytes
        3. Pad nt_hash to 21 bytes (5 zero bytes)
        4. Split into 3 × 7-byte DES keys
        5. response = DES(k1, chal) + DES(k2, chal) + DES(k3, chal) → 24 bytes
    """
    challenge_hash = generate_challenge_hash(
        PEER_CHALLENGE, server_challenge, username
    )
    nt_hash_val = nt_hash(password)

    # Pad to 21 bytes
    padded = nt_hash_val + b"\x00" * 5

    # Split into 3 × 7-byte keys and DES-encrypt challenge_hash
    response = b""
    for i in range(3):
        key_7 = padded[i * 7:(i + 1) * 7]
        response += des_encrypt_ecb(key_7, challenge_hash)

    return response


# ------------------------------------------------------------------ #
#  MPPE Key Derivation (for RC4 session — needed for success check)   #
# ------------------------------------------------------------------ #

_MAGIC1 = (
    b"This is the MPPE Master Key"
)
_MAGIC2 = (
    b"On the client side, this is the send key; "
    b"on the server side, it is the receive key."
)
_MAGIC3 = (
    b"On the client side, this is the receive key; "
    b"on the server side, it is the send key."
)
_SHA_PAD1 = b"\x00" * 40
_SHA_PAD2 = b"\xf2" * 40


def _get_master_key(nt_hash_val: bytes, nt_response: bytes) -> bytes:
    """Derive MPPE master key from NT hash and NT response."""
    nt_hash_hash = md4(nt_hash_val)
    h = hashlib.sha1()
    h.update(nt_hash_hash)
    h.update(nt_response)
    h.update(_MAGIC1)
    return h.digest()[:16]


def _get_asymmetric_key(master_key: bytes, magic: bytes) -> bytes:
    """Derive an asymmetric session key."""
    h = hashlib.sha1()
    h.update(master_key)
    h.update(_SHA_PAD1)
    h.update(magic)
    h.update(_SHA_PAD2)
    return h.digest()[:16]


def derive_session_keys(
    password: str, nt_response: bytes
) -> Tuple[bytes, bytes]:
    """Derive RC4 send/receive keys from password and NT response.

    Returns (send_key, recv_key) — each 16 bytes.
    """
    nt_hash_val = nt_hash(password)
    master_key = _get_master_key(nt_hash_val, nt_response)
    send_key = _get_asymmetric_key(master_key, _MAGIC2)
    recv_key = _get_asymmetric_key(master_key, _MAGIC3)
    return send_key, recv_key


# ------------------------------------------------------------------ #
#  RC4 with drop(768)                                                  #
# ------------------------------------------------------------------ #

class RC4:
    """RC4 stream cipher with drop(768) — drops first 768 keystream bytes."""

    def __init__(self, key: bytes):
        self._cipher = Cipher(algorithms.ARC4(key), mode=None)
        self._encryptor = self._cipher.encryptor()
        # Drop first 768 bytes of keystream (security hardening)
        self._encryptor.update(b"\x00" * 768)

    def encrypt(self, data: bytes) -> bytes:
        return self._encryptor.update(data)

    def decrypt(self, data: bytes) -> bytes:
        # RC4 is symmetric — encrypt == decrypt
        return self._encryptor.update(data)


# ------------------------------------------------------------------ #
#  UTF-16LE binary encoding (WebFig wire format)                      #
# ------------------------------------------------------------------ #

def pack_bytes(data: bytes) -> bytes:
    """Decode UTF-16LE encoded binary data to raw bytes.

    WebFig transmits binary data as UTF-16LE where each byte X becomes
    [X, 0x00]. This extracts the original bytes.
    """
    result = bytearray()
    for i in range(0, len(data) - 1, 2):
        result.append(data[i])
    return bytes(result)


def unpack_bytes(data: bytes) -> bytes:
    """Encode raw bytes as UTF-16LE for WebFig wire format.

    Each byte X becomes [X, 0x00] in the output.
    """
    result = bytearray()
    for b in data:
        result.append(b)
        result.append(0x00)
    return bytes(result)


# ------------------------------------------------------------------ #
#  WebFig HTTP Connection                                              #
# ------------------------------------------------------------------ #

class WebfigError(Exception):
    """Raised on WebFig protocol errors."""


class WebfigConnection:
    """Low-level WebFig /jsproxy connection handler."""

    def __init__(self):
        self._sock: Optional[socket.socket] = None
        self._host: str = ""

    def connect(self, host: str, port: int, timeout: int = 10,
                sock: Optional[socket.socket] = None):
        """Open a TCP connection to the WebFig HTTP service."""
        self._host = host
        if sock is not None:
            self._sock = sock
            self._sock.settimeout(timeout)
        else:
            self._sock = socket.create_connection(
                (host, port), timeout=timeout
            )

    def close(self):
        """Close the connection."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def _send_http_post(self, path: str, body: bytes = b""):
        """Send a minimal HTTP/1.1 POST request."""
        if self._sock is None:
            raise ConnectionError("Not connected")
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self._host}\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode("ascii") + body
        self._sock.sendall(request)

    def _recv_all(self, bufsize: int = 8192) -> bytes:
        """Read all available data from socket."""
        data = b""
        while True:
            try:
                chunk = self._sock.recv(bufsize)
                if not chunk:
                    break
                data += chunk
                # If we got headers + body, try to determine if complete
                if b"\r\n\r\n" in data:
                    header_end = data.index(b"\r\n\r\n") + 4
                    headers = data[:header_end].decode("ascii", errors="replace")
                    # Check Content-Length
                    for line in headers.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            expected = int(line.split(":")[1].strip())
                            body_so_far = len(data) - header_end
                            if body_so_far >= expected:
                                return data
                    # If no content-length and we got some data, try short read
                    if len(data) > header_end:
                        # Brief wait for more data
                        self._sock.settimeout(1.0)
                        try:
                            more = self._sock.recv(bufsize)
                            if more:
                                data += more
                        except socket.timeout:
                            pass
                        return data
            except socket.timeout:
                break
        return data

    def _parse_http_response(
        self, raw: bytes
    ) -> Tuple[int, dict, bytes]:
        """Parse an HTTP response into (status_code, headers, body)."""
        if b"\r\n\r\n" not in raw:
            raise WebfigError("Invalid HTTP response: no header terminator")

        header_end = raw.index(b"\r\n\r\n") + 4
        header_bytes = raw[:header_end]
        body = raw[header_end:]

        lines = header_bytes.decode("ascii", errors="replace").split("\r\n")
        status_line = lines[0]
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            raise WebfigError(f"Invalid status line: {status_line}")
        status_code = int(parts[1])

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        return status_code, headers, body

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """Attempt WebFig login via /jsproxy MS-CHAP-V2 handshake.

        Returns:
            (success, error_message) tuple.
        """
        try:
            # Step 1: Initial POST to get server challenge
            self._send_http_post("/jsproxy")
            raw_resp = self._recv_all()
            status, headers, body = self._parse_http_response(raw_resp)

            if status != 200:
                return False, f"HTTP {status} on initial handshake"

            if len(body) < 16:
                return False, "Challenge response too short"

            # Decode UTF-16LE body to raw bytes
            raw_data = pack_bytes(body)

            if len(raw_data) < 24:
                # Not enough data for session_id + seq + challenge
                return False, "Challenge data too short after decode"

            # Extract session ID, sequence, and server challenge
            session_id = struct.unpack("!I", raw_data[:4])[0]
            seq = struct.unpack("!I", raw_data[4:8])[0]
            server_challenge = raw_data[8:24]

            # Step 2: Compute MS-CHAP-V2 response
            nt_resp = generate_nt_response(
                server_challenge, username, password
            )

            # Step 3: Build response payload
            payload = bytearray()
            payload += struct.pack("!I", session_id)
            payload += struct.pack("!I", 0)  # zero flag
            payload += server_challenge
            payload += struct.pack("!H", 0)  # zero flag
            payload += PEER_CHALLENGE
            payload += struct.pack("!Q", 0)  # zero padding
            payload += nt_resp
            payload += username.encode("utf-8")

            # Encode as UTF-16LE for WebFig wire format
            wire_payload = unpack_bytes(bytes(payload))

            # Step 4: Send authentication response
            self._send_http_post("/jsproxy", wire_payload)
            raw_resp2 = self._recv_all()
            status2, headers2, body2 = self._parse_http_response(raw_resp2)

            if status2 == 200 and len(body2) > 0:
                # Server accepted the auth — it responds with session data
                # A failed auth typically returns an empty body or error
                return True, ""
            elif status2 == 403:
                return False, "Authentication rejected (HTTP 403)"
            elif status2 == 200 and len(body2) == 0:
                return False, "Authentication failed (empty response)"
            else:
                return False, f"Unexpected HTTP {status2}"

        except WebfigError as e:
            return False, str(e)
        except (ConnectionError, socket.error, OSError) as e:
            return False, f"Connection error: {e}"
