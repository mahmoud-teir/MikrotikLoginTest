"""RouterOS API wire protocol implementation.

Implements the binary framing, length encoding, and both legacy (MD5
challenge-response) and modern (plaintext) login flows for the RouterOS
API service on port 8728/tcp.

Reference: https://help.mikrotik.com/docs/spaces/ROS/pages/47579156/API
"""

import hashlib
import socket
import struct
from typing import Dict, List, Optional, Tuple


class ApiError(Exception):
    """Raised when the RouterOS API returns a !trap or !fatal."""

    def __init__(self, message: str, category: str = ""):
        super().__init__(message)
        self.category = category


class ApiConnection:
    """Low-level RouterOS API connection and protocol handler."""

    def __init__(self):
        self._sock: Optional[socket.socket] = None

    # ------------------------------------------------------------------ #
    #  Connection management                                              #
    # ------------------------------------------------------------------ #

    def connect(self, host: str, port: int, timeout: int = 10,
                sock: Optional[socket.socket] = None):
        """Open a TCP connection to the RouterOS API.

        Args:
            host: Router IP or hostname.
            port: API port (usually 8728).
            timeout: Socket timeout in seconds.
            sock: Pre-created socket (e.g. via SOCKS proxy).
        """
        if sock is not None:
            self._sock = sock
            self._sock.settimeout(timeout)
        else:
            self._sock = socket.create_connection((host, port),
                                                  timeout=timeout)

    def close(self):
        """Close the API connection."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def connected(self) -> bool:
        return self._sock is not None

    # ------------------------------------------------------------------ #
    #  Length encoding/decoding (RouterOS wire format)                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def encode_length(length: int) -> bytes:
        """Encode an integer length into the RouterOS variable-length format.

        Encoding rules:
            0x00 ..       0x7F  ->  1 byte
            0x80 ..     0x3FFF  ->  2 bytes, first byte has 0x80 set
            0x4000 ..  0x1FFFFF ->  3 bytes, first byte has 0xC0 set
            0x200000 .. 0xFFFFFFF -> 4 bytes, first byte has 0xE0 set
        """
        if length < 0x80:
            return struct.pack("!B", length)
        elif length < 0x4000:
            return struct.pack("!H", length | 0x8000)
        elif length < 0x200000:
            return struct.pack("!I", length | 0xC00000)[1:]  # 3 bytes
        elif length < 0x10000000:
            return struct.pack("!I", length | 0xE0000000)
        else:
            return b"\xf0" + struct.pack("!I", length)

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly n bytes from the socket."""
        data = b""
        while len(data) < n:
            chunk = self._sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by remote host")
            data += chunk
        return data

    def decode_length(self) -> int:
        """Read and decode a RouterOS length from the socket."""
        b = self._recv_exact(1)
        first = b[0]

        if first < 0x80:
            return first
        elif first < 0xC0:
            second = self._recv_exact(1)
            return ((first & 0x3F) << 8) | second[0]
        elif first < 0xE0:
            rest = self._recv_exact(2)
            return ((first & 0x1F) << 16) | (rest[0] << 8) | rest[1]
        elif first < 0xF0:
            rest = self._recv_exact(3)
            return (
                ((first & 0x0F) << 24)
                | (rest[0] << 16)
                | (rest[1] << 8)
                | rest[2]
            )
        else:
            rest = self._recv_exact(4)
            return struct.unpack("!I", rest)[0]

    # ------------------------------------------------------------------ #
    #  Sentence I/O                                                       #
    # ------------------------------------------------------------------ #

    def send_sentence(self, words: List[str]):
        """Encode and send an API sentence (list of words + empty terminator)."""
        if self._sock is None:
            raise ConnectionError("Not connected")
        data = b""
        for word in words:
            encoded = word.encode("utf-8")
            data += self.encode_length(len(encoded)) + encoded
        data += self.encode_length(0)  # empty word terminates sentence
        self._sock.sendall(data)

    def read_sentence(self) -> List[str]:
        """Read and decode a complete API sentence from the socket."""
        if self._sock is None:
            raise ConnectionError("Not connected")
        words = []
        while True:
            length = self.decode_length()
            if length == 0:
                break
            word_bytes = self._recv_exact(length)
            words.append(word_bytes.decode("utf-8", errors="replace"))
        return words

    # ------------------------------------------------------------------ #
    #  Authentication                                                      #
    # ------------------------------------------------------------------ #

    def login_legacy(self, username: str, password: str) -> bool:
        """Legacy login (RouterOS < 6.43): MD5 challenge-response.

        1. Send /login
        2. Receive =ret=<hex_challenge>
        3. Compute MD5(0x00 + password + challenge_bytes)
        4. Send /login with =name= and =response=
        """
        self.send_sentence(["/login"])
        resp = self.read_sentence()

        challenge_hex = None
        for word in resp:
            if word.startswith("=ret="):
                challenge_hex = word[5:]
                break

        if challenge_hex is None:
            raise ApiError("No challenge received in legacy login")

        challenge = bytes.fromhex(challenge_hex)
        md5 = hashlib.md5()
        md5.update(b"\x00")
        md5.update(password.encode("utf-8"))
        md5.update(challenge)
        response = "00" + md5.hexdigest()

        self.send_sentence([
            "/login",
            f"=name={username}",
            f"=response={response}",
        ])
        resp = self.read_sentence()
        return self._check_login_response(resp)

    def login_modern(self, username: str, password: str) -> bool:
        """Modern login (RouterOS >= 6.43): plaintext credentials.

        Send /login with =name= and =password= in a single sentence.
        """
        self.send_sentence([
            "/login",
            f"=name={username}",
            f"=password={password}",
        ])
        resp = self.read_sentence()
        return self._check_login_response(resp)

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """Attempt login, trying modern first then falling back to legacy.

        Returns:
            (success, error_message) tuple.
        """
        try:
            # Try modern login first
            self.send_sentence([
                "/login",
                f"=name={username}",
                f"=password={password}",
            ])
            resp = self.read_sentence()

            # Check if we got a challenge (legacy mode)
            challenge_hex = None
            for word in resp:
                if word.startswith("=ret="):
                    challenge_hex = word[5:]
                    break

            if challenge_hex is not None:
                # Router responded with challenge -> legacy mode
                challenge = bytes.fromhex(challenge_hex)
                md5 = hashlib.md5()
                md5.update(b"\x00")
                md5.update(password.encode("utf-8"))
                md5.update(challenge)
                response = "00" + md5.hexdigest()

                self.send_sentence([
                    "/login",
                    f"=name={username}",
                    f"=response={response}",
                ])
                resp = self.read_sentence()

            if self._check_login_response(resp):
                return True, ""
            else:
                return False, self._extract_error(resp)

        except ApiError as e:
            return False, str(e)
        except (ConnectionError, socket.error, OSError) as e:
            return False, f"Connection error: {e}"

    @staticmethod
    def _check_login_response(words: List[str]) -> bool:
        """Check if login response indicates success."""
        for word in words:
            if word == "!done":
                return True
        return False

    @staticmethod
    def _extract_error(words: List[str]) -> str:
        """Extract error message from a !trap response."""
        for word in words:
            if word.startswith("=message="):
                return word[9:]
        if words and words[0] == "!trap":
            return "Authentication failed"
        return "Unknown error"

    # ------------------------------------------------------------------ #
    #  Command execution                                                   #
    # ------------------------------------------------------------------ #

    def execute_command(self, command: str,
                        params: Optional[Dict[str, str]] = None
                        ) -> List[Dict[str, str]]:
        """Execute a RouterOS API command and collect responses.

        Args:
            command: API command path (e.g. "/ip/address/print").
            params: Optional query parameters.

        Returns:
            List of dictionaries, one per !re response row.
        """
        words = [command]
        if params:
            for key, value in params.items():
                words.append(f"={key}={value}")

        self.send_sentence(words)

        results = []
        while True:
            resp = self.read_sentence()
            if not resp:
                break

            if resp[0] == "!re":
                row = {}
                for word in resp[1:]:
                    if word.startswith("=") and "=" in word[1:]:
                        key, _, value = word[1:].partition("=")
                        row[key] = value
                results.append(row)
            elif resp[0] == "!trap":
                msg = self._extract_error(resp)
                raise ApiError(msg)
            elif resp[0] == "!done":
                break
            elif resp[0] == "!fatal":
                msg = self._extract_error(resp)
                raise ApiError(msg, category="fatal")

        return results
