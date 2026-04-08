"""SSH credential tester using paramiko with multiple auth methods."""

import logging
import socket
from dataclasses import dataclass
from typing import Optional

import paramiko

logger = logging.getLogger("mikrotik_tester")


@dataclass
class SSHResult:
    """Result of an SSH credential test."""
    success: bool
    auth_method: str = ""
    error_type: Optional[str] = None
    message: str = ""


class SSHTester:
    """Tests credentials against SSH with password, keyboard-interactive,
    and key-based authentication."""

    def __init__(self, host: str, port: int = 22, timeout: int = 10,
                 key_file: Optional[str] = None):
        self._host = host
        self._port = port
        self._timeout = timeout
        self._key_file = key_file
        self._host_key_policy = paramiko.AutoAddPolicy()

    def test_credential(self, username: str, password: str,
                        sock: Optional[socket.socket] = None) -> SSHResult:
        """Test a single username/password via SSH.

        Tries authentication methods in order:
        1. Password authentication
        2. Keyboard-interactive (sends password in response)
        3. Key-based (if key_file configured)

        Args:
            username: SSH username.
            password: Password to test.
            sock: Optional pre-connected socket (e.g. via proxy).

        Returns:
            SSHResult with success status and method used.
        """
        transport = None
        try:
            if sock is not None:
                transport = paramiko.Transport(sock)
            else:
                transport = paramiko.Transport((self._host, self._port))

            transport.connect()
            transport.set_keepalive(30)

            # Method 1: Password authentication
            try:
                transport.auth_password(username, password)
                if transport.is_authenticated():
                    logger.debug("SSH password auth SUCCESS: %s", username)
                    return SSHResult(
                        success=True, auth_method="password",
                        message="Password authentication successful",
                    )
            except paramiko.AuthenticationException:
                pass
            except paramiko.SSHException:
                pass

            # Method 2: Keyboard-interactive
            if not transport.is_authenticated():
                try:
                    def kbd_interactive_handler(title, instructions, prompts):
                        return [password] * len(prompts)

                    transport.auth_interactive(username,
                                               kbd_interactive_handler)
                    if transport.is_authenticated():
                        logger.debug(
                            "SSH keyboard-interactive SUCCESS: %s", username
                        )
                        return SSHResult(
                            success=True,
                            auth_method="keyboard-interactive",
                            message="Keyboard-interactive auth successful",
                        )
                except paramiko.AuthenticationException:
                    pass
                except paramiko.SSHException:
                    pass

            # Method 3: Key-based fallback
            if not transport.is_authenticated() and self._key_file:
                try:
                    pkey = self._load_key(self._key_file, password)
                    if pkey:
                        transport.auth_publickey(username, pkey)
                        if transport.is_authenticated():
                            logger.debug(
                                "SSH key auth SUCCESS: %s", username
                            )
                            return SSHResult(
                                success=True, auth_method="publickey",
                                message="Key-based auth successful",
                            )
                except paramiko.AuthenticationException:
                    pass
                except paramiko.SSHException:
                    pass

            return SSHResult(
                success=False, error_type="auth_failed",
                message="All authentication methods failed",
            )

        except paramiko.AuthenticationException:
            return SSHResult(
                success=False, error_type="auth_failed",
                message="Authentication failed",
            )
        except socket.timeout:
            return SSHResult(
                success=False, error_type="timeout",
                message="Connection timed out",
            )
        except ConnectionRefusedError:
            return SSHResult(
                success=False, error_type="connection_refused",
                message="SSH connection refused",
            )
        except paramiko.SSHException as e:
            return SSHResult(
                success=False, error_type="ssh_error",
                message=str(e),
            )
        except (ConnectionError, EOFError, OSError) as e:
            return SSHResult(
                success=False, error_type="connection_error",
                message=str(e),
            )
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass

    @staticmethod
    def _load_key(key_file: str,
                  passphrase: str = "") -> Optional[paramiko.PKey]:
        """Try loading a private key file with various key types."""
        key_classes = [
            paramiko.RSAKey,
            paramiko.Ed25519Key,
            paramiko.ECDSAKey,
            paramiko.DSSKey,
        ]
        pwd = passphrase if passphrase else None
        for key_cls in key_classes:
            try:
                return key_cls.from_private_key_file(key_file, password=pwd)
            except (paramiko.SSHException, ValueError, IOError):
                continue
        return None
