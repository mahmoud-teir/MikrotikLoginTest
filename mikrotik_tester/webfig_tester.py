"""WebFig (HTTP) credential tester using MS-CHAP-V2 via /jsproxy."""

import logging
import socket
from dataclasses import dataclass
from typing import Optional

from .webfig_protocol import WebfigConnection, WebfigError

logger = logging.getLogger("mikrotik_tester")


@dataclass
class WebfigResult:
    """Result of a WebFig credential test."""
    success: bool
    error_type: Optional[str] = None
    message: str = ""


class WebfigTester:
    """Tests credentials against MikroTik WebFig (port 80)."""

    def __init__(self, host: str, port: int = 80, timeout: int = 10):
        self._host = host
        self._port = port
        self._timeout = timeout

    def test_credential(self, username: str, password: str,
                        sock: Optional[socket.socket] = None) -> WebfigResult:
        """Test a single username/password pair against WebFig.

        Args:
            username: RouterOS username.
            password: Password to test.
            sock: Optional pre-connected socket (e.g. via proxy).

        Returns:
            WebfigResult with success status and error details.
        """
        conn = WebfigConnection()
        try:
            conn.connect(self._host, self._port, self._timeout, sock=sock)
            success, error = conn.login(username, password)

            if success:
                logger.debug("WebFig login SUCCESS: %s", username)
                return WebfigResult(success=True, message="Login successful")
            else:
                return WebfigResult(
                    success=False,
                    error_type=self._classify_error(error),
                    message=error,
                )

        except ConnectionRefusedError:
            return WebfigResult(
                success=False, error_type="connection_refused",
                message="Connection refused - WebFig may be disabled",
            )
        except socket.timeout:
            return WebfigResult(
                success=False, error_type="timeout",
                message="Connection timed out",
            )
        except ConnectionError as e:
            return WebfigResult(
                success=False, error_type="connection_error",
                message=str(e),
            )
        except WebfigError as e:
            return WebfigResult(
                success=False, error_type="protocol_error",
                message=str(e),
            )
        except OSError as e:
            return WebfigResult(
                success=False, error_type="os_error",
                message=str(e),
            )
        finally:
            conn.close()

    @staticmethod
    def _classify_error(error_msg: str) -> str:
        """Classify an error message into a category."""
        msg_lower = error_msg.lower()
        if "403" in msg_lower or "rejected" in msg_lower:
            return "auth_failed"
        if "empty response" in msg_lower or "failed" in msg_lower:
            return "auth_failed"
        if "timeout" in msg_lower:
            return "timeout"
        if "connection" in msg_lower:
            return "connection_error"
        if "too short" in msg_lower:
            return "protocol_error"
        return "unknown"
