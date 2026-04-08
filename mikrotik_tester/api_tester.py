"""RouterOS API credential tester with session reuse and config reading."""

import logging
import socket
from dataclasses import dataclass
from typing import Dict, Optional

from .api_protocol import ApiConnection, ApiError

logger = logging.getLogger("mikrotik_tester")


@dataclass
class ApiResult:
    """Result of an API credential test."""
    success: bool
    error_type: Optional[str] = None
    message: str = ""


class ApiTester:
    """Tests credentials against the RouterOS API (port 8728)."""

    def __init__(self, host: str, port: int = 8728, timeout: int = 10):
        self._host = host
        self._port = port
        self._timeout = timeout
        self._config_connection: Optional[ApiConnection] = None

    def test_credential(self, username: str, password: str,
                        sock: Optional[socket.socket] = None) -> ApiResult:
        """Test a single username/password pair against the API.

        Args:
            username: RouterOS username.
            password: Password to test.
            sock: Optional pre-connected socket (e.g. via proxy).

        Returns:
            ApiResult with success status and error details.
        """
        conn = ApiConnection()
        try:
            conn.connect(self._host, self._port, self._timeout, sock=sock)
            success, error = conn.login(username, password)

            if success:
                logger.debug("API login SUCCESS: %s", username)
                return ApiResult(success=True, message="Login successful")
            else:
                return ApiResult(
                    success=False,
                    error_type=self._classify_error(error),
                    message=error,
                )

        except ConnectionRefusedError:
            return ApiResult(
                success=False, error_type="connection_refused",
                message="Connection refused - API port may be disabled",
            )
        except socket.timeout:
            return ApiResult(
                success=False, error_type="timeout",
                message="Connection timed out",
            )
        except ConnectionError as e:
            return ApiResult(
                success=False, error_type="connection_error",
                message=str(e),
            )
        except OSError as e:
            return ApiResult(
                success=False, error_type="os_error",
                message=str(e),
            )
        finally:
            conn.close()

    def read_router_config(self, username: str,
                           password: str) -> Optional[Dict]:
        """Read router security config using low-priv credentials.

        Attempts to read login policies and service configuration to
        understand lockout settings before running a full test.

        Args:
            username: Username with at least read access.
            password: Password for the account.

        Returns:
            Dictionary with relevant config, or None if access fails.
        """
        conn = ApiConnection()
        try:
            conn.connect(self._host, self._port, self._timeout)
            success, error = conn.login(username, password)
            if not success:
                logger.warning("Cannot read config: login failed (%s)", error)
                return None

            config = {}

            # Read login settings
            try:
                login_config = conn.execute_command("/ip/login/print")
                config["login"] = login_config
            except ApiError:
                pass

            # Read service settings (to see API port config)
            try:
                services = conn.execute_command("/ip/service/print")
                config["services"] = services
            except ApiError:
                pass

            # Read firewall filter rules related to login
            try:
                filters = conn.execute_command(
                    "/ip/firewall/filter/print",
                    {"?chain": "input"},
                )
                config["firewall_input"] = filters
            except ApiError:
                pass

            logger.info("Router config retrieved successfully")
            return config

        except (ConnectionError, socket.error, ApiError, OSError) as e:
            logger.warning("Failed to read router config: %s", e)
            return None
        finally:
            conn.close()

    @staticmethod
    def _classify_error(error_msg: str) -> str:
        """Classify an API error message into a category."""
        msg_lower = error_msg.lower()
        if "cannot log in" in msg_lower or "invalid" in msg_lower:
            return "auth_failed"
        if "too many" in msg_lower or "connection limit" in msg_lower:
            return "rate_limited"
        if "disabled" in msg_lower:
            return "account_disabled"
        return "unknown"
