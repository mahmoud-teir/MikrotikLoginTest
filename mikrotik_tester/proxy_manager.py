"""SOCKS5/HTTP proxy rotation manager for distributed credential testing."""

import logging
import socket
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import socks

logger = logging.getLogger("mikrotik_tester")

# Map URL schemes to PySocks proxy types
PROXY_TYPE_MAP = {
    "socks5": socks.SOCKS5,
    "socks4": socks.SOCKS4,
    "http": socks.HTTP,
    "https": socks.HTTP,
}


@dataclass
class ProxyInfo:
    """Parsed proxy configuration."""
    proxy_type: int  # socks.SOCKS5, socks.SOCKS4, or socks.HTTP
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    failures: int = 0
    active: bool = True

    @property
    def display(self) -> str:
        return f"{self.host}:{self.port}"


class ProxyManager:
    """Thread-safe round-robin proxy rotation with health tracking."""

    def __init__(self, proxy_file: str, max_failures: int = 5):
        self._proxies: List[ProxyInfo] = []
        self._index = 0
        self._lock = threading.Lock()
        self._max_failures = max_failures
        self._load_proxies(proxy_file)

    def _load_proxies(self, proxy_file: str):
        """Load proxies from a file.

        Supported formats:
            socks5://host:port
            socks5://user:pass@host:port
            http://host:port
            http://user:pass@host:port
            host:port  (assumes SOCKS5)
        """
        with open(proxy_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                proxy = self._parse_proxy(line)
                if proxy:
                    self._proxies.append(proxy)

        if not self._proxies:
            raise ValueError(f"No valid proxies found in {proxy_file}")

        logger.info("Loaded %d proxies from %s", len(self._proxies),
                     proxy_file)

    @staticmethod
    def _parse_proxy(line: str) -> Optional[ProxyInfo]:
        """Parse a single proxy line into ProxyInfo."""
        try:
            # Handle bare host:port (no scheme)
            if "://" not in line:
                line = "socks5://" + line

            parsed = urlparse(line)
            scheme = parsed.scheme.lower()
            proxy_type = PROXY_TYPE_MAP.get(scheme)
            if proxy_type is None:
                logger.warning("Unknown proxy scheme: %s", scheme)
                return None

            host = parsed.hostname
            port = parsed.port
            if not host or not port:
                logger.warning("Invalid proxy address: %s", line)
                return None

            return ProxyInfo(
                proxy_type=proxy_type,
                host=host,
                port=port,
                username=parsed.username,
                password=parsed.password,
            )
        except Exception as e:
            logger.warning("Failed to parse proxy '%s': %s", line, e)
            return None

    def get_next_proxy(self) -> Optional[ProxyInfo]:
        """Get the next active proxy in round-robin order.

        Returns:
            ProxyInfo or None if no active proxies remain.
        """
        with self._lock:
            active = [p for p in self._proxies if p.active]
            if not active:
                return None
            proxy = active[self._index % len(active)]
            self._index += 1
            return proxy

    def mark_failure(self, proxy: ProxyInfo):
        """Record a failure for a proxy; deactivate if over threshold."""
        with self._lock:
            proxy.failures += 1
            if proxy.failures >= self._max_failures:
                proxy.active = False
                logger.warning(
                    "Proxy %s deactivated after %d failures",
                    proxy.display, proxy.failures,
                )

    def mark_success(self, proxy: ProxyInfo):
        """Reset failure count on success."""
        with self._lock:
            proxy.failures = 0

    @property
    def active_count(self) -> int:
        with self._lock:
            return sum(1 for p in self._proxies if p.active)

    @property
    def total_count(self) -> int:
        return len(self._proxies)

    def create_socket(self, proxy: ProxyInfo,
                      dest_host: str, dest_port: int,
                      timeout: int = 10) -> socket.socket:
        """Create a socket connected through the given proxy.

        Args:
            proxy: Proxy configuration to route through.
            dest_host: Destination host to connect to.
            dest_port: Destination port.
            timeout: Socket timeout.

        Returns:
            Connected socket object.
        """
        s = socks.socksocket()
        s.set_proxy(
            proxy_type=proxy.proxy_type,
            addr=proxy.host,
            port=proxy.port,
            username=proxy.username,
            password=proxy.password,
        )
        s.settimeout(timeout)
        s.connect((dest_host, dest_port))
        return s
