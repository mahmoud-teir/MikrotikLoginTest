"""Tests for the proxy rotation manager."""

import os
import tempfile
import threading

import pytest
import socks

from mikrotik_tester.proxy_manager import ProxyInfo, ProxyManager


def _create_proxy_file(lines):
    """Helper to create a temporary proxy file."""
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


class TestProxyParsing:
    """Test proxy file parsing."""

    def test_socks5_basic(self):
        path = _create_proxy_file(["socks5://127.0.0.1:1080"])
        try:
            mgr = ProxyManager(path)
            proxy = mgr.get_next_proxy()
            assert proxy is not None
            assert proxy.proxy_type == socks.SOCKS5
            assert proxy.host == "127.0.0.1"
            assert proxy.port == 1080
            assert proxy.username is None
        finally:
            os.unlink(path)

    def test_socks5_with_auth(self):
        path = _create_proxy_file(["socks5://user:pass@10.0.0.1:1080"])
        try:
            mgr = ProxyManager(path)
            proxy = mgr.get_next_proxy()
            assert proxy.username == "user"
            assert proxy.password == "pass"
        finally:
            os.unlink(path)

    def test_http_proxy(self):
        path = _create_proxy_file(["http://proxy.example.com:8080"])
        try:
            mgr = ProxyManager(path)
            proxy = mgr.get_next_proxy()
            assert proxy.proxy_type == socks.HTTP
            assert proxy.host == "proxy.example.com"
            assert proxy.port == 8080
        finally:
            os.unlink(path)

    def test_bare_host_port(self):
        path = _create_proxy_file(["192.168.1.1:9050"])
        try:
            mgr = ProxyManager(path)
            proxy = mgr.get_next_proxy()
            assert proxy.proxy_type == socks.SOCKS5  # default
            assert proxy.host == "192.168.1.1"
            assert proxy.port == 9050
        finally:
            os.unlink(path)

    def test_comments_and_blanks_skipped(self):
        path = _create_proxy_file([
            "# This is a comment",
            "",
            "socks5://10.0.0.1:1080",
            "  ",
            "# Another comment",
            "socks5://10.0.0.2:1080",
        ])
        try:
            mgr = ProxyManager(path)
            assert mgr.total_count == 2
        finally:
            os.unlink(path)

    def test_empty_file_raises(self):
        path = _create_proxy_file(["# only comments", ""])
        try:
            with pytest.raises(ValueError, match="No valid proxies"):
                ProxyManager(path)
        finally:
            os.unlink(path)

    def test_invalid_format_skipped(self):
        path = _create_proxy_file([
            "socks5://10.0.0.1:1080",
            "not_a_valid_proxy",
            "ftp://bad:scheme",
        ])
        try:
            mgr = ProxyManager(path)
            # Only the valid socks5 one should load
            assert mgr.total_count >= 1
        finally:
            os.unlink(path)


class TestProxyRotation:
    """Test round-robin proxy rotation."""

    def test_round_robin_order(self):
        path = _create_proxy_file([
            "socks5://10.0.0.1:1080",
            "socks5://10.0.0.2:1080",
            "socks5://10.0.0.3:1080",
        ])
        try:
            mgr = ProxyManager(path)
            p1 = mgr.get_next_proxy()
            p2 = mgr.get_next_proxy()
            p3 = mgr.get_next_proxy()
            p4 = mgr.get_next_proxy()  # Should wrap around

            hosts = [p1.host, p2.host, p3.host]
            assert len(set(hosts)) == 3  # All different
            assert p4.host == p1.host  # Wrapped around
        finally:
            os.unlink(path)

    def test_failure_deactivation(self):
        path = _create_proxy_file([
            "socks5://10.0.0.1:1080",
            "socks5://10.0.0.2:1080",
        ])
        try:
            mgr = ProxyManager(path, max_failures=3)
            proxy = mgr.get_next_proxy()

            for _ in range(3):
                mgr.mark_failure(proxy)

            assert not proxy.active
            assert mgr.active_count == 1
        finally:
            os.unlink(path)

    def test_success_resets_failures(self):
        path = _create_proxy_file(["socks5://10.0.0.1:1080"])
        try:
            mgr = ProxyManager(path, max_failures=3)
            proxy = mgr.get_next_proxy()

            mgr.mark_failure(proxy)
            mgr.mark_failure(proxy)
            assert proxy.failures == 2

            mgr.mark_success(proxy)
            assert proxy.failures == 0
        finally:
            os.unlink(path)

    def test_all_deactivated_returns_none(self):
        path = _create_proxy_file(["socks5://10.0.0.1:1080"])
        try:
            mgr = ProxyManager(path, max_failures=1)
            proxy = mgr.get_next_proxy()
            mgr.mark_failure(proxy)

            result = mgr.get_next_proxy()
            assert result is None
        finally:
            os.unlink(path)


class TestProxyThreadSafety:
    """Test concurrent proxy access."""

    def test_concurrent_get_next(self):
        path = _create_proxy_file([
            "socks5://10.0.0.1:1080",
            "socks5://10.0.0.2:1080",
            "socks5://10.0.0.3:1080",
        ])
        try:
            mgr = ProxyManager(path)
            results = []
            errors = []

            def worker():
                try:
                    for _ in range(100):
                        proxy = mgr.get_next_proxy()
                        if proxy:
                            results.append(proxy.host)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=worker) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0
            assert len(results) == 500
        finally:
            os.unlink(path)
