"""Command-line interface for MikroTik credential tester."""

import argparse

from .config import TestConfig

BANNER = r"""
 __  __ _ _              _   _ _      _____         _
|  \/  (_) | ___ __ ___ | |_(_) | __ |_   _|__  ___| |_
| |\/| | | |/ / '__/ _ \| __| | |/ /   | |/ _ \/ __| __|
| |  | | |   <| | | (_) | |_| |   <    | |  __/\__ \ |_
|_|  |_|_|_|\_\_|  \___/ \__|_|_|\_\   |_|\___||___/\__|

    MikroTik Credential Strength Tester
    FOR AUTHORIZED SECURITY TESTING ONLY
"""

DISCLAIMER = """
WARNING: This tool is designed for authorized security testing only.
Unauthorized access to computer systems is illegal. You must have
explicit written permission to test the target system.

By using --i-am-authorized you confirm that:
  - You own or have written authorization to test the target device
  - You understand the legal implications of credential testing
  - You accept full responsibility for your actions
"""


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="mikrotik-tester",
        description="MikroTik router credential strength tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=DISCLAIMER,
    )

    # Required
    parser.add_argument(
        "--target", "-t", required=True,
        help="Target router IP address or hostname",
    )
    parser.add_argument(
        "--i-am-authorized", action="store_true", required=True,
        help="Confirm you are authorized to test this target",
    )

    # Protocol selection
    parser.add_argument(
        "--protocol", "-p", choices=["ssh", "api", "both"], default="both",
        help="Protocol to test (default: both)",
    )
    parser.add_argument("--ssh-port", type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument("--api-port", type=int, default=8728,
                        help="API port (default: 8728)")

    # Credentials
    parser.add_argument(
        "--users", "-u", nargs="+", default=["admin"],
        help="Username(s) to test (default: admin)",
    )
    parser.add_argument(
        "--wordlist", "-w",
        help="Path to password wordlist file",
    )
    parser.add_argument(
        "--use-defaults", action="store_true",
        help="Include known MikroTik default passwords",
    )
    parser.add_argument(
        "--mutate", "-m", action="store_true",
        help="Apply password mutations (leet speak, years, case variations)",
    )
    parser.add_argument(
        "--key-file",
        help="SSH private key file for key-based auth fallback",
    )

    # Performance
    parser.add_argument(
        "--threads", type=int, default=1,
        help="Number of concurrent threads (default: 1, safe for MikroTik "
             "bruteforce prevention)",
    )
    parser.add_argument(
        "--min-delay", type=float, default=1.0,
        help="Minimum delay between attempts in seconds (default: 1.0). "
             "Auto-increases when router blocking is detected",
    )
    parser.add_argument(
        "--slow", action="store_true",
        help="Slow-down mode: use 3-7s delays (safer against aggressive "
             "bruteforce prevention rules)",
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Connection timeout in seconds (default: 10)",
    )

    # Proxy
    parser.add_argument(
        "--proxy-file",
        help="File with proxy list (one per line: socks5://host:port)",
    )

    # Checkpoint
    parser.add_argument(
        "--checkpoint", default="checkpoint.json",
        help="Checkpoint file path (default: checkpoint.json)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume from last checkpoint",
    )

    # Logging
    parser.add_argument(
        "--log-file", default="mikrotik_test.log",
        help="Log file path (default: mikrotik_test.log)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose/debug logging",
    )

    # Router config read
    parser.add_argument(
        "--read-config", nargs=2, metavar=("USER", "PASS"),
        help="Read router config first using these credentials",
    )

    return parser


def parse_args(argv=None) -> TestConfig:
    """Parse CLI arguments and return a TestConfig."""
    parser = build_parser()
    args = parser.parse_args(argv)

    config = TestConfig(
        target=args.target,
        protocol=args.protocol,
        ssh_port=args.ssh_port,
        api_port=args.api_port,
        threads=args.threads,
        min_delay=args.min_delay,
        slow_mode=args.slow,
        proxy_file=args.proxy_file,
        wordlist=args.wordlist,
        use_defaults=args.use_defaults,
        mutate=args.mutate,
        usernames=args.users,
        checkpoint_file=args.checkpoint,
        resume=args.resume,
        key_file=args.key_file,
        log_file=args.log_file,
        timeout=args.timeout,
    )

    config.validate()
    return config
