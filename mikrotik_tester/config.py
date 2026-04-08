"""Configuration dataclass and validation for MikroTik credential tester."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TestConfig:
    """Configuration for a credential testing session."""

    target: str
    protocol: str = "both"  # "ssh", "api", "webfig", "both", or "all"
    ssh_port: int = 22
    api_port: int = 8728
    webfig_port: int = 80
    threads: int = 1
    slow_mode: bool = False
    min_delay: float = 1.0  # Minimum delay between attempts (seconds)
    proxy_file: Optional[str] = None
    wordlist: Optional[str] = None
    use_defaults: bool = False
    mutate: bool = False
    usernames: List[str] = field(default_factory=lambda: ["admin"])
    checkpoint_file: str = "checkpoint.json"
    resume: bool = False
    key_file: Optional[str] = None
    log_file: str = "mikrotik_test.log"
    timeout: int = 10

    def validate(self):
        """Validate configuration values."""
        if not self.target:
            raise ValueError("Target host is required")
        if self.protocol not in ("ssh", "api", "webfig", "both", "all"):
            raise ValueError(f"Invalid protocol: {self.protocol}")
        if self.threads < 1 or self.threads > 50:
            raise ValueError("Threads must be between 1 and 50")
        if self.ssh_port < 1 or self.ssh_port > 65535:
            raise ValueError("SSH port must be between 1 and 65535")
        if self.api_port < 1 or self.api_port > 65535:
            raise ValueError("API port must be between 1 and 65535")
        if self.webfig_port < 1 or self.webfig_port > 65535:
            raise ValueError("WebFig port must be between 1 and 65535")
        if self.timeout < 1:
            raise ValueError("Timeout must be at least 1 second")
        if self.min_delay < 0:
            raise ValueError("Minimum delay cannot be negative")
        if not self.wordlist and not self.use_defaults:
            raise ValueError(
                "Either --wordlist or --use-defaults must be specified"
            )
