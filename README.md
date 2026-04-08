# MikroTik Credential Strength Tester

A modular Python tool for testing login credential strength on MikroTik routers you own. Supports both RouterOS API (port 8728) and SSH (port 22) protocols.

> **WARNING**: This tool is for **authorized security testing only**. Unauthorized access to computer systems is illegal. You must have explicit written permission to test the target system.

## Features

- **Multi-protocol**: Tests both RouterOS API (8728/tcp) and SSH (22/tcp)
- **Multi-threaded**: Controlled concurrency with configurable thread count (default: 3)
- **RouterOS API protocol**: Raw implementation supporting both legacy MD5 challenge-response and modern plaintext login
- **SSH**: Password, keyboard-interactive, and key-based auth via paramiko
- **Proxy rotation**: SOCKS5/HTTP proxy support for distributed testing
- **Dictionary generator**: Built-in MikroTik defaults with mutation engine (leet speak, year appending, case variations)
- **Checkpoint/resume**: Pause and resume testing sessions
- **Slow-down mode**: Random 2-5s delays to mimic human intervals
- **Detailed reporting**: Found credentials, timing, and statistics

## Installation

```bash
pip install -r requirements.txt

# For development/testing:
pip install -r requirements-dev.txt
```

## Usage

### Basic: Test with default MikroTik passwords

```bash
python -m mikrotik_tester \
  --target 192.168.88.1 \
  --use-defaults \
  --i-am-authorized
```

### Custom wordlist with mutations

```bash
python -m mikrotik_tester \
  --target 192.168.88.1 \
  --wordlist /path/to/passwords.txt \
  --mutate \
  --i-am-authorized
```

### SSH only with slow mode

```bash
python -m mikrotik_tester \
  --target 192.168.88.1 \
  --protocol ssh \
  --use-defaults \
  --slow \
  --i-am-authorized
```

### With proxy rotation

```bash
python -m mikrotik_tester \
  --target 192.168.88.1 \
  --use-defaults \
  --proxy-file proxies.txt \
  --threads 5 \
  --i-am-authorized
```

### Resume from checkpoint

```bash
python -m mikrotik_tester \
  --target 192.168.88.1 \
  --use-defaults \
  --resume \
  --i-am-authorized
```

### Read router config first (requires initial access)

```bash
python -m mikrotik_tester \
  --target 192.168.88.1 \
  --use-defaults \
  --read-config admin "" \
  --i-am-authorized
```

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target`, `-t` | Router IP/hostname | *required* |
| `--i-am-authorized` | Confirm authorization | *required* |
| `--protocol`, `-p` | `ssh`, `api`, or `both` | `both` |
| `--ssh-port` | SSH port | `22` |
| `--api-port` | API port | `8728` |
| `--users`, `-u` | Username(s) to test | `admin` |
| `--wordlist`, `-w` | Password wordlist file | — |
| `--use-defaults` | Include MikroTik default passwords | `false` |
| `--mutate`, `-m` | Apply password mutations | `false` |
| `--key-file` | SSH private key for fallback auth | — |
| `--threads` | Concurrent threads | `3` |
| `--slow` | Slow-down mode (2-5s delays) | `false` |
| `--timeout` | Connection timeout (seconds) | `10` |
| `--proxy-file` | Proxy list file | — |
| `--checkpoint` | Checkpoint file path | `checkpoint.json` |
| `--resume` | Resume from checkpoint | `false` |
| `--log-file` | Log file path | `mikrotik_test.log` |
| `--verbose`, `-v` | Debug logging | `false` |
| `--read-config` | Read router config (USER PASS) | — |

## Proxy File Format

```
socks5://host:port
socks5://user:pass@host:port
http://host:port
host:port          # defaults to SOCKS5
```

## Password Mutations

When `--mutate` is enabled, each base password generates variations:

- **Leet speak**: `admin` → `4dm1n`
- **Year appending**: `admin` → `admin2020` ... `admin2026`
- **Case variations**: `admin` → `ADMIN`, `Admin`, `aDMIN`
- **Common suffixes**: `admin!`, `admin123`, `admin@`, `admin#`

## Project Structure

```
mikrotik_tester/
├── __init__.py        # Package version
├── __main__.py        # Main orchestrator
├── cli.py             # CLI argument parsing
├── config.py          # Configuration dataclass
├── api_protocol.py    # RouterOS API wire protocol
├── api_tester.py      # API credential tester
├── ssh_tester.py      # SSH credential tester
├── proxy_manager.py   # Proxy rotation
├── wordlist.py        # Dictionary generator
├── checkpoint.py      # Pause/resume
├── reporter.py        # Report generation
└── logger.py          # Logging setup
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## License

For authorized security testing and educational use only.
