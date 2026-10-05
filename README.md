# File Integrity Monitoring (FIM) Engine

[![CI](https://github.com/Krish9800/file-integrity-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/Krish9800/file-integrity-monitor/actions)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Type Checked: mypy](https://img.shields.io/badge/type_checker-mypy_strict-blue.svg)](https://mypy-lang.org/)
[![Code Style: Ruff](https://img.shields.io/badge/code_style-ruff-black.svg)](https://astral.sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Educational Defensive Security Project (Cybersecurity Portfolio — Project 03)**  
> A production-grade, host-based File Integrity Monitoring (FIM) and anti-tampering engine built in Python 3.12+. Features dual-algorithm streaming cryptographic hashing (SHA-256 + BLAKE2b), HMAC-authenticated baseline catalogs against poisoning attacks, complete POSIX metadata inspection, real-time filesystem event monitoring via kernel inotify, and SIEM-ready security alert telemetry (JSON Lines and ArcSight CEF).

---

## 🔒 Security Posture & Architecture Guarantees

> [!IMPORTANT]
> **Core Cryptographic & Defensive Controls:**
> - **Dual Cryptographic Hashing:** Every file is digested concurrently with both SHA-256 and BLAKE2b via $O(1)$ memory-bounded streaming chunks ($64\text{ KB}$ buffers), eliminating collision vulnerabilities.
> - **Baseline Sealing via HMAC-SHA256:** Baseline catalogs are cryptographically signed with a 256-bit secret key. If an adversary attempts to modify the baseline database, verification fails in constant time with exit code 2.
> - **Full POSIX Metadata Inspection:** Tracks permission bitmasks (`chmod`), ownership transfers (`chown`), file sizes, modification timestamps (`mtime`), and inodes.
> - **Symlink & Traversal Hardening:** Canonical path resolution and refusal to follow symbolic links (`follow_symlinks=False`) prevent directory escape attacks and cyclic recursion bombs.
> - **Real-Time Kernel Auditing:** Continuous filesystem event watching using OS kernel notifications (`watchdog` / Linux inotify) with intelligent debouncing.
> - **Threat Policy Rules:** Instant `CRITICAL` alert dispatch on SetUID (`0o4000`) or SetGID (`0o2000`) elevation, critical system file tampering (`/etc/shadow`, `/etc/sudoers`, `/bin/*`), and world-writable permission exposure (`0o002`).

---

## 📋 Compliance & Regulatory Mapping

This engine directly satisfies technical requirements across industry compliance frameworks:

| Standard / Framework | Requirement | How FIM Satisfies It |
| :--- | :--- | :--- |
| **PCI DSS v4.0** | **Requirement 11.5.2** | Deploys a file integrity monitoring mechanism to alert personnel to unauthorized modification of critical system files, configuration files, or content files. |
| **NIST SP 800-53 Rev. 5** | **SI-7: Software, Firmware, and Information Integrity** | Employs integrity verification tools to detect unauthorized changes to software, firmware, and information across protected host boundaries. |
| **ISO/IEC 27001:2022** | **Control A.12.4.1 (Event Logging)** | Monitors and logs unauthorized administrative actions and file modifications for forensic auditability. |
| **SOC 2 Type II** | **Common Criteria CC6.8** | Prevents or detects unauthorized execution of malicious software, alterations to binaries, and access privilege deviations. |

---

## 🚀 Quick Start

### 1. Installation

Requires **Python 3.12+**.

```bash
# Clone the repository
git clone https://github.com/Krish9800/file-integrity-monitor.git
cd file-integrity-monitor

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development dependencies
pip install -e .[dev]
```

### 2. Generate a 256-Bit HMAC Authentication Key

Create a cryptographically secure key to sign and verify baseline catalogs:

```bash
fim init-key --output fim.key
```
*Note: Key permissions are automatically restricted to POSIX `0600` (owner read/write only).*

### 3. Create a Sealed Cryptographic Baseline

Scan target directories (e.g. `/etc`, `/bin`, `/var/www`), compute streaming hashes, and seal with HMAC-SHA256:

```bash
fim baseline create /etc /bin \
    --output baseline.json \
    --key fim.key \
    --exclude "*.tmp" \
    --exclude "*.log"
```

### 4. Verify Filesystem State Against Baseline

Audit live files against the sealed catalog:

```bash
# Human-readable Rich console report and alerts table
fim verify --baseline baseline.json --key fim.key

# Stream JSON Lines for data pipelines
fim verify --baseline baseline.json --key fim.key --format json

# Stream ArcSight Common Event Format (CEF) for SIEM
fim verify --baseline baseline.json --key fim.key --format cef
```

### 5. Launch Real-Time Kernel Event Monitoring Daemon

Watch directories continuously for unauthorized changes and stream security alerts in real time:

```bash
fim watch /etc /bin \
    --baseline baseline.json \
    --key fim.key \
    --format console \
    --log-file /var/log/fim/alerts.jsonl
```

---

## 🛠️ CLI Reference

```
Usage: fim [OPTIONS] COMMAND [ARGS]...

Production-Grade File Integrity Monitoring (FIM) & Anti-Tampering Engine.

Commands:
  init-key   Generate a cryptographically secure 256-bit HMAC key with POSIX 0600 permissions.
  baseline   Manage cryptographic filesystem baseline catalogs (create).
  verify     Verify live filesystem state against cryptographic baseline catalog.
  watch      Continuously monitor filesystem in real-time and stream security alerts.
  version    Print FIM version and cryptographic capabilities.
```

### Exit Codes for CI/CD & Automation
- `0`: Success / Intact. No unauthorized modifications detected.
- `1`: Security Alert / Modifications detected. Changes found between baseline and live state.
- `2`: Integrity Failure. Baseline HMAC signature mismatch or corrupted baseline catalog.

---

## 📡 SIEM & SOC Integration

### ArcSight Common Event Format (CEF)
Alerts can be emitted directly as standard CEF strings for syslog / SIEM ingestion:

```
CEF:0|CyberSecurityPortfolio|FileIntegrityMonitor|0.1.0|SUID_PRIVILEGE_ESCALATION|Privilege escalation indicator: SUID/SGID bit active on /usr/bin/tool|10|filePath=/usr/bin/tool act=MODIFIED msg=Privilege escalation indicator: SUID/SGID bit active on /usr/bin/tool externalId=18a8b1d9-5f21-4fce-bdfa-b1cfcbdf33a6 rt=2026-10-05T15:30:00.000000+00:00
```

### Structured JSON Lines
```json
{
  "id": "18a8b1d9-5f21-4fce-bdfa-b1cfcbdf33a6",
  "timestamp": "2026-10-05T15:30:00.000000+00:00",
  "severity": "CRITICAL",
  "category": "CRITICAL_FILE_TAMPERED",
  "target_path": "/etc/shadow",
  "change_type": "MODIFIED",
  "description": "Cryptographic hash mismatch on critical system file: /etc/shadow",
  "recommendation": "Immediate incident response required. Inspect binary diffs or configuration backdoors.",
  "details": {
    "hash_sha256": ["old_hash...", "new_hash..."]
  }
}
```

---

## 🐳 Docker Deployment

Run as an isolated, unprivileged container with read-only host mounts:

```bash
# Build the non-root container
docker build -t fim:latest .

# Run daemon with docker-compose
docker compose up -d
```

---

## 🧪 Testing & DevSecOps Quality Gates

The test suite enforces a **90%+ statement coverage gate** across unit, integration, and security edge case suites:

```bash
# Run full test suite with coverage report
pytest --cov=src --cov-report=term-missing --cov-fail-under=90

# Run Ruff linter and formatter checks
ruff check .
ruff format --check .

# Run Mypy strict type checking
mypy src/

# Run Bandit AST security scan
bandit -r src/
```

---

## 📚 Documentation
- [System Architecture & Cryptographic Design](docs/architecture.md)
- [STRIDE Threat Model & Mitigations](docs/threat_model.md)
- [Release Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
