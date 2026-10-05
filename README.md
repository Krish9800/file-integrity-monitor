# File Integrity Monitoring System (FIM)

[![CI](https://github.com/Krish9800/file-integrity-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/Krish9800/file-integrity-monitor/actions)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Type Checked: mypy](https://img.shields.io/badge/type_checker-mypy_strict-blue.svg)](https://mypy-lang.org/)
[![Code Style: Ruff](https://img.shields.io/badge/code_style-ruff-black.svg)](https://astral.sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Educational Defensive Security Project (Cybersecurity Portfolio — Project 03)**  
> An enterprise-grade, host-based File Integrity Monitoring (FIM) engine in modern Python 3.12+ featuring dual-algorithm streaming cryptographic hashing (SHA-256 + BLAKE2b), HMAC-authenticated baseline catalogs against tampering, POSIX metadata inspection, real-time filesystem event monitoring, and SIEM-ready security alert telemetry.

---

## 🔒 Security Posture & Architecture Guarantees

> [!IMPORTANT]
> **Core Cryptographic & Architectural Controls:**
> - **Dual Cryptographic Hashing:** Every file is hashed with both SHA-256 and BLAKE2b via memory-bounded streaming chunks ($64\text{ KB}$ buffers), eliminating collision vulnerabilities.
> - **Baseline Sealing via HMAC-SHA256:** Baseline catalogs are cryptographically sealed with a secret key to prevent baseline tampering/poisoning attacks.
> - **Full POSIX Metadata Inspection:** Detects file permission alterations (`chmod`), ownership transfers (`chown`), file size changes, and timestamp anomalies.
> - **Symlink & Traversal Defenses:** Safe path canonicalization and recursion limits defend against symlink loops and directory traversal attacks.
> - **Real-Time Event Auditing:** Continuous kernel event watching using OS filesystem hooks (`watchdog` / Linux inotify) with debouncing.
> - **Privilege Escalation Rules:** Immediate `CRITICAL` alerting on SUID (`0o4000`) or SGID (`0o2000`) bit modifications.
