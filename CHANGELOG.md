# Changelog

All notable changes to the **File Integrity Monitor (FIM)** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-05

### Added
- **Cryptographic Core**:
  - Constant $O(1)$ memory streaming dual-hashing using SHA-256 and BLAKE2b with configurable 64 KB chunk buffers.
  - HMAC-SHA256 baseline sealing and constant-time verification using `hmac.compare_digest`.
  - Secure key generator enforcing minimum 256-bit entropy and POSIX `0600` permissions.
- **Data Models**:
  - Pydantic v2 `FileRecord` tracking permissions, mode bitmask, UID, GID, mtime, inode, SUID/SGID flags, and cryptographic digests.
  - `BaselineCatalog` with deterministic sorted JSON serialization.
  - `FileDelta`, `AttributeDiff`, and `ScanReport` for differential state representation.
  - `SecurityAlert` with ArcSight Common Event Format (CEF) and JSON Lines export.
- **Scanner Subsystem**:
  - `SafePathWalker` featuring canonical path resolution, symlink escape protection, cyclic recursion bomb defenses, and configurable glob pattern exclusions.
  - `ScanEngine` for live state capture and baseline generation.
- **Differential Analysis & Threat Rules**:
  - `StateComparator` detecting added, deleted, modified, and metadata-altered files.
  - `PolicyEngine` classifying security events into CRITICAL, HIGH, MEDIUM, LOW, and INFO severities with actionable incident response recommendations.
  - Detection rules for SetUID/SetGID privilege escalation, critical system file tampering (`/etc/shadow`, `/etc/sudoers`, `/bin/*`), and world-writable permission exposure.
- **Real-Time Event Observer**:
  - `FIMEventHandler` and `RealtimeMonitor` wrapping Linux `watchdog` inotify kernel events.
  - Event debouncing and settle delay to ensure clean hash calculations after file flushes.
- **CLI & Telemetry**:
  - Rich and Typer-powered CLI (`fim init-key`, `fim baseline create`, `fim verify`, `fim watch`, `fim version`).
  - `TelemetryEmitter` supporting Rich console panels, tables, JSON Lines, and CEF syslog streaming.
- **DevSecOps & Deployment**:
  - Multi-stage non-root `Dockerfile` with dedicated `fimuser` (UID 10001).
  - Production `docker-compose.yml` with read-only volume mounts and dropped Linux capabilities.
  - GitHub Actions CI workflow executing Ruff, Mypy, Bandit, and Pytest with 90%+ coverage enforcement.
  - Architectural deep-dive (`docs/architecture.md`) and STRIDE threat model (`docs/threat_model.md`).
