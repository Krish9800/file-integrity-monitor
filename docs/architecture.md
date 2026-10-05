# File Integrity Monitoring (FIM) Engine Architecture

## 1. Executive Overview

The **File Integrity Monitoring (FIM) Engine** is an enterprise-grade, defensive host-based security system designed to detect unauthorized modifications, additions, and deletions across sensitive filesystems. It serves as a foundational component in host intrusion detection (HIDS), compliance automation (PCI DSS §11.5, NIST SP 800-53 SI-7, ISO 27001 A.12.4.1, SOC 2 CC6.8), and incident response.

### Core Design Principles
1. **Cryptographic Authenticity**: Baselines are cryptographically signed with HMAC-SHA256; baselines cannot be tampered with by adversaries without invalidating the constant-time signature.
2. **Dual-Digest Collision Resistance**: Every monitored file is hashed concurrently with SHA-256 and BLAKE2b in a single streaming I/O pass, eliminating collision exploit risks.
3. **Bounded $O(1)$ Memory**: Files are streamed in 64 KB buffers, ensuring predictable memory footprints even when monitoring large binaries or multi-gigabyte files.
4. **Symlink Attack Hardening**: Canonical path resolution and non-traversal of symbolic links prevent directory escape attacks and cyclic recursion bombs.
5. **SIEM Interoperability**: Telemetry can be emitted as human-readable Rich console dashboards, structured JSON Lines for modern data lakes, and ArcSight Common Event Format (CEF) for legacy SIEM pipelines.

---

## 2. Component Architecture

```mermaid
flowchart TD
    subgraph Filesystem Space
        TargetFiles[Monitored Files & Directories]
        KernelEvents[Linux Inotify / FileSystem Events]
    end

    subgraph Scanner Subsystem
        Walker[SafePathWalker<br/>- Canonicalization<br/>- Symlink Exclusion<br/>- Depth Control]
        Hasher[Streaming Hasher<br/>- SHA-256<br/>- BLAKE2b<br/>- O(1) Memory]
        Engine[ScanEngine]
    end

    subgraph Cryptographic Core
        HMAC[Integrity Core<br/>- HMAC-SHA256 Signing<br/>- Constant-Time Verify<br/>- POSIX 0600 Storage]
        Baseline[BaselineCatalog<br/>- Canonical Deterministic JSON<br/>- Tamper Seal]
    end

    subgraph Differential Analysis & Threat Engine
        Comparator[StateComparator<br/>- ADDED / DELETED<br/>- MODIFIED (Hash Changed)<br/>- ATTRIBUTES_CHANGED]
        Policy[PolicyEngine<br/>- SUID/SGID Privilege Escalation<br/>- Critical Target Rules<br/>- World-Writable Exposure<br/>- Severity Scoring]
    end

    subgraph Telemetry & Real-Time Monitoring
        Watchdog[FIMEventHandler & RealtimeMonitor]
        Emitter[TelemetryEmitter<br/>- Rich Console Panels<br/>- JSON Lines<br/>- ArcSight CEF Syslog]
    end

    TargetFiles --> Walker
    Walker --> Hasher
    Hasher --> Engine
    Engine --> Baseline
    HMAC <--> Baseline

    Baseline --> Comparator
    Engine --> Comparator
    Comparator --> Policy
    Policy --> Emitter

    KernelEvents --> Watchdog
    Watchdog --> Policy
    Watchdog --> Emitter
```

---

## 3. Cryptographic Implementation Details

### Dual-Digest Streaming Hashing
Rather than reading entire files into RAM:
$$\text{Memory Complexity} = O(1)$$
```python
buffer_size = 65536  # 64 KB
sha256 = hashlib.sha256()
blake2b = hashlib.blake2b()

with file_path.open("rb") as f:
    while chunk := f.read(buffer_size):
        sha256.update(chunk)
        blake2b.update(chunk)
```
- **SHA-256**: Widely recognized NIST standard, compatible with all SIEM and compliance frameworks.
- **BLAKE2b**: High-speed, cryptographically secure hash providing resistance against length extension attacks.

### Deterministic HMAC Baseline Sealing
To prevent an adversary with local write access from editing the baseline file:
1. All baseline file records are serialized canonically:
   $$JSON_{\text{canonical}} = \text{json.dumps}(data, \text{sort\_keys}=\text{True}, \text{separators}=(',', ':'))$$
2. A 256-bit secret key is stored with strict POSIX `0600` permissions.
3. The canonical payload is signed via HMAC-SHA256:
   $$\text{Signature} = \text{HMAC-SHA256}(K, JSON_{\text{canonical}})$$
4. Verification is executed using Python's `hmac.compare_digest()` to eliminate timing side-channel attacks.

---

## 4. Threat Classification Matrix

| Category | Trigger Condition | Severity | Defensive Recommendation |
| :--- | :--- | :--- | :--- |
| `SUID_PRIVILEGE_ESCALATION` | SetUID (`0o4000`) or SetGID (`0o2000`) bit added | **CRITICAL** | Revoke bit immediately (`chmod u-s`); inspect binary for backdoor injection. |
| `CRITICAL_FILE_TAMPERED` | Cryptographic hash divergence on `/etc/shadow`, `/etc/sudoers`, `/bin/*` | **CRITICAL** | Initiate immediate incident response; isolate host from network. |
| `CRITICAL_FILE_DELETED` | Core configuration or security binary removed | **CRITICAL** | Restore from immutable backup; review auditd records for user session. |
| `CRITICAL_FILE_INJECTION` | New unexpected executable created in critical system path | **CRITICAL** | Quarantine binary; check software package manager verification (`dpkg -V` / `rpm -V`). |
| `PERMISSIVE_ACCESS_EXPOSURE`| File modified to world-writable mode (`0o002` set) | **HIGH** | Restrict permissions (`chmod o-w`) to prevent unprivileged tampering. |
| `CONTENT_TAMPERED` | SHA-256 / BLAKE2b hash mismatch on standard monitored file | **HIGH** | Verify against change ticket; inspect git or backup diff. |
| `OWNERSHIP_CHANGED` | File owner (`uid`) or group (`gid`) changed | **MEDIUM** | Confirm whether maintenance activity was scheduled. |
| `PERMISSIONS_ALTERED` | POSIX permissions mode changed without world-writable bit | **MEDIUM** | Audit access controls against least-privilege policy. |
| `FILE_DELETED` | Non-critical monitored file removed | **MEDIUM** | Verify intentionality. |
| `FILE_ADDED` | New file discovered in monitored scope | **MEDIUM** | Incorporate into baseline if legitimate. |
| `METADATA_TOUCHED` | Modification timestamp (`mtime`) changed without content hash diff | **LOW** | Check for timestomping or benign file touch commands. |

---

## 5. Security & Isolation Controls
- **Non-Root Execution**: Runs by default under unprivileged service account `fimuser` (UID 10001).
- **Read-Only Mounting**: When deployed in Docker/containers, host filesystems are mounted strictly with the `:ro` flag.
- **Drop All Capabilities**: Dropped `CAP_ALL` and `no-new-privileges:true` prevent container escapes.
