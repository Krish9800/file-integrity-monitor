# STRIDE Threat Model: Host-Based File Integrity Monitoring

## 1. Scope & Objective
This document outlines the STRIDE threat analysis for the **File Integrity Monitoring (FIM)** system, analyzing threats against host file state observability, baseline authenticity, and alert dispatch integrity.

---

## 2. Threat Analysis (STRIDE)

### S - Spoofing
| Threat ID | Threat Description | Attack Vector | Mitigation in FIM |
| :--- | :--- | :--- | :--- |
| **TH-01** | Spoofed Baseline Database | Adversary modifies `baseline.json` directly to include backdoored file hashes as "expected". | **Cryptographic HMAC Sealing**: Baselines are signed with HMAC-SHA256 using a separate secret key (`fim.key`). A modified baseline fails constant-time verification with exit code 2. |
| **TH-02** | Telemetry Alert Spoofing | An attacker generates fake CEF or JSON alert payloads to overwhelm the SOC. | Alerts contain cryptographic UUIDs, RFC-3339 UTC timestamps, and can be securely streamed via TLS to SIEM ingestion endpoints. |

---

### T - Tampering
| Threat ID | Threat Description | Attack Vector | Mitigation in FIM |
| :--- | :--- | :--- | :--- |
| **TH-03** | Monitored File Content Tampering | Adversary replaces a legitimate binary with a trojanized version. | **Dual Hashing**: Dual SHA-256 and BLAKE2b streaming calculation detects single-bit divergence. |
| **TH-04** | Timestamp Tampering (Timestomping) | Attacker alters `mtime` back to original value after modifying file content. | FIM compares cryptographic content hashes (`hashes`), not merely `mtime`. Even with identical `mtime`, hash divergence triggers `CONTENT_TAMPERED` alerts. |
| **TH-05** | Metadata / Permission Tampering | Attacker adds SetUID/SetGID bit to a local helper utility for privilege escalation. | FIM inspects raw POSIX mode bitmask (`is_suid`, `is_sgid`, world-writable bits) and raises **CRITICAL** `SUID_PRIVILEGE_ESCALATION` alert. |

---

### R - Repudiation
| Threat ID | Threat Description | Attack Vector | Mitigation in FIM |
| :--- | :--- | :--- | :--- |
| **TH-06** | Change Repudiation | An insider modifies a sensitive configuration and claims it was already present in the baseline. | Baseline records preserve exact cryptographic hashes, creation timestamps, and permissions signed by the HMAC key. Full differential reports document before/after states. |

---

### I - Information Disclosure
| Threat ID | Threat Description | Attack Vector | Mitigation in FIM |
| :--- | :--- | :--- | :--- |
| **TH-07** | HMAC Secret Key Exposure | Unprivileged local users read `fim.key` and forge baseline signatures. | The key file is created with POSIX `0o600` permissions (`chmod 0600`). Key validation enforces a minimum 256-bit entropy threshold. |
| **TH-08** | Sensitive Content Leakage in Alerts | File contents or sensitive credentials leak into log files. | Alerts only record metadata diffs (permissions, mode, hashes, size). File contents are **never** logged or emitted into telemetry streams. |

---

### D - Denial of Service
| Threat ID | Threat Description | Attack Vector | Mitigation in FIM |
| :--- | :--- | :--- | :--- |
| **TH-09** | Symlink Directory Escape & Loops | Malicious cyclic symlinks or symlinks to `/dev/zero` / `/proc/kcore` exhaust memory/disk. | `SafePathWalker` does **not** follow symbolic links (`follow_symlinks=False`), tracks visited directory inodes, enforces a `max_depth=30` limit, and reads regular files only. |
| **TH-10** | Memory Exhaustion via Large Files | Storing multi-gigabyte files in RAM causes OOM crash of the monitoring daemon. | Streaming chunked read buffer ($64\text{ KB}$) ensures $O(1)$ constant memory overhead regardless of file size. |

---

### E - Elevation of Privilege
| Threat ID | Threat Description | Attack Vector | Mitigation in FIM |
| :--- | :--- | :--- | :--- |
| **TH-11** | FIM Process Compromise | Exploitation of the FIM daemon to gain root execution. | Designed to run as an unprivileged non-root user (`fimuser`, UID 10001). In containerized environments, host mounts are read-only (`:ro`) and capabilities are dropped (`CAP_DROP ALL`). |

---

## 3. Residual Risks & Operational Guidance
1. **Kernel-Level Rootkits**: If a rootkit hooks Linux VFS (`sys_read`, `sys_stat`), it can return forged contents to userland scanners. Defense-in-depth requires pairing FIM with secure boot, kernel module signing (`CONFIG_MODULE_SIG_FORCE`), and eBPF runtime security (Tetragon/Falco).
2. **Key Storage**: On production systems, the HMAC key should be protected using a Hardware Security Module (HSM), TPM 2.0, or cloud KMS (AWS KMS / GCP Cloud KMS / HashiCorp Vault).
