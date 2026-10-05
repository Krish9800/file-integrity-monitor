# Security Policy

## Reporting Security Issues

The `file-integrity-monitor` project is an educational, defensive cybersecurity engineering implementation. We take system security and baseline integrity seriously.

If you identify a security vulnerability (such as a baseline bypass, symlink race condition, hash collision risk, or denial-of-service vector):

1. **Do not open a public issue.**
2. Report the vulnerability privately via GitHub Security Advisories or by emailing `security-reports@example.com`.
3. Provide a clear proof-of-concept (PoC) and expected remediation.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Defensive Threat Assumptions
- **Baseline Key Protection:** The HMAC baseline authentication key must be secured with restricted POSIX permissions (`0600` or `0400`) and stored outside the monitored directory tree.
- **Root Operations:** When monitoring system directories (`/etc`, `/usr/bin`), run FIM under dedicated monitoring service accounts or systemd service with `CAP_DAC_READ_SEARCH` capability.
