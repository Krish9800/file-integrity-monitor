"""Threat policy and rule evaluation engine for security alert generation."""

import fnmatch
from pathlib import Path

from fim.models.alert import SecurityAlert, Severity
from fim.models.delta import ChangeType, FileDelta, ScanReport

DEFAULT_CRITICAL_PATTERNS = [
    "*/etc/passwd*",
    "*/etc/shadow*",
    "*/etc/sudoers*",
    "*/etc/pam.d/*",
    "*/etc/ssh/*",
    "*/etc/security/*",
    "*/bin/*",
    "*/sbin/*",
    "*/usr/bin/*",
    "*/usr/sbin/*",
    "*/lib/*.so*",
    "*/lib64/*.so*",
    "*/usr/lib/*.so*",
    "*authorized_keys*",
    "*id_rsa*",
    "*id_ed25519*",
]


class PolicyEngine:
    """Classifies filesystem deltas against defensive security rules."""

    def __init__(self, critical_patterns: list[str] | None = None) -> None:
        """Initialize engine with customizable critical path patterns.

        Args:
            critical_patterns: Glob patterns identifying high-value security targets.
        """
        self.critical_patterns = (
            critical_patterns if critical_patterns is not None else list(DEFAULT_CRITICAL_PATTERNS)
        )

    def is_critical_path(self, target_path: str) -> bool:
        """Check whether a target path matches any critical target glob pattern.

        Args:
            target_path: File system path to evaluate.

        Returns:
            True if path matches a critical pattern.
        """
        norm_path = Path(target_path).as_posix()
        for pattern in self.critical_patterns:
            if fnmatch.fnmatch(norm_path, pattern):
                return True
        return False

    def evaluate_delta(self, delta: FileDelta) -> SecurityAlert:
        """Evaluate a single FileDelta against threat rules and return a SecurityAlert.

        Args:
            delta: Filesystem delta to evaluate.

        Returns:
            Structured SecurityAlert with severity, category, and guidance.
        """
        path = delta.path
        is_crit = self.is_critical_path(path)
        diff_dict = {d.attribute: (d.old_value, d.new_value) for d in delta.diffs}

        # 1. SUID / SGID elevation detection (Privilege Escalation Indicator)
        if delta.new_record and (delta.new_record.is_suid or delta.new_record.is_sgid):
            was_suid = delta.old_record and delta.old_record.is_suid
            was_sgid = delta.old_record and delta.old_record.is_sgid
            if not was_suid or not was_sgid or delta.change_type == ChangeType.ADDED:
                return SecurityAlert(
                    severity=Severity.CRITICAL,
                    category="SUID_PRIVILEGE_ESCALATION",
                    target_path=path,
                    change_type=delta.change_type,
                    description=f"Privilege escalation indicator: SUID/SGID bit active on {path}",
                    recommendation=(
                        "Inspect binary immediately. SUID/SGID binaries can lead to local root "
                        "compromise. Revoke SUID bit with 'chmod u-s' if unauthorized."
                    ),
                    details=diff_dict,
                )

        # 2. Critical system path evaluation
        if is_crit:
            if delta.change_type == ChangeType.DELETED:
                return SecurityAlert(
                    severity=Severity.CRITICAL,
                    category="CRITICAL_FILE_DELETED",
                    target_path=path,
                    change_type=delta.change_type,
                    description=f"Critical system or configuration file deleted: {path}",
                    recommendation=(
                        "Immediate incident response required. Restore file from trusted "
                        "backup and audit host logs for unauthorized administrative activity."
                    ),
                    details=diff_dict,
                )
            if delta.change_type == ChangeType.MODIFIED:
                return SecurityAlert(
                    severity=Severity.CRITICAL,
                    category="CRITICAL_FILE_TAMPERED",
                    target_path=path,
                    change_type=delta.change_type,
                    description=(f"Cryptographic hash mismatch on critical system file: {path}"),
                    recommendation=(
                        "Immediate incident response required. Inspect binary diffs or "
                        "configuration backdoors. Quarantine host if tampering is confirmed."
                    ),
                    details=diff_dict,
                )
            if delta.change_type == ChangeType.ADDED:
                return SecurityAlert(
                    severity=Severity.CRITICAL,
                    category="CRITICAL_FILE_INJECTION",
                    target_path=path,
                    change_type=delta.change_type,
                    description=(
                        f"Unauthorized file creation in critical security directory: {path}"
                    ),
                    recommendation=(
                        "Verify package manager provenance. If not deployed via approved "
                        "automation, quarantine binary and perform malware analysis."
                    ),
                    details=diff_dict,
                )
            if delta.change_type == ChangeType.ATTRIBUTES_CHANGED:
                return SecurityAlert(
                    severity=Severity.HIGH,
                    category="CRITICAL_METADATA_ALTERED",
                    target_path=path,
                    change_type=delta.change_type,
                    description=(
                        f"Security metadata or permissions altered on critical file: {path}"
                    ),
                    recommendation=(
                        "Revert permissions to standard security baseline. Investigate "
                        "who made attribute modifications."
                    ),
                    details=diff_dict,
                )

        # 3. World-writable permissions exposure (Mode allows write by 'others')
        if delta.new_record:
            mode = delta.new_record.mode
            if mode & 0o002:  # S_IWOTH
                was_world_writable = delta.old_record and (delta.old_record.mode & 0o002)
                if not was_world_writable:
                    return SecurityAlert(
                        severity=Severity.HIGH,
                        category="PERMISSIVE_ACCESS_EXPOSURE",
                        target_path=path,
                        change_type=delta.change_type,
                        description=(
                            f"File has world-writable permissions (mode: {oct(mode)}): {path}"
                        ),
                        recommendation=(
                            "Restrict write permissions ('chmod o-w'). Any local unprivileged user "
                            "can overwrite or corrupt this file."
                        ),
                        details=diff_dict,
                    )

        # 4. Content modification on monitored standard file
        if delta.change_type == ChangeType.MODIFIED:
            return SecurityAlert(
                severity=Severity.HIGH,
                category="CONTENT_TAMPERED",
                target_path=path,
                change_type=delta.change_type,
                description=f"Cryptographic hash divergence detected on monitored file: {path}",
                recommendation=(
                    "Verify against authorized software change ticket. Investigate file diff."
                ),
                details=diff_dict,
            )

        # 5. Ownership (UID/GID) or permission change
        if delta.change_type == ChangeType.ATTRIBUTES_CHANGED:
            if "uid" in diff_dict or "gid" in diff_dict:
                return SecurityAlert(
                    severity=Severity.MEDIUM,
                    category="OWNERSHIP_CHANGED",
                    target_path=path,
                    change_type=delta.change_type,
                    description=f"User or group ownership altered on file: {path}",
                    recommendation=(
                        "Confirm change of ownership was performed by authorized administrator."
                    ),
                    details=diff_dict,
                )
            if "permissions" in diff_dict or "mode" in diff_dict:
                return SecurityAlert(
                    severity=Severity.MEDIUM,
                    category="PERMISSIONS_ALTERED",
                    target_path=path,
                    change_type=delta.change_type,
                    description=f"Filesystem permissions modified on file: {path}",
                    recommendation=(
                        "Ensure permissions align with the principle of least privilege."
                    ),
                    details=diff_dict,
                )
            # Metadata-only (e.g. timestamp mtime or inode)
            return SecurityAlert(
                severity=Severity.LOW,
                category="METADATA_TOUCHED",
                target_path=path,
                change_type=delta.change_type,
                description=f"Metadata timestamp or inode touched on file: {path}",
                recommendation=("Audit for benign touches or potential timestomping activity."),
                details=diff_dict,
            )

        # 6. File deletion (standard)
        if delta.change_type == ChangeType.DELETED:
            return SecurityAlert(
                severity=Severity.MEDIUM,
                category="FILE_DELETED",
                target_path=path,
                change_type=delta.change_type,
                description=f"Monitored file removed from filesystem: {path}",
                recommendation="Verify if deletion was intentional and authorized.",
                details=diff_dict,
            )

        # 7. File addition (standard)
        return SecurityAlert(
            severity=Severity.MEDIUM,
            category="FILE_ADDED",
            target_path=path,
            change_type=delta.change_type,
            description=f"New file created in monitored directory: {path}",
            recommendation="Confirm the file origin and incorporate into baseline if legitimate.",
            details=diff_dict,
        )

    def evaluate_report(self, report: ScanReport) -> list[SecurityAlert]:
        """Evaluate all deltas in a ScanReport into security alerts.

        Args:
            report: ScanReport containing discovered deltas.

        Returns:
            List of generated SecurityAlert objects ordered by severity.
        """
        alerts = [self.evaluate_delta(delta) for delta in report.deltas]
        severity_rank = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        alerts.sort(key=lambda a: severity_rank.get(a.severity, 5))
        return alerts

    @staticmethod
    def filter_alerts(
        alerts: list[SecurityAlert],
        min_severity: Severity = Severity.LOW,
    ) -> list[SecurityAlert]:
        """Filter alerts by minimum severity threshold.

        Args:
            alerts: List of alerts.
            min_severity: Lowest severity to include.

        Returns:
            Filtered list of alerts.
        """
        severity_rank = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        threshold = severity_rank.get(min_severity, 5)
        return [a for a in alerts if severity_rank.get(a.severity, 5) <= threshold]
