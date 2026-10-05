"""Security alert domain model formatted for SIEM ingestion and CEF telemetry."""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from fim.models.delta import ChangeType


class Severity(StrEnum):
    """Threat severity classification levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityAlert(BaseModel):
    """SIEM-ready security alert capturing unauthorized filesystem modifications."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    severity: Severity = Field(default=Severity.MEDIUM)
    category: str = Field(description="Alert category (e.g. SUID_ESCALATION, CONTENT_TAMPERING)")
    target_path: str = Field(description="Altered file path")
    change_type: ChangeType = Field(description="Addition, Deletion, or Modification")
    description: str = Field(description="Clear explanation of security event")
    recommendation: str = Field(
        default="Inspect host for compromise and verify authorized change window.",
        description="Recommended defensive response action",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual metadata diffs",
    )

    def to_cef(self) -> str:
        """Format alert as standard ArcSight Common Event Format (CEF) string.

        Format:
        CEF:Version|Vendor|Product|Version|Event Class ID|Name|Severity|[Extension]
        """
        severity_mapping = {
            Severity.INFO: 1,
            Severity.LOW: 3,
            Severity.MEDIUM: 6,
            Severity.HIGH: 8,
            Severity.CRITICAL: 10,
        }
        cef_sev = severity_mapping.get(self.severity, 5)

        # Build CEF extension key-value pairs
        ext_parts = [
            f"filePath={self.target_path}",
            f"act={self.change_type.value}",
            f"msg={self.description.replace('=', ':')}",
            f"externalId={self.id}",
            f"rt={self.timestamp}",
        ]
        extension_str = " ".join(ext_parts)

        return (
            f"CEF:0|CyberSecurityPortfolio|FileIntegrityMonitor|0.1.0|"
            f"{self.category}|{self.description}|{cef_sev}|{extension_str}"
        )
