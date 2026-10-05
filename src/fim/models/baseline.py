"""Baseline catalog model representing the cryptographically authenticated state snapshot."""

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from fim.core.integrity import IntegrityError, sign_payload, verify_payload
from fim.models.file_record import FileRecord


class BaselineCatalog(BaseModel):
    """Cryptographically sealed catalog storing reference filesystem records."""

    version: str = Field(default="1.0", description="Baseline schema version")
    created_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="Catalog generation timestamp in UTC",
    )
    root_paths: list[str] = Field(
        default_factory=list,
        description="List of target root directory paths monitored",
    )
    total_files: int = Field(default=0, ge=0, description="Total files tracked in baseline")
    signature: str | None = Field(
        default=None,
        description="HMAC-SHA256 digest sealing catalog payload",
    )
    records: dict[str, FileRecord] = Field(
        default_factory=dict,
        description="Mapping from canonical path to FileRecord",
    )

    def get_canonical_payload(self) -> bytes:
        """Produce deterministic, sorted JSON payload excluding the signature.

        Guarantees that signature verification is stable regardless of key ordering.
        """
        data = {
            "version": self.version,
            "created_at": self.created_at,
            "root_paths": sorted(self.root_paths),
            "total_files": self.total_files,
            "records": {
                p: self.records[p].model_dump(mode="json") for p in sorted(self.records.keys())
            },
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def seal(self, key: bytes) -> str:
        """Compute HMAC-SHA256 signature and seal the catalog against tampering.

        Args:
            key: Secret HMAC key.

        Returns:
            Computed signature string.
        """
        payload = self.get_canonical_payload()
        self.signature = sign_payload(payload, key)
        return self.signature

    def verify_integrity(self, key: bytes) -> bool:
        """Verify catalog authenticity and detect baseline poisoning.

        Args:
            key: Secret HMAC key.

        Returns:
            True if catalog signature matches, False otherwise.
        """
        if not self.signature:
            return False
        payload = self.get_canonical_payload()
        return verify_payload(payload, self.signature, key)

    def save(self, file_path: Path, key: bytes | None = None) -> None:
        """Save baseline catalog to JSON file, optionally sealing with HMAC key.

        Args:
            file_path: Destination path for baseline file.
            key: Optional secret key to sign catalog before saving.
        """
        if key is not None:
            self.seal(key)

        file_path.write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load(cls, file_path: Path, key: bytes | None = None) -> "BaselineCatalog":
        """Load and parse baseline catalog from file, optionally enforcing HMAC check.

        Args:
            file_path: Path to baseline JSON file.
            key: Optional secret key to verify catalog authenticity.

        Returns:
            Validated BaselineCatalog instance.

        Raises:
            FileNotFoundError: If baseline file is missing.
            IntegrityError: If catalog signature is missing or verification fails.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Baseline catalog '{file_path}' does not exist.")

        raw_content = file_path.read_text(encoding="utf-8")
        catalog = cls.model_validate_json(raw_content)

        if key is not None:
            if not catalog.signature:
                raise IntegrityError(
                    f"Baseline '{file_path}' is unsigned; cryptographic verification failed."
                )
            if not catalog.verify_integrity(key):
                raise IntegrityError(
                    f"Baseline catalog '{file_path}' failed HMAC signature check! "
                    "Possible baseline tampering or incorrect key."
                )

        return catalog
