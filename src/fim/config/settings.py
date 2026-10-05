"""Configuration and baseline security settings for the File Integrity Monitor."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class FIMSettings(BaseSettings):
    """FIM operational parameters, buffer sizes, and threat heuristics."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General System
    APP_NAME: str = "File Integrity Monitor"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "production"

    # Streaming Cryptographic Buffering
    HASH_CHUNK_SIZE_BYTES: int = Field(
        default=65536,
        ge=4096,
        description="Chunk buffer size for streaming file hashing (64 KB default)",
    )
    DEFAULT_ALGORITHMS: list[str] = Field(
        default_factory=lambda: ["sha256", "blake2b"],
        description="Dual cryptographic hash algorithms computed for collision resistance",
    )

    # Filesystem Traversal & Safety Limits
    MAX_RECURSION_DEPTH: int = Field(
        default=30,
        ge=1,
        le=100,
        description="Maximum directory recursion depth to avoid traversal loops",
    )
    FOLLOW_SYMLINKS: bool = Field(
        default=False,
        description="Whether to follow symbolic links during traversal (disabled for safety)",
    )
    DEFAULT_EXCLUDE_PATTERNS: list[str] = Field(
        default_factory=lambda: [
            "*.tmp",
            "*.swp",
            "*.pyc",
            "*.log",
            "*/.git/*",
            "*/__pycache__/*",
            "*/.venv/*",
            "*/.idea/*",
            "*/.vscode/*",
        ],
        description="Glob patterns ignored during integrity scans",
    )

    # Baseline & HMAC Sealing
    DEFAULT_BASELINE_FILE: str = "baseline.json"
    DEFAULT_KEY_FILE: str = "fim_key.secret"
    HMAC_KEY_BYTES: int = Field(default=32, ge=32, description="256-bit HMAC authentication key")

    # Real-time Event Monitoring
    DEBOUNCE_INTERVAL_SECONDS: float = Field(
        default=0.5,
        ge=0.1,
        le=5.0,
        description="Debounce delay in seconds to aggregate burst filesystem events",
    )

    # Heuristic Severity Critical Patterns
    CRITICAL_SYSTEM_PATTERNS: list[str] = Field(
        default_factory=lambda: [
            "/etc/passwd*",
            "/etc/shadow*",
            "/etc/sudoers*",
            "/etc/pam.d/*",
            "/etc/ssh/*",
            "*/authorized_keys*",
            "/bin/*",
            "/sbin/*",
            "/usr/bin/*",
            "/usr/sbin/*",
        ],
        description="Path patterns considered critical system infrastructure",
    )


settings = FIMSettings()
