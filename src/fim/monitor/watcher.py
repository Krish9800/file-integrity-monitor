"""Real-time directory filesystem observer wrapping watchdog background threads."""

import logging
from collections.abc import Callable
from pathlib import Path
from types import TracebackType

from watchdog.observers import Observer

from fim.models.alert import SecurityAlert
from fim.models.baseline import BaselineCatalog
from fim.monitor.handler import FIMEventHandler
from fim.rules.policy import PolicyEngine

logger = logging.getLogger("fim.monitor")


class RealtimeMonitor:
    """Manages kernel filesystem notification threads across monitored directory roots."""

    def __init__(
        self,
        baseline: BaselineCatalog,
        policy_engine: PolicyEngine,
        alert_callback: Callable[[SecurityAlert], None],
        exclude_patterns: list[str] | None = None,
        settle_delay: float = 0.1,
    ) -> None:
        """Initialize RealtimeMonitor.

        Args:
            baseline: Initial baseline catalog.
            policy_engine: PolicyEngine to classify anomalies.
            alert_callback: Invoked on security alert discovery.
            exclude_patterns: Glob patterns to exclude.
            settle_delay: Small window (seconds) allowing file flush before reading.
        """
        self.baseline = baseline
        self.policy_engine = policy_engine
        self.alert_callback = alert_callback
        self.exclude_patterns = exclude_patterns or []
        self.settle_delay = settle_delay

        self._observer = Observer()
        self._handler = FIMEventHandler(
            baseline=baseline,
            policy_engine=policy_engine,
            alert_callback=alert_callback,
            exclude_patterns=self.exclude_patterns,
            settle_delay=self.settle_delay,
        )
        self._is_running = False

    def start(self) -> None:
        """Schedule recursive watches on all baseline root paths and start observer."""
        if self._is_running:
            return

        scheduled_any = False
        for root_str in self.baseline.root_paths:
            root_path = Path(root_str).resolve()
            if root_path.exists() and root_path.is_dir():
                self._observer.schedule(
                    self._handler,
                    path=str(root_path),
                    recursive=True,
                )
                logger.info("Attached realtime watch on directory: %s", root_path)
                scheduled_any = True
            elif root_path.exists() and root_path.is_file():
                # For single files, watch their parent directory non-recursively
                self._observer.schedule(
                    self._handler,
                    path=str(root_path.parent),
                    recursive=False,
                )
                logger.info("Attached watch on parent of file: %s", root_path)
                scheduled_any = True
            else:
                logger.warning("Cannot attach watch: target does not exist: %s", root_path)

        if not scheduled_any:
            raise ValueError(
                "No valid directories or files found in baseline root paths to monitor."
            )

        self._observer.start()
        self._is_running = True
        logger.info("FIM RealtimeMonitor background observer started successfully.")

    def stop(self) -> None:
        """Stop background monitoring and join observer threads."""
        if not self._is_running:
            return
        self._observer.stop()
        self._observer.join(timeout=5.0)
        self._is_running = False
        logger.info("FIM RealtimeMonitor stopped.")

    @property
    def is_alive(self) -> bool:
        """Check if observer thread is currently active."""
        return self._is_running and self._observer.is_alive()

    def __enter__(self) -> "RealtimeMonitor":
        """Context manager support."""
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Stop observer cleanly on context exit."""
        self.stop()
