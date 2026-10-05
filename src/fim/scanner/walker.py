"""Safe recursive filesystem traversal with symlink defenses and glob filtering."""

import fnmatch
import logging
from collections.abc import Generator
from pathlib import Path

from fim.config.settings import settings

logger = logging.getLogger("fim.scanner")


class SafePathWalker:
    """Recursively walks filesystem trees with symlink loop detection and exclusion filters."""

    def __init__(
        self,
        exclude_patterns: list[str] | None = None,
        follow_symlinks: bool = False,
        max_depth: int | None = None,
    ) -> None:
        self.exclude_patterns = exclude_patterns or settings.DEFAULT_EXCLUDE_PATTERNS
        self.follow_symlinks = follow_symlinks
        self.max_depth = max_depth or settings.MAX_RECURSION_DEPTH

    def is_excluded(self, path: Path) -> bool:
        """Check if path matches any configured glob/exclusion pattern.

        Evaluates against both file name and string path representations.
        """
        path_str = str(path)
        name = path.name

        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path_str, pattern):
                return True
        return False

    def walk(self, root: Path) -> Generator[Path, None, None]:
        """Safely traverse directory tree yielding readable regular files.

        Args:
            root: Starting file or directory path.

        Yields:
            Resolved Path objects to readable regular files.
        """
        canonical_root = root.resolve(strict=False)

        if not canonical_root.exists():
            logger.warning("Specified root does not exist: %s", canonical_root)
            return

        if canonical_root.is_file():
            if not self.is_excluded(canonical_root):
                yield canonical_root
            return

        # Stack-based traversal with depth tracking: (current_dir, current_depth)
        stack: list[tuple[Path, int]] = [(canonical_root, 0)]
        visited_inodes: set[int] = set()

        while stack:
            curr_dir, depth = stack.pop()

            if depth > self.max_depth:
                logger.warning(
                    "Reached maximum recursion depth (%d) at %s", self.max_depth, curr_dir
                )
                continue

            try:
                curr_stat = curr_dir.stat()
                if curr_stat.st_ino in visited_inodes:
                    logger.debug("Skipping already visited directory inode: %s", curr_dir)
                    continue
                visited_inodes.add(curr_stat.st_ino)
            except (PermissionError, OSError) as exc:
                logger.warning("Cannot stat directory %s: %exc", curr_dir, exc)
                continue

            try:
                entries = list(curr_dir.iterdir())
            except (PermissionError, OSError) as exc:
                logger.warning("Permission denied reading directory %s: %s", curr_dir, exc)
                continue

            for entry in sorted(entries):
                # Symlink defense
                if entry.is_symlink() and not self.follow_symlinks:
                    logger.debug("Ignoring symlink per security policy: %s", entry)
                    continue

                if self.is_excluded(entry):
                    continue

                try:
                    if entry.is_dir():
                        stack.append((entry, depth + 1))
                    elif entry.is_file():
                        yield entry.resolve(strict=False)
                except (PermissionError, OSError) as exc:
                    logger.warning("Access error for %s: %s", entry, exc)
                    continue
