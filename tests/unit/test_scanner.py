"""Unit tests for Phase 4: SafePathWalker and ScanEngine."""

from pathlib import Path

from fim.core.integrity import generate_key
from fim.scanner.engine import ScanEngine
from fim.scanner.walker import SafePathWalker


def test_walker_discovers_nested_files(tmp_path: Path) -> None:
    """Ensure SafePathWalker finds files in nested directories."""
    dir_a = tmp_path / "a"
    dir_b = dir_a / "b"
    dir_b.mkdir(parents=True)

    f1 = tmp_path / "root.txt"
    f2 = dir_a / "level1.txt"
    f3 = dir_b / "level2.txt"

    f1.write_text("root", encoding="utf-8")
    f2.write_text("l1", encoding="utf-8")
    f3.write_text("l2", encoding="utf-8")

    walker = SafePathWalker()
    discovered = list(walker.walk(tmp_path))

    discovered_names = {p.name for p in discovered}
    assert discovered_names == {"root.txt", "level1.txt", "level2.txt"}


def test_walker_exclusion_patterns(tmp_path: Path) -> None:
    """Ensure excluded file extensions and glob patterns are omitted."""
    (tmp_path / "valid.txt").write_text("valid", encoding="utf-8")
    (tmp_path / "cache.tmp").write_text("temp", encoding="utf-8")
    (tmp_path / "app.log").write_text("log", encoding="utf-8")

    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("git config", encoding="utf-8")

    walker = SafePathWalker(exclude_patterns=["*.tmp", "*.log", "*/.git/*"])
    discovered = list(walker.walk(tmp_path))

    discovered_names = {p.name for p in discovered}
    assert discovered_names == {"valid.txt"}


def test_walker_ignores_symlinks(tmp_path: Path) -> None:
    """Ensure symlinks are ignored to prevent traversal loops and attacks."""
    real_file = tmp_path / "real.txt"
    real_file.write_text("content", encoding="utf-8")

    symlink_file = tmp_path / "symlink_file.txt"
    try:
        symlink_file.symlink_to(real_file)
    except OSError:
        pass  # On environments without symlink privilege

    walker = SafePathWalker(follow_symlinks=False)
    discovered = list(walker.walk(tmp_path))

    assert real_file.resolve() in discovered
    if symlink_file.exists() and symlink_file.is_symlink():
        assert symlink_file not in discovered


def test_scan_engine_build_baseline(tmp_path: Path) -> None:
    """Test ScanEngine building and cryptographically signing a baseline catalog."""
    sub = tmp_path / "monitored"
    sub.mkdir()
    (sub / "conf1.cfg").write_text("cfg1", encoding="utf-8")
    (sub / "conf2.cfg").write_text("cfg2", encoding="utf-8")

    key = generate_key()
    engine = ScanEngine()
    baseline = engine.build_baseline([sub], key=key)

    assert baseline.total_files == 2
    assert baseline.signature is not None
    assert baseline.verify_integrity(key) is True
    assert len(baseline.records) == 2


def test_walker_handles_single_file_root(tmp_path: Path) -> None:
    """Ensure walker works when pointing directly to a single file."""
    target = tmp_path / "single.conf"
    target.write_text("data", encoding="utf-8")

    walker = SafePathWalker()
    files = list(walker.walk(target))
    assert len(files) == 1
    assert files[0] == target.resolve()
