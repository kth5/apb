"""Unit tests for SRCDEST configuration and periodic cleanup on the build server."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from apb.constants import BuildStatus
from apb.server import engine


def _set_mtime(path: Path, age_seconds: float) -> None:
    mtime = time.time() - age_seconds
    os.utime(path, (mtime, mtime))


@pytest.fixture
def srcdest_dir(tmp_path: Path) -> Path:
    srcdest = tmp_path / "srcdest"
    srcdest.mkdir()
    return srcdest


def test_cleanup_srcdest_sources_removes_old_entries_and_preserves_locks(srcdest_dir: Path):
    old_file = srcdest_dir / "old.tar.gz"
    old_file.write_bytes(b"old-source")
    _set_mtime(old_file, 40 * 86400)

    new_file = srcdest_dir / "new.tar.gz"
    new_file.write_bytes(b"new-source")
    _set_mtime(new_file, 86400)

    lock_file = srcdest_dir / ".apb-deadbeef.lock"
    lock_file.write_text("lock")
    _set_mtime(lock_file, 40 * 86400)

    old_dir = srcdest_dir / "old-checkout"
    old_dir.mkdir()
    (old_dir / "README").write_text("old")
    _set_mtime(old_dir, 40 * 86400)

    stats = engine.cleanup_srcdest_sources(srcdest_dir, retention_days=30)

    assert stats["removed_files"] == 1
    assert stats["removed_dirs"] == 1
    assert stats["freed_bytes"] >= len(b"old-source")
    assert not old_file.exists()
    assert new_file.exists()
    assert lock_file.exists()
    assert not old_dir.exists()


def test_cleanup_srcdest_noop_when_srcdest_undefined():
    with patch.object(engine, "cleanup_orphaned_srcdest_locks") as lock_cleanup_mock:
        with patch.object(engine, "get_makepkg_config", return_value={}):
            engine.cleanup_srcdest()

    lock_cleanup_mock.assert_not_called()


def test_cleanup_srcdest_runs_lock_and_source_cleanup(srcdest_dir: Path):
    old_file = srcdest_dir / "old.tar.gz"
    old_file.write_bytes(b"old")
    _set_mtime(old_file, 40 * 86400)

    engine.server_config = {"srcdest_retention_days": 30}

    with patch.object(engine, "get_makepkg_config", return_value={"SRCDEST": str(srcdest_dir)}):
        with patch.object(engine, "cleanup_orphaned_srcdest_locks") as lock_cleanup_mock:
            engine.cleanup_srcdest()

    lock_cleanup_mock.assert_called_once()
    assert not old_file.exists()


def test_cleanup_srcdest_skips_source_cleanup_during_active_builds(srcdest_dir: Path):
    old_file = srcdest_dir / "old.tar.gz"
    old_file.write_bytes(b"old")
    _set_mtime(old_file, 40 * 86400)

    engine.server_config = {"srcdest_retention_days": 30}
    engine.active_builds["build-1"] = {"status": BuildStatus.BUILDING}

    try:
        with patch.object(engine, "get_makepkg_config", return_value={"SRCDEST": str(srcdest_dir)}):
            with patch.object(engine, "cleanup_orphaned_srcdest_locks") as lock_cleanup_mock:
                engine.cleanup_srcdest()

        lock_cleanup_mock.assert_called_once()
        assert old_file.exists()
    finally:
        engine.active_builds.pop("build-1", None)


def test_monitor_srcdest_cleanup_returns_immediately_when_disabled():
    engine.server_config = {"srcdest_cleanup_interval": 0}

    with patch.object(engine, "cleanup_srcdest") as cleanup_mock:
        engine.monitor_srcdest_cleanup()

    cleanup_mock.assert_not_called()


def test_monitor_srcdest_cleanup_runs_once_before_waiting():
    engine.server_config = {"srcdest_cleanup_interval": 60}
    engine.shutdown_event.clear()

    with patch.object(engine, "cleanup_srcdest") as cleanup_mock:
        with patch.object(engine.shutdown_event, "wait", side_effect=lambda _interval: engine.shutdown_event.set()):
            engine.monitor_srcdest_cleanup()

    cleanup_mock.assert_called_once()


HOST_MAKEPKG_CONF = """#!/hint/bash
SRCDEST=/var/cache/makepkg/sources
export CCACHE_DIR="/var/cache/ccache"
"""


@pytest.fixture
def host_conf_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    conf_dir = tmp_path / "etc"
    conf_dir.mkdir()
    (conf_dir / "makepkg.conf").write_text(HOST_MAKEPKG_CONF, encoding="utf-8")
    (conf_dir / "pacman.conf").write_text("[options]\nArchitecture = auto\n", encoding="utf-8")
    monkeypatch.setattr(engine, "HOST_CONF_DIR", conf_dir)
    return conf_dir


def _fake_sudo_run(command, **_kwargs) -> subprocess.CompletedProcess:
    """Stand in for the privileged `sudo cp` calls made while setting up the chroot."""
    if command[:2] == ["sudo", "cp"]:
        shutil.copy(command[2], command[3])
    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


def test_get_makepkg_config_falls_back_to_makepkg_conf(host_conf_dir: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(engine, "server_config", {})

    config = engine.get_makepkg_config()

    assert config["SRCDEST"] == "/var/cache/makepkg/sources"
    assert config["CCACHE_DIR"] == "/var/cache/ccache"


def test_get_makepkg_config_prefers_cli_srcdest(
    host_conf_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    override = tmp_path / "cli-sources"
    monkeypatch.setattr(engine, "server_config", {"srcdest": override})

    config = engine.get_makepkg_config()

    assert config["SRCDEST"] == str(override)
    assert config["CCACHE_DIR"] == "/var/cache/ccache"


def test_get_makepkg_config_cli_srcdest_without_conf_entry(
    host_conf_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (host_conf_dir / "makepkg.conf").write_text("#SRCDEST=/var/cache/makepkg/sources\n", encoding="utf-8")
    override = tmp_path / "cli-sources"
    monkeypatch.setattr(engine, "server_config", {"srcdest": override})

    assert engine.get_makepkg_config() == {"SRCDEST": str(override)}


def test_apply_srcdest_override_replaces_active_assignment():
    result = engine.apply_srcdest_override(HOST_MAKEPKG_CONF, "/data/sources")

    assert 'SRCDEST="/data/sources"' in result
    assert "SRCDEST=/var/cache/makepkg/sources" not in result
    assert 'export CCACHE_DIR="/var/cache/ccache"' in result


def test_apply_srcdest_override_appends_when_only_commented_out():
    conf_text = "#SRCDEST=/var/cache/makepkg/sources\nBUILDDIR=/tmp/build\n"

    result = engine.apply_srcdest_override(conf_text, "/data/sources")

    assert result.splitlines() == [
        "#SRCDEST=/var/cache/makepkg/sources",
        "BUILDDIR=/tmp/build",
        'SRCDEST="/data/sources"',
    ]


def test_setup_buildroot_writes_srcdest_override_into_chroot_conf(
    host_conf_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    buildroot = tmp_path / "buildroot"
    chroot_etc = buildroot / "root" / "etc"
    chroot_etc.mkdir(parents=True)
    override = tmp_path / "cli-sources"
    monkeypatch.setattr(engine, "server_config", {"srcdest": override})

    with patch.object(engine.subprocess, "run", side_effect=_fake_sudo_run):
        assert engine.setup_buildroot(buildroot)

    chroot_conf = chroot_etc / "makepkg.conf"
    chroot_conf_text = chroot_conf.read_text(encoding="utf-8")
    assert f'SRCDEST="{override}"' in chroot_conf_text
    assert "SRCDEST=/var/cache/makepkg/sources" not in chroot_conf_text
    assert chroot_conf.stat().st_mode & 0o777 == 0o644
    assert not (buildroot / ".makepkg.conf.apb").exists()


def test_setup_buildroot_keeps_host_conf_without_override(
    host_conf_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    buildroot = tmp_path / "buildroot"
    chroot_etc = buildroot / "root" / "etc"
    chroot_etc.mkdir(parents=True)
    monkeypatch.setattr(engine, "server_config", {})

    with patch.object(engine.subprocess, "run", side_effect=_fake_sudo_run):
        assert engine.setup_buildroot(buildroot)

    assert (chroot_etc / "makepkg.conf").read_text(encoding="utf-8") == HOST_MAKEPKG_CONF
