"""Tests for SRCDEST locking and makechrootpkg command assembly."""

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from apb.server import engine


def test_srcdest_lock_path_uses_pkgname_hash(tmp_path: Path):
    pkgname = "foo-bar"
    expected_hash = hashlib.md5(pkgname.encode()).hexdigest()
    lock_path = engine.srcdest_lock_path(str(tmp_path), pkgname)
    assert lock_path == str(tmp_path / f".apb-{expected_hash}.lock")


def test_different_packages_get_distinct_locks(tmp_path: Path):
    srcdest = str(tmp_path)
    lock_a = engine.lock_srcdest(srcdest, "package-a")
    lock_b = engine.lock_srcdest(srcdest, "package-b")
    assert lock_a is not None
    assert lock_b is not None
    assert lock_a != lock_b
    engine.unlock_srcdest(lock_a)
    engine.unlock_srcdest(lock_b)


def test_same_package_blocks_second_lock(tmp_path: Path):
    srcdest = str(tmp_path)
    first = engine.lock_srcdest(srcdest, "same-pkg")
    assert first is not None
    second = engine.lock_srcdest(srcdest, "same-pkg")
    assert second is None
    engine.unlock_srcdest(first)


def test_leftover_lock_file_without_holder_is_acquired(tmp_path: Path):
    srcdest = str(tmp_path)
    lock_file = engine.srcdest_lock_path(srcdest, "orphan-pkg")
    Path(lock_file).write_text("stale")
    fd = engine.lock_srcdest(srcdest, "orphan-pkg")
    assert fd is not None
    assert Path(lock_file).exists()
    engine.unlock_srcdest(fd)


def test_cleanup_removes_unheld_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    srcdest = str(tmp_path)
    lock_file = engine.srcdest_lock_path(srcdest, "cleanup-me")
    Path(lock_file).write_text("stale")
    monkeypatch.setattr(
        engine,
        "get_makepkg_config",
        lambda: {"SRCDEST": srcdest},
    )
    engine.cleanup_orphaned_srcdest_locks()
    assert not Path(lock_file).exists()


def test_cleanup_keeps_lock_held_by_running_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    srcdest = str(tmp_path)
    held_fd = engine.lock_srcdest(srcdest, "busy-pkg")
    assert held_fd is not None
    lock_file = engine.srcdest_lock_path(srcdest, "busy-pkg")
    monkeypatch.setattr(
        engine,
        "get_makepkg_config",
        lambda: {"SRCDEST": srcdest},
    )
    engine.cleanup_orphaned_srcdest_locks()
    assert Path(lock_file).exists()
    engine.unlock_srcdest(held_fd)


def test_build_makechrootpkg_command_includes_chroot_slot_and_bind_mounts(tmp_path: Path):
    buildroot = tmp_path / "buildroot"
    makepkg_config = {
        "CCACHE_DIR": "/cache",
        "SRCDEST": "/sources",
    }
    cmd = engine.build_makechrootpkg_command(
        buildroot,
        "apb-slot-1",
        makepkg_config,
        "/tmp/custom-pacman.conf",
        "x86_64",
    )
    assert cmd[:7] == [
        "sudo",
        "makechrootpkg",
        "-cuT",
        "-l",
        "apb-slot-1",
        "-r",
        str(buildroot),
    ]
    assert "-d" in cmd
    assert "/cache" in cmd
    assert "/sources" in cmd
    assert "-D" in cmd
    assert "/tmp/custom-pacman.conf:/etc/pacman.conf" in cmd


def test_build_makechrootpkg_command_uses_ppc32_on_powerpc(tmp_path: Path):
    buildroot = tmp_path / "buildroot"
    cmd = engine.build_makechrootpkg_command(
        buildroot,
        "apb-slot-0",
        {},
        None,
        "powerpc",
    )
    assert cmd[0:3] == ["sudo", "ppc32", "makechrootpkg"]
    assert "-l" in cmd and "apb-slot-0" in cmd


def test_init_chroot_slots_resets_pool():
    engine.init_chroot_slots(2)
    slot_a = engine.chroot_slots.get_nowait()
    slot_b = engine.chroot_slots.get_nowait()
    assert {slot_a, slot_b} == {"apb-slot-0", "apb-slot-1"}
    with pytest.raises(Exception):
        engine.chroot_slots.get_nowait()
    engine.chroot_slots.put(slot_a)
    engine.chroot_slots.put(slot_b)
    engine.init_chroot_slots(engine.DEFAULT_MAX_CONCURRENT)
