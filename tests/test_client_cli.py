"""Unit tests for apb client CLI dispatch, config-based builds, and the auth client."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from apb.arch import KNOWN_PACKAGE_ARCH_SUFFIXES
from apb.client import cli
from apb.client.auth import APBAuthClient, choose_mfa_method
from mfa_support import SoftSecurityKey, enroll_totp, fresh_totp_code
from apb.constants import BuildStatus
from apb.models import BuildSubmitResponse

PKGBUILD = "pkgname=test\npkgver=1\npkgrel=1\narch=(x86_64 aarch64)\n"
CONFIG = {
    "servers": {"x86_64": ["http://x86-a", "http://x86-b"], "aarch64": ["http://arm"]},
    "farm_url": "http://farm",
}


@pytest.fixture
def pkg_dir(tmp_path: Path) -> Path:
    path = tmp_path / "pkg"
    path.mkdir()
    (path / "PKGBUILD").write_text(PKGBUILD, encoding="utf-8")
    return path


def _context(argv: list[str], monkeypatch: pytest.MonkeyPatch, config: dict = CONFIG) -> cli.CliContext:
    monkeypatch.setattr(cli, "load_config", lambda _path: config)
    return cli.resolve_context(cli.parse_args(argv))


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, []), ("", []), ("x86_64", ["x86_64"]), (" x86_64, aarch64 ,,x86_64", ["x86_64", "aarch64"])],
)
def test_parse_arch_list(value, expected) -> None:
    assert cli.parse_arch_list(value) == expected


def test_resolve_context_uses_farm_url_for_auth_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(["--auth-status"], monkeypatch)
    assert ctx.server_url == "http://farm"
    assert ctx.auth_client is not None


def test_resolve_context_direct_server_has_no_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(["--server", "http://x86-a"], monkeypatch)
    assert ctx.server_url == "http://x86-a"
    assert ctx.auth_client is None
    assert ctx.fallback_arch is None


def test_run_dispatches_single_command(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(["--cancel", "b1"], monkeypatch)
    monkeypatch.setattr(cli, "run_cancel", lambda _ctx: 7)
    monkeypatch.setattr(cli, "run_build", lambda _ctx: pytest.fail("build must not run"))
    assert cli.run(ctx) == 7


def test_pkgbuild_download_requires_farm(monkeypatch: pytest.MonkeyPatch, pkg_dir: Path, capsys) -> None:
    ctx = _context(["--server", "http://x86-a", "--download", str(pkg_dir)], monkeypatch)
    assert cli.run(ctx) == 1
    assert "requires --farm" in capsys.readouterr().out


def test_direct_build_needs_single_arch(monkeypatch: pytest.MonkeyPatch, pkg_dir: Path, capsys) -> None:
    ctx = _context(["--server", "http://x86-a", "--arch", "x86_64,aarch64", str(pkg_dir)], monkeypatch)
    assert cli.run(ctx) == 1
    assert "need --arch or default_arch" in capsys.readouterr().out


def test_config_build_passes_options(monkeypatch: pytest.MonkeyPatch, pkg_dir: Path) -> None:
    captured = {}

    def fake_build(*args, **kwargs):
        captured.update(kwargs)
        return True

    monkeypatch.setattr(cli, "build_for_multiple_arches", fake_build)
    ctx = _context(
        ["--arch", "x86_64,aarch64", "--no-download", "--build-timeout", "600", str(pkg_dir)],
        monkeypatch,
    )
    assert cli.run(ctx) == 0
    assert captured["specific_arch"] == "x86_64,aarch64"
    assert captured["download"] is False
    assert captured["build_timeout"] == 600


def test_build_for_multiple_arches_submits_comma_separated_archs(
    monkeypatch: pytest.MonkeyPatch, pkg_dir: Path
) -> None:
    submitted = []

    def fake_submit(server_url, *_args, **kwargs):
        submitted.append((server_url, kwargs.get("build_timeout")))
        if server_url == "http://x86-a":
            return None
        return BuildSubmitResponse(build_id=f"id-{server_url}", status=BuildStatus.QUEUED)

    monkeypatch.setattr(cli, "submit_build", fake_submit)
    assert cli.build_for_multiple_arches(
        pkg_dir, pkg_dir / "output", CONFIG, detach=True, force=True,
        specific_arch="x86_64,aarch64", build_timeout=900,
    ) is True
    assert submitted == [("http://x86-a", 900), ("http://x86-b", 900), ("http://arm", 900)]


def test_build_for_multiple_arches_reports_missing_servers(
    monkeypatch: pytest.MonkeyPatch, pkg_dir: Path, capsys
) -> None:
    monkeypatch.setattr(
        cli, "submit_build", lambda *_a, **_k: BuildSubmitResponse(build_id="b1", status=BuildStatus.QUEUED)
    )
    assert cli.build_for_multiple_arches(
        pkg_dir, pkg_dir / "output", CONFIG, detach=True, force=True, specific_arch="x86_64,riscv64",
    ) is False
    out = capsys.readouterr().out
    assert "[riscv64] No servers configured" in out
    assert "[riscv64] Build submission failed" in out


def test_build_for_multiple_arches_without_download(monkeypatch: pytest.MonkeyPatch, pkg_dir: Path) -> None:
    monkeypatch.setattr(
        cli, "submit_build", lambda url, *_a, **_k: BuildSubmitResponse(build_id=f"id-{url}", status="queued")
    )
    captured_targets = []

    def fake_monitor(targets, *, verbose=False):
        captured_targets.extend(targets)
        return {target.build_id: (BuildStatus.COMPLETED, True) for target in targets}

    monkeypatch.setattr(cli, "monitor_builds", fake_monitor)
    assert cli.build_for_multiple_arches(
        pkg_dir, pkg_dir / "output", CONFIG, force=True, download=False
    ) is True
    assert [target.arch for target in captured_targets] == ["x86_64", "aarch64"]
    assert all(target.output_dir is None for target in captured_targets)


def test_known_package_arch_suffixes() -> None:
    assert "espresso" not in KNOWN_PACKAGE_ARCH_SUFFIXES
    assert {"x86_64", "aarch64", "powerpc", "powerpc64le", "any"} <= set(KNOWN_PACKAGE_ARCH_SUFFIXES)
    assert len(KNOWN_PACKAGE_ARCH_SUFFIXES) == len(set(KNOWN_PACKAGE_ARCH_SUFFIXES))


def test_auth_client_keeps_url_prefix(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "token": "secret",
                "user": {"id": 1, "username": "alice", "role": "user", "created_at": 0.0},
            },
        )

    monkeypatch.setattr(
        "apb.client.auth.create_sync_client",
        lambda **_kwargs: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    auth_path = tmp_path / "auth.json"
    auth_client = APBAuthClient("http://farm/apb/", config_path=auth_path)

    assert auth_client.login("alice", "password1") is True
    assert str(requests[0].url) == "http://farm/apb/auth/login"
    assert json.loads(auth_path.read_text())["tokens"]["http://farm/apb"] == "secret"
    assert auth_client.get_auth_headers() == {"Authorization": "Bearer secret"}


@pytest.mark.parametrize(
    ("methods", "requested", "has_key", "expected"),
    [
        (["webauthn", "totp", "recovery"], None, True, "webauthn"),
        (["webauthn", "totp", "recovery"], None, False, "totp"),
        (["webauthn", "recovery"], None, False, "recovery"),
        (["webauthn"], None, False, "webauthn"),
        (["webauthn", "totp"], "totp", True, "totp"),
        (["totp"], "key", False, None),
        (["totp", "recovery"], "recovery", False, "recovery"),
    ],
)
def test_choose_mfa_method(methods, requested, has_key, expected) -> None:
    assert choose_mfa_method(methods, requested, has_key) == expected


def test_parse_args_2fa_method() -> None:
    assert cli.parse_args(["--login", "--2fa-method", "key"]).mfa_method == "key"
    assert cli.parse_args(["--login"]).mfa_method is None


@pytest.fixture
def farm_auth_client(farm_client, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> APBAuthClient:
    """APBAuthClient talking to the in-process farm app at its configured farm_url."""
    monkeypatch.setattr("apb.client.auth.create_sync_client", lambda **_kwargs: contextlib.nullcontext(farm_client))
    return APBAuthClient("http://localhost:8080", config_path=tmp_path / "auth.json")


def test_auth_client_login_with_totp(farm_auth_client: APBAuthClient) -> None:
    from apb.farm import core

    db = core.auth_manager.db
    user = core.auth_manager.create_user("bob", "password123", core.UserRole.USER)
    enroll_totp(db, user.id)
    prompts = []

    def prompt(label: str) -> str:
        prompts.append(label)
        return fresh_totp_code(db, user.id)

    assert farm_auth_client.login("bob", "password123", prompt=prompt) is True
    assert prompts == ["Authentication code: "]
    assert farm_auth_client.get_user_info()["mfa_enabled"] is True


def test_auth_client_login_with_security_key(farm_auth_client: APBAuthClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from apb.farm import core, mfa

    db = core.auth_manager.db
    user = core.auth_manager.create_user("bob", "password123", core.UserRole.USER)
    key = SoftSecurityKey()
    mfa.register_security_key(
        db,
        core.public_farm_url(),
        "session",
        user.id,
        "YubiKey",
        key.register(mfa.registration_options(db, core.public_farm_url(), "session", user.id, "bob")),
    )
    origins = []

    class FakeFido2Client:
        def __init__(self, device, collector, user_interaction):
            origins.append(collector._origin)

        def get_assertion(self, options):
            assertion = key.assertion({"publicKey": dict(options)})
            return SimpleNamespace(get_response=lambda _index: assertion)

    monkeypatch.setattr("apb.client.auth.find_security_keys", lambda: [object()])
    monkeypatch.setattr("apb.client.auth.Fido2Client", FakeFido2Client)

    assert farm_auth_client.login("bob", "password123", prompt=lambda _label: pytest.fail("no code prompt expected")) is True
    assert origins == ["http://localhost:8080"]


def test_auth_client_reports_admin_setup(farm_auth_client: APBAuthClient, capsys: pytest.CaptureFixture) -> None:
    assert farm_auth_client.login("admin", "admin123") is False
    assert "http://localhost:8080/account/2fa" in capsys.readouterr().out
    assert not farm_auth_client.is_authenticated()
