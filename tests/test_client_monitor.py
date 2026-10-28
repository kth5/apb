"""Client build submission and the shared monitor poll loop."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from apb.client import cli
from apb.client.api import APBotClient, BuildRejectedError
from apb.constants import BuildStatus
from apb.models import BuildStatusResponse, FarmBuildSubmitResponse


@pytest.fixture(autouse=True)
def fast_polling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "POLL_INTERVAL", 0)
    monkeypatch.setattr(cli, "ERROR_RETRY_INTERVAL", 0)


def _status(status: str, **extra) -> BuildStatusResponse:
    return BuildStatusResponse(build_id="b1", pkgname="hello", status=status, **extra)


def _http_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "http://farm/build/b1/status-api")
    return httpx.HTTPStatusError("error", request=request, response=httpx.Response(status_code, request=request))


def _write_pkgbuild(tmp_path: Path) -> Path:
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text("pkgname=hello\npkgver=1\npkgrel=1\narch=(any)\n", encoding="utf-8")
    return pkg_dir


def test_monitor_build_downloads_after_completion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.get_build_status.side_effect = [
        _status(BuildStatus.QUEUED, queue_state="farm", queue_position=2, farm_queue_size=3),
        _status(BuildStatus.BUILDING),
        _status(BuildStatus.COMPLETED),
    ]
    downloads = []
    monkeypatch.setattr(
        cli,
        "_download_build_artifacts",
        lambda _client, build_id, output_dir, *, arch_prefix="": downloads.append((build_id, output_dir)) or True,
    )

    assert cli.monitor_build("b1", client, tmp_path / "any", arch="any") is True
    assert downloads == [("b1", tmp_path / "any")]


def test_monitor_build_fails_when_download_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.get_build_status.return_value = _status(BuildStatus.COMPLETED)
    monkeypatch.setattr(cli, "_download_build_artifacts", lambda *_args, **_kwargs: False)

    assert cli.monitor_build("b1", client, tmp_path) is False


def test_poll_uses_cached_terminal_status_when_server_stays_unavailable() -> None:
    client = MagicMock()
    client.get_build_status.side_effect = [
        _status(BuildStatus.BUILDING, server_unavailable=True),
    ] * (cli.MAX_SERVER_UNAVAILABLE - 1) + [_status(BuildStatus.COMPLETED, server_unavailable=True)]

    final_status = cli._poll_build(cli.MonitorTarget("b1", client), MagicMock(is_set=lambda: False))

    assert final_status == BuildStatus.COMPLETED


def test_poll_gives_up_on_repeated_server_errors() -> None:
    client = MagicMock()
    client.get_build_status.side_effect = _http_error(503)

    final_status = cli._poll_build(cli.MonitorTarget("b1", client), MagicMock(is_set=lambda: False))

    assert final_status == cli.STATUS_SERVER_UNAVAILABLE
    assert client.get_build_status.call_count == cli.MAX_SERVER_UNAVAILABLE


def test_poll_gives_up_on_repeated_not_found() -> None:
    client = MagicMock()
    client.get_build_status.side_effect = _http_error(404)

    final_status = cli._poll_build(cli.MonitorTarget("b1", client), MagicMock(is_set=lambda: False))

    assert final_status == BuildStatus.FAILED
    assert client.get_build_status.call_count == cli.MAX_STATUS_ERRORS


def test_monitor_builds_runs_targets_in_parallel() -> None:
    clients = {arch: MagicMock() for arch in ("x86_64", "powerpc")}
    clients["x86_64"].get_build_status.return_value = _status(BuildStatus.COMPLETED)
    clients["powerpc"].get_build_status.return_value = _status(BuildStatus.FAILED)
    targets = [cli.MonitorTarget(f"b-{arch}", client, None, arch) for arch, client in clients.items()]

    results = cli.monitor_builds(targets)

    assert results == {
        "b-x86_64": (BuildStatus.COMPLETED, True),
        "b-powerpc": (BuildStatus.FAILED, False),
    }


def test_build_package_returns_farm_response_and_sends_form(tmp_path: Path) -> None:
    pkg_dir = _write_pkgbuild(tmp_path)
    farm_payload = {
        "build_id": "b1",
        "status": "queued",
        "message": "Queued 1 build(s) for processing",
        "pkgname": "hello",
        "target_architectures": ["any"],
        "pkgbuild_architectures": ["any"],
        "builds": [{
            "build_id": "b1", "arch": "any", "status": "queued", "pkgname": "hello",
            "submission_group": "g1", "created_at": 1.0,
        }],
        "submission_group": "g1",
        "created_at": 1.0,
    }
    captured = {}

    def fake_post(url, files=None, data=None):
        captured.update(url=url, data=data, filename=files[0][1][0])
        return httpx.Response(200, json=farm_payload, request=httpx.Request("POST", url))

    with patch("httpx.Client.post", side_effect=fake_post):
        response = APBotClient("http://farm/apb").build_package(
            pkg_dir, architectures=["any"], build_timeout=3600
        )

    assert isinstance(response, FarmBuildSubmitResponse)
    assert [build.arch for build in response.builds] == ["any"]
    assert captured == {
        "url": "http://farm/apb/build",
        "data": {"architectures": "any", "build_timeout": "3600"},
        "filename": "build.tar.gz",
    }


def test_build_package_raises_on_farm_rejection(tmp_path: Path) -> None:
    pkg_dir = _write_pkgbuild(tmp_path)
    payload = {"error": "No builds queued", "message": "No servers available", "available_architectures": []}

    def fake_post(url, files=None, data=None):
        return httpx.Response(200, json=payload, request=httpx.Request("POST", url))

    with patch("httpx.Client.post", side_effect=fake_post), pytest.raises(BuildRejectedError) as exc:
        APBotClient("http://farm").build_package(pkg_dir)

    assert str(exc.value) == "No servers available"
    assert exc.value.detail == payload


def test_build_package_rejects_invalid_timeout(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        APBotClient("http://farm").build_package(_write_pkgbuild(tmp_path), build_timeout=1)


def test_wait_for_farm_artifacts_does_not_wait_on_build_server() -> None:
    client = APBotClient("http://server")
    with patch.object(client, "get_build_status", return_value=_status(BuildStatus.COMPLETED)) as get_status:
        status = client.wait_for_farm_artifacts("b1", timeout=5)

    assert status is not None and status.status == BuildStatus.COMPLETED
    assert get_status.call_count == 1


def test_wait_for_farm_artifacts_waits_for_farm_cache() -> None:
    client = APBotClient("http://farm")
    statuses = [_status(BuildStatus.COMPLETED, artifacts_ready=False), _status(BuildStatus.COMPLETED, artifacts_ready=True)]
    with patch.object(client, "get_build_status", side_effect=statuses):
        status = client.wait_for_farm_artifacts("b1", poll_interval=0)

    assert status is not None and status.artifacts_ready is True
