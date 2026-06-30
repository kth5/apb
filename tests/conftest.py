"""Shared pytest fixtures for APB integration tests."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from apb.client.auth import APBAuthClient

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"

PACKAGE_FILES = (
    "PKGBUILD",
    "pyproject.toml",
    "apb.json.example",
    "apb.sysusers",
    "apb.tmpfiles",
    "apb.sudoers",
    "apb.install",
)
PACKAGE_DIRS = ("src",)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_health(url: str, timeout: float = 120.0) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            response = httpx.get(f"{url}/health", timeout=2.0)
            if response.status_code == 200:
                return
        except httpx.HTTPError as exc:
            last_error = exc
        time.sleep(0.5)
    raise TimeoutError(f"Service at {url} did not become healthy: {last_error}")


def integration_skip_reason() -> str | None:
    if sys.platform != "linux":
        return "APB package integration tests require Linux with Arch build tools"
    if shutil.which("makechrootpkg") is None:
        return "makechrootpkg not found"
    if shutil.which("sudo") is None:
        return "sudo not found"
    if os.environ.get("APB_INTEGRATION") != "1":
        return "set APB_INTEGRATION=1 to run APB package integration tests"
    sudo_check = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if sudo_check.returncode != 0:
        return "passwordless sudo is required (configure NOPASSWD or run interactively with APB_INTEGRATION=1)"
    return None


def stage_apb_package(staging_dir: Path) -> Path:
    staging_dir.mkdir(parents=True, exist_ok=True)
    for name in PACKAGE_FILES:
        shutil.copy2(REPO_ROOT / name, staging_dir / name)
    for name in PACKAGE_DIRS:
        destination = staging_dir / name
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(REPO_ROOT / name, destination)
    return staging_dir


def login_farm_user(farm_url: str, auth_path: Path, username: str = "admin", password: str = "admin123") -> APBAuthClient:
    auth_client = APBAuthClient(farm_url, config_path=auth_path)
    response = httpx.post(
        f"{farm_url}/auth/login",
        json={"username": username, "password": password},
        timeout=30.0,
    )
    response.raise_for_status()
    auth_client._save_token(response.json()["token"])
    return auth_client


@dataclass
class ApbIntegrationEnv:
    home: Path
    server_url: str
    farm_url: str
    output_dir: Path
    build_path: Path
    auth_client: APBAuthClient


@pytest.fixture(scope="session")
def integration_available() -> None:
    reason = integration_skip_reason()
    if reason:
        pytest.skip(reason)


@pytest.fixture
def apb_integration(tmp_path: Path, integration_available: None) -> ApbIntegrationEnv:
    home = tmp_path / "home"
    home.mkdir()
    buildroot = tmp_path / "buildroot"
    builds_dir = tmp_path / "builds"
    output_dir = tmp_path / "output"
    build_path = stage_apb_package(tmp_path / "apb-package")
    auth_path = home / ".apb" / "auth.json"

    server_port = find_free_port()
    farm_port = find_free_port()
    server_url = f"http://127.0.0.1:{server_port}"
    farm_url = f"http://127.0.0.1:{farm_port}"

    config_path = tmp_path / "apb.json"
    config_path.write_text(
        json.dumps(
            {
                "servers": {
                    "x86_64": [server_url],
                    "any": [server_url],
                },
                "default_server": server_url,
                "default_arch": "x86_64",
                "output_dir": str(output_dir),
                "farm_url": farm_url,
            }
        ),
        encoding="utf-8",
    )

    env = {
        **os.environ,
        "HOME": str(home),
        "PYTHONPATH": str(SRC_ROOT),
    }

    server_cmd = [
        sys.executable,
        "-c",
        (
            "import sys; "
            f"sys.argv = ['apb-server', '--host', '127.0.0.1', '--port', '{server_port}', "
            f"'--buildroot', '{buildroot}', '--builds-dir', '{builds_dir}']; "
            "from apb.server.cli import main; main()"
        ),
    ]
    farm_cmd = [
        sys.executable,
        "-c",
        (
            "import sys; "
            f"sys.argv = ['apb-farm', '--host', '127.0.0.1', '--port', '{farm_port}', "
            f"'--config', '{config_path}', '--log-level', 'WARNING']; "
            "from apb.farm.cli import main; main()"
        ),
    ]

    server_log = tmp_path / "server.log"
    farm_log = tmp_path / "farm.log"
    server_proc = subprocess.Popen(
        server_cmd,
        env=env,
        stdout=server_log.open("w"),
        stderr=subprocess.STDOUT,
    )
    farm_proc = subprocess.Popen(
        farm_cmd,
        env=env,
        stdout=farm_log.open("w"),
        stderr=subprocess.STDOUT,
    )

    try:
        wait_for_health(server_url, timeout=300.0)
        wait_for_health(farm_url, timeout=60.0)
        auth_client = login_farm_user(farm_url, auth_path)
        yield ApbIntegrationEnv(
            home=home,
            server_url=server_url,
            farm_url=farm_url,
            output_dir=output_dir,
            build_path=build_path,
            auth_client=auth_client,
        )
    except Exception as exc:
        details = [str(exc)]
        for log_path in (server_log, farm_log):
            if log_path.exists():
                details.append(f"{log_path.name}:\n{log_path.read_text()}")
        pytest.fail("\n\n".join(details))
    finally:
        for proc in (farm_proc, server_proc):
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
