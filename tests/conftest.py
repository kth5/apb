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


def wait_for_server_buildroot(server_url: str, buildroot: Path, timeout: float = 600.0) -> None:
    """Wait until the server is healthy and its buildroot chroot exists."""
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            health = httpx.get(f"{server_url}/health", timeout=5.0)
            if health.status_code != 200:
                raise httpx.HTTPError(f"health returned {health.status_code}")

            root_path = buildroot / "root"
            if not root_path.is_dir():
                raise FileNotFoundError(f"buildroot not ready: {root_path}")

            info = httpx.get(f"{server_url}/", timeout=5.0)
            info.raise_for_status()
            if not info.json().get("supported_architecture"):
                raise ValueError("server did not report supported_architecture")

            return
        except (httpx.HTTPError, ValueError, FileNotFoundError) as exc:
            last_error = exc
        time.sleep(1.0)
    raise TimeoutError(f"Server buildroot at {buildroot} was not ready: {last_error}")


def wait_for_farm_servers(farm_url: str, timeout: float = 120.0) -> None:
    """Wait until the farm discovers at least one online build server."""
    deadline = time.time() + timeout
    last_payload: dict | None = None
    while time.time() < deadline:
        try:
            response = httpx.get(f"{farm_url}/farm", timeout=5.0)
            if response.status_code == 200:
                payload = response.json()
                last_payload = payload
                available_architectures = payload.get("available_architectures") or []
                online_servers = [
                    server
                    for server in payload.get("servers", [])
                    if server.get("status") == "online"
                ]
                if available_architectures and online_servers:
                    return
        except httpx.HTTPError:
            pass
        time.sleep(1.0)
    pytest.fail(
        "Farm did not discover any online build servers before build submission. "
        f"Last /farm response: {last_payload}"
    )


def wait_for_service(
    proc: subprocess.Popen,
    url: str,
    log_path: Path,
    service_name: str,
    timeout: float = 120.0,
) -> None:
    """Wait for a spawned service to become healthy or fail fast if it exits."""
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        exit_code = proc.poll()
        if exit_code is not None:
            log_text = log_path.read_text(encoding="utf-8") if log_path.exists() else "(no log output)"
            pytest.fail(f"{service_name} exited with code {exit_code} before becoming healthy:\n{log_text}")
        try:
            response = httpx.get(f"{url}/health", timeout=2.0)
            if response.status_code == 200:
                return
        except httpx.HTTPError as exc:
            last_error = exc
        time.sleep(0.5)
    log_text = log_path.read_text(encoding="utf-8") if log_path.exists() else "(no log output)"
    pytest.fail(
        f"{service_name} at {url} did not become healthy within {timeout}s: {last_error}\n{log_text}"
    )


def _multipart_module_path(module_name: str) -> str | None:
    import importlib.util

    spec = importlib.util.find_spec(module_name)
    if spec is None or spec.origin is None:
        return None
    return spec.origin


def runtime_dependency_skip_reason() -> str | None:
    """Verify form upload dependencies used by server and farm routes."""
    try:
        from python_multipart.multipart import parse_options_header

        assert parse_options_header
        return None
    except (ImportError, AssertionError):
        pass

    try:
        from multipart.multipart import parse_options_header

        assert parse_options_header
        return None
    except ImportError:
        pass

    lines = [
        "Form upload support is unavailable in the Python running pytest.",
        f"Python: {sys.executable}",
    ]
    python_multipart_path = _multipart_module_path("python_multipart")
    multipart_path = _multipart_module_path("multipart")
    if python_multipart_path:
        lines.append(f"python_multipart: {python_multipart_path}")
    else:
        lines.append("python_multipart: not found")
    if multipart_path:
        lines.append(f"multipart: {multipart_path}")
    if multipart_path and not python_multipart_path:
        lines.append(
            'The PyPI package "multipart" (not "python-multipart") may be installed, or '
            "python-multipart is too old (<0.0.13)."
        )
    lines.append(
        f"Fix: {sys.executable} -m pip uninstall -y multipart; "
        f"{sys.executable} -m pip install --force-reinstall 'python-multipart>=0.0.20'"
    )
    lines.append(f"Run tests with: {sys.executable} -m pytest")
    return "\n".join(lines)


def integration_skip_reason() -> str | None:
    if sys.platform != "linux":
        return "APB package integration tests require Linux with Arch build tools"
    runtime_reason = runtime_dependency_skip_reason()
    if runtime_reason:
        return runtime_reason
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
    farm_proc: subprocess.Popen | None = None

    try:
        wait_for_service(server_proc, server_url, server_log, "APB Server", timeout=600.0)
        wait_for_server_buildroot(server_url, buildroot, timeout=600.0)

        farm_proc = subprocess.Popen(
            farm_cmd,
            env=env,
            stdout=farm_log.open("w"),
            stderr=subprocess.STDOUT,
        )
        wait_for_service(farm_proc, farm_url, farm_log, "APB Farm", timeout=60.0)
        wait_for_farm_servers(farm_url, timeout=120.0)
        auth_client = login_farm_user(farm_url, auth_path)
        yield ApbIntegrationEnv(
            home=home,
            server_url=server_url,
            farm_url=farm_url,
            output_dir=output_dir,
            build_path=build_path,
            auth_client=auth_client,
        )
    finally:
        for proc in (farm_proc, server_proc):
            if proc is None:
                continue
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
