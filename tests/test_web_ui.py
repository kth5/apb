"""Tests for the server-rendered web UI: templates, escaping, form auth and CSRF."""

from __future__ import annotations

import re
import time
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apb.multipart_compat import install_multipart_compat

install_multipart_compat()

from apb.farm import core
from apb.server import routes as server_routes
from apb.web import STATIC_CACHE_CONTROL, mount_static
from mfa_support import api_token, enroll_totp, web_login

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
XSS = "<script>alert(1)</script>"
ESCAPED_XSS = "&lt;script&gt;alert(1)&lt;/script&gt;"
CSRF_META = re.compile(r'<meta name="csrf-token" content="([0-9a-f]+)">')


def _insert_build(db, *, pkgname: str, status: str, user_id: int = 1) -> str:
    build_id = str(uuid.uuid4())
    now = time.time()
    db.execute(
        "INSERT INTO builds (id, server_url, server_arch, pkgname, status, start_time, created_at, user_id, pkgver, pkgrel) "
        "VALUES (?, NULL, 'x86_64', ?, ?, ?, ?, ?, '1.0', '1')",
        (build_id, pkgname, status, now, now, user_id),
    )
    db.commit()
    return build_id


@pytest.fixture(autouse=True)
def admin_totp(request: pytest.FixtureRequest):
    """Admins must use 2FA; give the default admin an authenticator app for farm tests."""
    if "farm_client" in request.fixturenames:
        request.getfixturevalue("farm_client")
        enroll_totp(core.auth_manager.db, 1)


@pytest.fixture
def server_client(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setattr(server_routes.engine, "active_builds", {})
    monkeypatch.setattr(server_routes.engine, "build_history", {})
    monkeypatch.setitem(server_routes.engine.server_config, "builds_dir", str(tmp_path))
    app = FastAPI()
    mount_static(app)
    app.include_router(server_routes.router)
    return TestClient(app)


def _login(client: TestClient, username: str = ADMIN_USERNAME, password: str = ADMIN_PASSWORD):
    return web_login(client, core.auth_manager.db, username, password)


def _csrf_token(client: TestClient) -> str:
    match = CSRF_META.search(client.get("/account").text)
    assert match, "account page must expose the CSRF token"
    return match.group(1)


@pytest.mark.parametrize("path", ["/dashboard", "/dashboard/builds", "/login"])
def test_public_pages_render(farm_client: TestClient, path: str):
    response = farm_client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<!DOCTYPE html>" in response.text
    assert "/static/style.css?v=" in response.text


def test_static_assets_are_cacheable(farm_client: TestClient):
    response = farm_client.get("/static/style.css")

    assert response.status_code == 200
    assert response.headers["cache-control"] == STATIC_CACHE_CONTROL


def test_dashboard_renders_only_active_tab(farm_client: TestClient):
    _insert_build(core.build_database, pkgname="vim", status="completed")

    servers = farm_client.get("/dashboard").text
    builds = farm_client.get("/dashboard/builds").text

    assert 'href="/dashboard/builds"' in servers
    assert "No build servers are available." in servers
    assert "vim (1.0-1)" not in servers
    assert "vim (1.0-1)" in builds
    assert "No build servers are available." not in builds
    assert 'href="/dashboard/builds" aria-current="page"' in builds


def test_statistics_tab_requires_login(farm_client: TestClient):
    assert 'href="/dashboard/statistics"' not in farm_client.get("/dashboard").text

    _login(farm_client)

    assert 'href="/dashboard/statistics"' in farm_client.get("/dashboard").text
    assert farm_client.get("/dashboard/statistics").status_code == 200


def test_build_status_page_escapes_package_name(farm_client: TestClient):
    build_id = _insert_build(core.build_database, pkgname=XSS, status="queued")

    response = farm_client.get(f"/build/{build_id}/status")

    assert response.status_code == 200
    assert XSS not in response.text
    assert ESCAPED_XSS in response.text
    assert 'data-poll="' in response.text
    assert '<noscript><meta http-equiv="refresh"' in response.text


def test_unknown_build_status_escapes_build_id(farm_client: TestClient):
    response = farm_client.get("/build/%3Cimg%20src=x%20onerror=alert(1)%3E/status")

    assert response.status_code == 404
    assert "<img src=x" not in response.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in response.text


def test_build_status_json_is_unchanged(farm_client: TestClient):
    response = farm_client.get(f"/build/{uuid.uuid4()}/status", params={"format": "json"})

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")


def test_admin_page_escapes_usernames(farm_client: TestClient):
    core.auth_manager.create_user(XSS, "password123", core.UserRole.USER, "evil@example.com")
    _login(farm_client)

    response = farm_client.get("/admin")

    assert response.status_code == 200
    assert XSS not in response.text
    assert ESCAPED_XSS in response.text


def test_admin_page_redirects_or_forbids(farm_client: TestClient):
    response = farm_client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    core.auth_manager.create_user("bob", "password123", core.UserRole.USER)
    _login(farm_client, "bob", "password123")

    assert farm_client.get("/admin").status_code == 403


def test_login_form_sets_httponly_cookie(farm_client: TestClient):
    response = _login(farm_client)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{core.AUTH_COOKIE_NAME}=")
    assert "HttpOnly" in cookie
    assert "samesite=lax" in cookie.lower()
    assert "Log out" in farm_client.get("/dashboard").text


def test_login_form_rejects_bad_credentials(farm_client: TestClient):
    response = _login(farm_client, ADMIN_USERNAME, "wrong")

    assert response.status_code == 401
    assert "Invalid username or password" in response.text
    assert "set-cookie" not in response.headers


def test_logout_form_requires_csrf(farm_client: TestClient):
    _login(farm_client)

    rejected = farm_client.post("/logout", follow_redirects=False)
    assert rejected.status_code == 403
    assert "Log out" in farm_client.get("/dashboard").text

    accepted = farm_client.post("/logout", data={"csrf_token": _csrf_token(farm_client)}, follow_redirects=False)
    assert accepted.status_code == 303
    assert "Log in" in farm_client.get("/dashboard").text
    assert farm_client.get("/account", follow_redirects=False).status_code == 303


def test_password_change_form(farm_client: TestClient):
    _login(farm_client)
    token = _csrf_token(farm_client)

    mismatch = farm_client.post(
        "/account/password",
        data={"csrf_token": token, "current_password": ADMIN_PASSWORD, "new_password": "newpassword1", "confirm_password": "other"},
    )
    assert mismatch.status_code == 400

    changed = farm_client.post(
        "/account/password",
        data={"csrf_token": token, "current_password": ADMIN_PASSWORD, "new_password": "newpassword1", "confirm_password": "newpassword1"},
    )
    assert changed.status_code == 200
    assert "Password changed" in changed.text

    assert _login(farm_client, ADMIN_USERNAME, ADMIN_PASSWORD).status_code == 401
    assert _login(farm_client, ADMIN_USERNAME, "newpassword1").status_code == 303


def test_cookie_post_without_csrf_is_rejected(farm_client: TestClient):
    _login(farm_client)

    response = farm_client.post(
        "/account/password",
        data={"current_password": ADMIN_PASSWORD, "new_password": "newpassword1", "confirm_password": "newpassword1"},
    )

    assert response.status_code == 403
    assert _login(farm_client, ADMIN_USERNAME, ADMIN_PASSWORD).status_code == 303


def test_bearer_requests_skip_csrf(farm_client: TestClient):
    token = api_token(farm_client, core.auth_manager.db, ADMIN_USERNAME, ADMIN_PASSWORD)

    response = farm_client.post(
        "/admin/repositories",
        headers={"Authorization": f"Bearer {token}"},
        data={"name": "myrepo", "url": "https://repo.example.com/$arch", "gpg_key_id": "ABCDEF"},
    )

    assert response.status_code == 200


def test_cancel_form_renders_html_error(farm_client: TestClient):
    _login(farm_client)
    build_id = str(uuid.uuid4())

    response = farm_client.post(f"/build/{build_id}/cancel", data={"csrf_token": _csrf_token(farm_client)})

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "Cancel failed" in response.text


def test_server_build_page_renders(server_client: TestClient):
    build_id = str(uuid.uuid4())
    server_routes.engine.build_history[build_id] = {
        "build_id": build_id,
        "pkgname": XSS,
        "status": "completed",
        "created_at": time.time(),
        "end_time": time.time(),
        "duration": 12,
        "exit_code": 0,
        "packages": [{"filename": "a.pkg.tar.zst", "size": 1024, "download_url": f"/build/{build_id}/download/a.pkg.tar.zst"}],
        "logs": [],
    }

    response = server_client.get(f"/build/{build_id}")

    assert response.status_code == 200
    assert ESCAPED_XSS in response.text
    assert XSS not in response.text
    assert "a.pkg.tar.zst" in response.text
    assert "data-poll" not in response.text.split("<main", 1)[1].split(">", 1)[0]


def test_server_confirm_cancel_and_cleanup_pages(server_client: TestClient):
    build_id = str(uuid.uuid4())
    server_routes.engine.active_builds[build_id] = {"build_id": build_id, "pkgname": "vim", "status": "building", "created_at": time.time()}

    assert server_client.get(f"/build/{build_id}/confirm-cancel").status_code == 200
    assert server_client.get(f"/build/{uuid.uuid4()}/confirm-cancel").status_code == 404
    assert server_client.get("/admin/cleanup").status_code == 200


def test_server_file_view_escapes_content(server_client: TestClient, tmp_path):
    build_id = str(uuid.uuid4())
    (tmp_path / build_id).mkdir()
    (tmp_path / build_id / "build.log").write_text(XSS, encoding="utf-8")

    response = server_client.get(f"/build/{build_id}/view/build.log")

    assert response.status_code == 200
    assert ESCAPED_XSS in response.text
    assert XSS not in response.text
