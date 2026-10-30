"""Tests for farm two-factor authentication: TOTP, recovery codes, security keys, scoped tokens and admin policy."""

from __future__ import annotations

import json
import time
from typing import Dict, List, Tuple

import pyotp
import pytest
from fastapi.testclient import TestClient

from apb.farm import core, mfa
from mfa_support import SoftSecurityKey, api_token, csrf_from_html, enroll_totp, fresh_totp_code

ADMIN = ("admin", "admin123")
BOB = ("bob", "password123")


@pytest.fixture
def db(farm_client: TestClient):
    return core.auth_manager.db


@pytest.fixture
def bob_id(farm_client: TestClient) -> int:
    return core.auth_manager.create_user(*BOB, core.UserRole.USER).id


def _bearer(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _login(client: TestClient, credentials: Tuple[str, str]) -> dict:
    response = client.post("/auth/login", json={"username": credentials[0], "password": credentials[1]})
    assert response.status_code == 200, response.text
    return response.json()


def _enroll_totp_via_api(client: TestClient, token: str) -> Tuple[pyotp.TOTP, dict]:
    secret = client.post("/auth/my/2fa/totp", headers=_bearer(token)).json()["secret"]
    totp = pyotp.TOTP(secret)
    response = client.post("/auth/my/2fa/totp/confirm", headers=_bearer(token), json={"code": totp.now()})
    assert response.status_code == 200, response.text
    return totp, response.json()


def _register_key_via_api(client: TestClient, token: str, key: SoftSecurityKey, name: str = "YubiKey") -> dict:
    options = client.post("/auth/my/2fa/webauthn/register-options", headers=_bearer(token)).json()
    response = client.post(
        "/auth/my/2fa/webauthn", headers=_bearer(token), json={"name": name, "credential": key.register(options)}
    )
    assert response.status_code == 200, response.text
    return response.json()


def _verify(client: TestClient, mfa_token: str, method: str, **payload):
    return client.post("/auth/login/2fa", json={"mfa_token": mfa_token, "method": method, **payload})


def _admin_token(client: TestClient, db) -> str:
    enroll_totp(db, 1)
    return api_token(client, db, *ADMIN)


# Login flow and token scopes

def test_user_without_2fa_logs_in_directly(farm_client: TestClient, bob_id: int):
    data = _login(farm_client, BOB)

    assert data["token"]
    assert data["user"]["mfa_enabled"] is False


def test_admin_without_2fa_only_gets_enrollment_session(farm_client: TestClient):
    data = _login(farm_client, ADMIN)

    assert data["mfa_setup_required"] is True
    assert data["setup_url"] == "http://localhost:8080/account/2fa"
    assert "token" not in data
    setup = _bearer(data["setup_token"])
    assert farm_client.get("/auth/me", headers=setup).status_code == 401
    assert farm_client.get("/auth/users", headers=setup).status_code == 401
    assert farm_client.get("/auth/my/2fa", headers=setup).json()["required"] is True


def test_admin_enrollment_upgrades_setup_session(farm_client: TestClient):
    setup_token = _login(farm_client, ADMIN)["setup_token"]

    _, enrolled = _enroll_totp_via_api(farm_client, setup_token)

    assert len(enrolled["recovery_codes"]) == mfa.RECOVERY_CODE_COUNT
    assert farm_client.get("/auth/me", headers=_bearer(enrolled["token"])).json()["mfa_enabled"] is True
    assert farm_client.get("/auth/my/2fa", headers=_bearer(setup_token)).status_code == 401
    assert _login(farm_client, ADMIN)["mfa_required"] is True


def test_totp_login_rejects_replayed_code(farm_client: TestClient, bob_id: int):
    totp, enrolled = _enroll_totp_via_api(farm_client, _login(farm_client, BOB)["token"])
    assert enrolled["token"] is None

    challenge = _login(farm_client, BOB)
    assert challenge["mfa_required"] is True
    assert challenge["methods"] == ["totp", "recovery"]
    assert farm_client.get("/auth/me", headers=_bearer(challenge["mfa_token"])).status_code == 401

    code = fresh_totp_code(core.auth_manager.db, bob_id)
    response = _verify(farm_client, challenge["mfa_token"], "totp", code=code)
    assert response.status_code == 200
    assert farm_client.get("/auth/me", headers=_bearer(response.json()["token"])).status_code == 200

    assert _verify(farm_client, challenge["mfa_token"], "totp", code=code).status_code == 401
    replay = _verify(farm_client, _login(farm_client, BOB)["mfa_token"], "totp", code=code)
    assert replay.status_code == 401


def test_totp_accepts_adjacent_time_steps_only(farm_client: TestClient, db, bob_id: int):
    keyring = core.auth_manager.keyring
    secret = mfa.start_totp_enrollment(db, keyring, bob_id)
    totp = pyotp.TOTP(secret)
    now = time.time()
    assert mfa.verify_totp(db, keyring, bob_id, totp.at(now - 30), confirm=True, now=now)

    assert not mfa.verify_totp(db, keyring, bob_id, totp.at(now - 90), now=now)
    assert mfa.verify_totp(db, keyring, bob_id, totp.at(now + 30), now=now)
    assert not mfa.verify_totp(db, keyring, bob_id, totp.at(now), now=now)


def test_pending_login_is_revoked_after_too_many_attempts(farm_client: TestClient, bob_id: int):
    _enroll_totp_via_api(farm_client, _login(farm_client, BOB)["token"])
    mfa_token = _login(farm_client, BOB)["mfa_token"]

    for _ in range(mfa.MFA_MAX_ATTEMPTS):
        assert _verify(farm_client, mfa_token, "totp", code="000000").status_code == 401

    response = _verify(farm_client, mfa_token, "totp", code=fresh_totp_code(core.auth_manager.db, bob_id))
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]


def test_pending_login_expires(farm_client: TestClient, db, bob_id: int):
    _enroll_totp_via_api(farm_client, _login(farm_client, BOB)["token"])
    mfa_token = _login(farm_client, BOB)["mfa_token"]
    db.execute("UPDATE tokens SET expires_at = ? WHERE scope = ?", (time.time() - 1, mfa.TOKEN_SCOPE_MFA_PENDING))
    db.commit()

    assert _verify(farm_client, mfa_token, "totp", code=fresh_totp_code(db, bob_id)).status_code == 401


def test_unenrolled_method_and_missing_code_are_rejected(farm_client: TestClient, bob_id: int):
    _enroll_totp_via_api(farm_client, _login(farm_client, BOB)["token"])
    mfa_token = _login(farm_client, BOB)["mfa_token"]

    assert _verify(farm_client, mfa_token, "webauthn", credential={}).status_code == 400
    assert _verify(farm_client, mfa_token, "totp").status_code == 400
    assert farm_client.post("/auth/login/2fa/webauthn-options", json={"mfa_token": mfa_token}).status_code == 400


def test_recovery_codes_work_once(farm_client: TestClient, bob_id: int):
    _, enrolled = _enroll_totp_via_api(farm_client, _login(farm_client, BOB)["token"])
    code = enrolled["recovery_codes"][0].upper().replace("-", " ")

    assert _verify(farm_client, _login(farm_client, BOB)["mfa_token"], "recovery", code=code).status_code == 200
    assert _verify(farm_client, _login(farm_client, BOB)["mfa_token"], "recovery", code=code).status_code == 401
    assert mfa.recovery_codes_remaining(core.auth_manager.db, bob_id) == mfa.RECOVERY_CODE_COUNT - 1


def test_recovery_code_regeneration_requires_password(farm_client: TestClient, bob_id: int):
    token = _login(farm_client, BOB)["token"]
    _, enrolled = _enroll_totp_via_api(farm_client, token)
    old_code = enrolled["recovery_codes"][0]

    wrong = farm_client.post("/auth/my/2fa/recovery-codes", headers=_bearer(token), json={"password": "nope"})
    assert wrong.status_code == 400
    regenerated = farm_client.post("/auth/my/2fa/recovery-codes", headers=_bearer(token), json={"password": BOB[1]})
    assert len(regenerated.json()["recovery_codes"]) == mfa.RECOVERY_CODE_COUNT
    assert _verify(farm_client, _login(farm_client, BOB)["mfa_token"], "recovery", code=old_code).status_code == 401


# Security keys

def test_security_key_registration_and_login(farm_client: TestClient, bob_id: int):
    key = SoftSecurityKey()
    enrolled = _register_key_via_api(farm_client, _login(farm_client, BOB)["token"], key)
    assert len(enrolled["recovery_codes"]) == mfa.RECOVERY_CODE_COUNT

    challenge = _login(farm_client, BOB)
    assert challenge["methods"] == ["webauthn", "recovery"]
    options = farm_client.post("/auth/login/2fa/webauthn-options", json={"mfa_token": challenge["mfa_token"]}).json()
    assert options["publicKey"]["rpId"] == "localhost"
    assertion = key.authenticate(options)

    response = _verify(farm_client, challenge["mfa_token"], "webauthn", credential=assertion)
    assert response.status_code == 200
    keys = farm_client.get("/auth/my/2fa", headers=_bearer(response.json()["token"])).json()["security_keys"]
    assert keys[0]["name"] == "YubiKey" and keys[0]["last_used_at"]


def test_security_key_rejects_replay_wrong_origin_and_clones(farm_client: TestClient, bob_id: int):
    key = SoftSecurityKey()
    _register_key_via_api(farm_client, _login(farm_client, BOB)["token"], key)

    def attempt(signing_key: SoftSecurityKey, assertion=None):
        mfa_token = _login(farm_client, BOB)["mfa_token"]
        options = farm_client.post("/auth/login/2fa/webauthn-options", json={"mfa_token": mfa_token}).json()
        credential = assertion or signing_key.authenticate(options)
        return _verify(farm_client, mfa_token, "webauthn", credential=credential), credential

    accepted, used_assertion = attempt(key)
    assert accepted.status_code == 200
    assert attempt(key, used_assertion)[0].status_code == 401

    phishing = SoftSecurityKey(origin="https://evil.example")
    phishing.private_key, phishing.credential_id, phishing.counter = key.private_key, key.credential_id, key.counter
    assert attempt(phishing)[0].status_code == 401

    key.counter = 0
    assert attempt(key)[0].status_code == 401


def test_security_key_cannot_be_registered_twice(farm_client: TestClient, bob_id: int):
    token = _login(farm_client, BOB)["token"]
    key = SoftSecurityKey()
    _register_key_via_api(farm_client, token, key)

    options = farm_client.post("/auth/my/2fa/webauthn/register-options", headers=_bearer(token)).json()
    assert options["publicKey"]["excludeCredentials"]
    duplicate = farm_client.post(
        "/auth/my/2fa/webauthn", headers=_bearer(token), json={"name": "again", "credential": key.register(options)}
    )
    assert duplicate.status_code == 400


# Removal, admin policy and reset

def test_removing_last_factor_disables_2fa_for_users(farm_client: TestClient, db, bob_id: int):
    token = _login(farm_client, BOB)["token"]
    _enroll_totp_via_api(farm_client, token)

    wrong = farm_client.request("DELETE", "/auth/my/2fa/totp", headers=_bearer(token), json={"password": "nope"})
    assert wrong.status_code == 400
    removed = farm_client.request("DELETE", "/auth/my/2fa/totp", headers=_bearer(token), json={"password": BOB[1]})
    assert removed.status_code == 200
    assert mfa.recovery_codes_remaining(db, bob_id) == 0
    assert "token" in _login(farm_client, BOB)


def test_admin_must_keep_one_factor(farm_client: TestClient):
    token = _admin_token(farm_client, core.auth_manager.db)

    last = farm_client.request("DELETE", "/auth/my/2fa/totp", headers=_bearer(token), json={"password": ADMIN[1]})
    assert last.status_code == 400

    _register_key_via_api(farm_client, token, SoftSecurityKey())
    assert farm_client.request("DELETE", "/auth/my/2fa/totp", headers=_bearer(token), json={"password": ADMIN[1]}).status_code == 200
    key_id = farm_client.get("/auth/my/2fa", headers=_bearer(token)).json()["security_keys"][0]["id"]
    remove_key = farm_client.request("DELETE", f"/auth/my/2fa/webauthn/{key_id}", headers=_bearer(token), json={"password": ADMIN[1]})
    assert remove_key.status_code == 400
    missing = farm_client.request("DELETE", "/auth/my/2fa/webauthn/999", headers=_bearer(token), json={"password": ADMIN[1]})
    assert missing.status_code == 404


def test_admin_reset_removes_factors_and_sessions(farm_client: TestClient, db, bob_id: int):
    admin_token = _admin_token(farm_client, db)
    bob_token = _login(farm_client, BOB)["token"]
    _enroll_totp_via_api(farm_client, bob_token)
    _register_key_via_api(farm_client, bob_token, SoftSecurityKey())
    users: List[dict] = farm_client.get("/auth/users", headers=_bearer(admin_token)).json()
    assert {user["username"]: user["mfa_enabled"] for user in users} == {"admin": True, "bob": True}

    assert farm_client.delete("/auth/users/1/2fa", headers=_bearer(admin_token)).status_code == 400
    assert farm_client.delete("/auth/users/999/2fa", headers=_bearer(admin_token)).status_code == 404
    response = farm_client.delete(f"/auth/users/{bob_id}/2fa", headers=_bearer(admin_token))

    assert response.status_code == 200
    assert farm_client.get("/auth/me", headers=_bearer(bob_token)).status_code == 401
    assert not mfa.has_second_factor(db, bob_id) and mfa.recovery_codes_remaining(db, bob_id) == 0
    assert "token" in _login(farm_client, BOB)
    assert farm_client.delete(f"/auth/users/{bob_id}/2fa", headers=_bearer(bob_token)).status_code == 401


def test_promotion_to_admin_without_2fa_ends_sessions(farm_client: TestClient, db, bob_id: int):
    admin_token = _admin_token(farm_client, db)
    bob_token = _login(farm_client, BOB)["token"]

    response = farm_client.put(f"/auth/users/{bob_id}/role", headers=_bearer(admin_token), json={"role": "admin"})

    assert response.status_code == 200
    assert farm_client.get("/auth/me", headers=_bearer(bob_token)).status_code == 401
    assert _login(farm_client, BOB)["mfa_setup_required"] is True


def test_full_sessions_renew_but_pending_ones_do_not(farm_client: TestClient, db, bob_id: int):
    _enroll_totp_via_api(farm_client, _login(farm_client, BOB)["token"])
    mfa_token = _login(farm_client, BOB)["mfa_token"]
    expires_before = db.execute("SELECT expires_at FROM tokens WHERE scope = ?", (mfa.TOKEN_SCOPE_MFA_PENDING,)).fetchone()[0]

    core.auth_manager.validate_token(mfa_token, (mfa.TOKEN_SCOPE_MFA_PENDING,))

    expires_after = db.execute("SELECT expires_at FROM tokens WHERE scope = ?", (mfa.TOKEN_SCOPE_MFA_PENDING,)).fetchone()[0]
    assert expires_after == expires_before
    assert expires_before - time.time() <= mfa.MFA_PENDING_TTL_SECONDS


# Web forms

def test_web_admin_setup_flow(farm_client: TestClient):
    response = farm_client.post("/login", data={"username": ADMIN[0], "password": ADMIN[1]}, follow_redirects=False)
    assert response.headers["location"] == "/account/2fa"

    page = farm_client.get("/account/2fa")
    assert "Administrators must use two-factor authentication" in page.text
    assert farm_client.get("/admin", follow_redirects=False).headers["location"] == "/login"

    csrf_token = csrf_from_html(page.text)
    started = farm_client.post("/account/2fa/totp", data={"csrf_token": csrf_token}, follow_redirects=False)
    assert started.headers["location"] == "/account/2fa/totp"
    totp_page = farm_client.get("/account/2fa/totp")
    assert "<svg" in totp_page.text
    secret = mfa.pending_totp_secret(core.auth_manager.db, core.auth_manager.keyring, 1)
    assert secret in totp_page.text

    wrong = farm_client.post("/account/2fa/totp/confirm", data={"csrf_token": csrf_token, "code": "000000"})
    assert wrong.status_code == 400
    confirmed = farm_client.post("/account/2fa/totp/confirm", data={"csrf_token": csrf_token, "code": pyotp.TOTP(secret).now()})

    assert confirmed.status_code == 200
    assert "Your recovery codes" in confirmed.text
    assert "Administrators must use" not in confirmed.text
    assert farm_client.get("/admin").status_code == 200


def test_web_login_with_totp_wrong_codes_and_lockout(farm_client: TestClient, db):
    enroll_totp(db, 1)
    response = farm_client.post("/login", data={"username": ADMIN[0], "password": ADMIN[1]}, follow_redirects=False)
    assert response.headers["location"] == "/login/2fa"
    assert "apbMfa=" in response.headers["set-cookie"]
    assert farm_client.get("/dashboard").text.count("Log out") == 0

    csrf_token = csrf_from_html(farm_client.get("/login/2fa").text)
    assert farm_client.post("/login/2fa", data={"method": "totp", "code": "000000"}).status_code == 403
    for _ in range(mfa.MFA_MAX_ATTEMPTS - 1):
        wrong = farm_client.post("/login/2fa", data={"csrf_token": csrf_token, "method": "totp", "code": "000000"})
        assert wrong.status_code == 401
        assert "Invalid code" in wrong.text
    locked = farm_client.post("/login/2fa", data={"csrf_token": csrf_token, "method": "totp", "code": "000000"})

    assert locked.status_code == 401
    assert "Please log in again" in locked.text
    assert farm_client.get("/login/2fa", follow_redirects=False).headers["location"] == "/login"


def test_web_login_with_security_key(farm_client: TestClient, db):
    key = SoftSecurityKey()
    admin_token = _admin_token(farm_client, db)
    _register_key_via_api(farm_client, admin_token, key)
    farm_client.post("/login", data={"username": ADMIN[0], "password": ADMIN[1]}, follow_redirects=False)

    page = farm_client.get("/login/2fa").text
    assert 'data-webauthn="get"' in page
    options = db.execute("SELECT state FROM webauthn_challenges WHERE purpose = 'authenticate'").fetchone()
    assert options
    challenge = json.loads(options[0])["challenge"]
    credential = key.authenticate({"publicKey": {"challenge": challenge}})

    response = farm_client.post(
        "/login/2fa",
        data={"csrf_token": csrf_from_html(page), "method": "webauthn", "credential": json.dumps(credential)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert farm_client.get("/admin").status_code == 200


def test_web_security_key_registration_and_removal(farm_client: TestClient, db, bob_id: int):
    farm_client.post("/login", data={"username": BOB[0], "password": BOB[1]})
    page = farm_client.get("/account/2fa").text
    assert 'data-webauthn="create"' in page
    state = json.loads(db.execute("SELECT state FROM webauthn_challenges WHERE purpose = 'register'").fetchone()[0])
    credential = SoftSecurityKey().register({"publicKey": {"challenge": state["challenge"]}})
    csrf_token = csrf_from_html(page)

    registered = farm_client.post(
        "/account/2fa/webauthn", data={"csrf_token": csrf_token, "name": "Desk key", "credential": json.dumps(credential)}
    )
    assert registered.status_code == 200
    assert "Desk key" in registered.text and "Your recovery codes" in registered.text

    key_id = mfa.list_security_keys(db, bob_id)[0].id
    removed = farm_client.post(f"/account/2fa/webauthn/{key_id}/delete", data={"csrf_token": csrf_token, "password": BOB[1]})
    assert removed.status_code == 200
    assert "Security key removed" in removed.text
    assert not mfa.has_second_factor(db, bob_id)
