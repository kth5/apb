"""Test helpers for farm two-factor authentication: TOTP codes, a software security key and full logins."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from typing import Any, Dict

import pyotp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from fido2.cose import ES256
from fido2.utils import websafe_decode
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorData,
    CollectedClientData,
    RegistrationResponse,
)

from apb.farm import mfa

FARM_URL = "http://localhost:8080"
CSRF_INPUT = re.compile(r'name="csrf_token" value="([0-9a-f]+)"')


def enroll_totp(db: sqlite3.Connection, user_id: int) -> pyotp.TOTP:
    """Confirm an authenticator app for the user directly in the database layer."""
    secret = mfa.start_totp_enrollment(db, user_id)
    totp = pyotp.TOTP(secret)
    assert mfa.verify_totp(db, user_id, totp.now(), confirm=True)
    return totp


def fresh_totp_code(db: sqlite3.Connection, user_id: int) -> str:
    """Current code with replay protection reset, for tests that log in more than once per time step."""
    secret = db.execute("SELECT secret FROM user_totp WHERE user_id = ?", (user_id,)).fetchone()[0]
    db.execute("UPDATE user_totp SET last_used_step = 0 WHERE user_id = ?", (user_id,))
    db.commit()
    return pyotp.TOTP(secret).now()


def csrf_from_html(html: str) -> str:
    match = CSRF_INPUT.search(html)
    assert match, "page must contain a csrf_token form field"
    return match.group(1)


class SoftSecurityKey:
    """Minimal software FIDO2 authenticator producing WebAuthn JSON responses like a browser."""

    def __init__(self, origin: str = FARM_URL, rp_id: str = "localhost"):
        self.origin = origin
        self.rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.counter = 0

    def register(self, options: Dict[str, Any]) -> Dict[str, Any]:
        client_data = CollectedClientData.create(
            type=CollectedClientData.TYPE.CREATE,
            challenge=websafe_decode(options["publicKey"]["challenge"]),
            origin=self.origin,
        )
        credential_data = AttestedCredentialData.create(
            Aaguid.NONE, self.credential_id, ES256.from_cryptography_key(self.private_key.public_key())
        )
        auth_data = AuthenticatorData.create(
            self.rp_id_hash, AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT, self.counter, credential_data
        )
        response = RegistrationResponse(
            raw_id=self.credential_id,
            response=AuthenticatorAttestationResponse(
                client_data=client_data, attestation_object=AttestationObject.create("none", auth_data, {})
            ),
        )
        return json.loads(json.dumps(dict(response)))

    def assertion(self, options: Dict[str, Any]) -> AuthenticationResponse:
        self.counter += 1
        client_data = CollectedClientData.create(
            type=CollectedClientData.TYPE.GET,
            challenge=websafe_decode(options["publicKey"]["challenge"]),
            origin=self.origin,
        )
        auth_data = AuthenticatorData.create(self.rp_id_hash, AuthenticatorData.FLAG.UP, self.counter)
        signature = self.private_key.sign(auth_data + client_data.hash, ec.ECDSA(hashes.SHA256()))
        return AuthenticationResponse(
            raw_id=self.credential_id,
            response=AuthenticatorAssertionResponse(
                client_data=client_data, authenticator_data=auth_data, signature=signature
            ),
        )

    def authenticate(self, options: Dict[str, Any]) -> Dict[str, Any]:
        return json.loads(json.dumps(dict(self.assertion(options))))


def web_login(client: TestClient, db: sqlite3.Connection, username: str, password: str):
    """POST /login and, when asked, finish the second step with a fresh TOTP code."""
    response = client.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    if response.headers.get("location") != "/login/2fa":
        return response
    user_id = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
    csrf_token = csrf_from_html(client.get("/login/2fa").text)
    return client.post(
        "/login/2fa",
        data={"csrf_token": csrf_token, "method": "totp", "code": fresh_totp_code(db, user_id)},
        follow_redirects=False,
    )


def api_token(client: TestClient, db: sqlite3.Connection, username: str, password: str) -> str:
    """Full Bearer token through /auth/login and, when asked, /auth/login/2fa with TOTP."""
    data = client.post("/auth/login", json={"username": username, "password": password}).json()
    if not data.get("mfa_required"):
        return data["token"]
    user_id = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
    response = client.post(
        "/auth/login/2fa",
        json={"mfa_token": data["mfa_token"], "method": "totp", "code": fresh_totp_code(db, user_id)},
    )
    assert response.status_code == 200, response.text
    return response.json()["token"]
