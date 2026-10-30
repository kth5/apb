"""Tests for TOTP secret encryption at rest: keyring file, AES-GCM values, startup migration, rotation and missing keys."""

from __future__ import annotations

import logging
import stat
import time
from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient

from apb.farm import core, mfa
from apb.farm.secret_store import (
    EMPTY_KEYRING,
    decrypt_value,
    encrypt_value,
    generate_keyring,
    is_legacy_plaintext,
    load_keyring,
    new_key_line,
    parse_keyring,
    stored_key_id,
)
from mfa_support import stored_totp_secret


@pytest.fixture
def db(farm_client: TestClient):
    return core.auth_manager.db


@pytest.fixture
def bob_id(farm_client: TestClient) -> int:
    return core.auth_manager.create_user("bob", "password123", core.UserRole.USER).id


def _stored(db, user_id: int) -> str:
    return db.execute("SELECT secret FROM user_totp WHERE user_id = ?", (user_id,)).fetchone()[0]


def _insert_plaintext_totp(db, user_id: int, secret: str) -> None:
    db.execute(
        "INSERT INTO user_totp (user_id, secret, confirmed, last_used_step, created_at) VALUES (?, ?, 1, 0, ?)",
        (user_id, secret, time.time()),
    )
    db.commit()


# Values

def test_encrypted_value_round_trips_and_is_bound_to_aad():
    keyring = generate_keyring()
    stored = encrypt_value(keyring, "JBSWY3DPEHPK3PXP", "apb-totp:2")

    assert "JBSWY3DPEHPK3PXP" not in stored
    assert stored_key_id(stored) == keyring.active_id
    assert decrypt_value(keyring, stored, "apb-totp:2") == "JBSWY3DPEHPK3PXP"
    assert decrypt_value(keyring, stored, "apb-totp:3") is None
    assert decrypt_value(generate_keyring(), stored, "apb-totp:2") is None
    assert decrypt_value(keyring, stored[:-2] + ("AA" if stored[-2:] != "AA" else "BB"), "apb-totp:2") is None


def test_encrypt_without_key_raises():
    with pytest.raises(ValueError):
        encrypt_value(EMPTY_KEYRING, "secret", "aad")


def test_parse_keyring_uses_last_key_and_rejects_bad_lines():
    first, second = new_key_line(), new_key_line()
    keyring = parse_keyring(f"# comment\n{first}\n\n{second}\n")

    assert keyring.active_id == second.split()[0]
    assert set(keyring.keys) == {first.split()[0], second.split()[0]}
    for bad in ("onlyid", "bad:id abc", f"{first}\n{first}", "kid c2hvcnQ"):
        with pytest.raises(ValueError):
            parse_keyring(bad)


# Keyring file

def test_load_keyring_generates_private_file(tmp_path: Path):
    path = tmp_path / "keys" / "farm-totp.keys"

    keyring = load_keyring(path)

    assert keyring.is_usable
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_keyring(path) == keyring


def test_load_keyring_warns_about_readable_file(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    path = tmp_path / "farm-totp.keys"
    path.write_text(new_key_line() + "\n")
    path.chmod(0o644)

    with caplog.at_level(logging.WARNING):
        assert load_keyring(path).is_usable
    assert "accessible by group or others" in caplog.text


def test_load_keyring_with_broken_file_is_empty(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    path = tmp_path / "farm-totp.keys"
    path.write_text("not a key file\n")
    path.chmod(0o600)

    with caplog.at_level(logging.ERROR):
        assert not load_keyring(path).is_usable
    assert "authenticator app logins are disabled" in caplog.text


# Storage and migration

def test_enrollment_stores_encrypted_secret(db, bob_id: int):
    secret = mfa.start_totp_enrollment(db, core.auth_manager.keyring, bob_id)

    stored = _stored(db, bob_id)
    assert not is_legacy_plaintext(stored)
    assert secret not in stored
    assert stored_totp_secret(db, bob_id) == secret


def test_secret_copied_to_other_user_does_not_verify(db, bob_id: int):
    keyring = core.auth_manager.keyring
    secret = mfa.start_totp_enrollment(db, keyring, 1)
    _insert_plaintext_totp(db, bob_id, _stored(db, 1))

    assert not mfa.verify_totp(db, keyring, bob_id, pyotp.TOTP(secret).now())


def test_startup_encrypts_plaintext_secrets(db, bob_id: int):
    secret = pyotp.random_base32()
    _insert_plaintext_totp(db, bob_id, secret)

    auth_manager = core.AuthManager(db, keyring=core.auth_manager.keyring)

    assert is_legacy_plaintext(_stored(db, bob_id)) is False
    assert mfa.verify_totp(db, auth_manager.keyring, bob_id, pyotp.TOTP(secret).now())


def test_startup_reencrypts_with_appended_key(db, bob_id: int, tmp_path: Path):
    path = tmp_path / "farm-totp.keys"
    old_keyring = load_keyring(path)
    secret = mfa.start_totp_enrollment(db, old_keyring, bob_id)
    with path.open("a") as keyring_file:
        keyring_file.write(new_key_line() + "\n")
    new_keyring = load_keyring(path)

    counts = mfa.migrate_totp_secrets(db, new_keyring)

    assert counts == {"encrypted": 0, "reencrypted": 1, "undecryptable": 0}
    assert stored_key_id(_stored(db, bob_id)) == new_keyring.active_id != old_keyring.active_id
    assert mfa.pending_totp_secret(db, new_keyring, bob_id) == secret
    assert mfa.migrate_totp_secrets(db, new_keyring) == {"encrypted": 0, "reencrypted": 0, "undecryptable": 0}


def test_unknown_key_is_reported_and_left_alone(db, bob_id: int, caplog: pytest.LogCaptureFixture):
    mfa.start_totp_enrollment(db, generate_keyring(), bob_id)
    stored = _stored(db, bob_id)

    with caplog.at_level(logging.ERROR):
        counts = mfa.migrate_totp_secrets(db, core.auth_manager.keyring)

    assert counts["undecryptable"] == 1
    assert _stored(db, bob_id) == stored
    assert "cannot be decrypted" in caplog.text


# Missing key fallback

def test_without_key_totp_fails_but_recovery_codes_work(farm_client: TestClient, db, bob_id: int):
    keyring = core.auth_manager.keyring
    secret = mfa.start_totp_enrollment(db, keyring, bob_id)
    assert mfa.verify_totp(db, keyring, bob_id, pyotp.TOTP(secret).now(), confirm=True)
    db.execute("UPDATE user_totp SET last_used_step = 0 WHERE user_id = ?", (bob_id,))
    codes = mfa.generate_recovery_codes(db, bob_id)

    core.auth_manager.keyring = EMPTY_KEYRING

    assert mfa.migrate_totp_secrets(db, EMPTY_KEYRING)["undecryptable"] == 1
    assert not mfa.verify_totp(db, EMPTY_KEYRING, bob_id, pyotp.TOTP(secret).now())
    with pytest.raises(ValueError):
        mfa.start_totp_enrollment(db, EMPTY_KEYRING, 1)
    assert mfa.consume_recovery_code(db, bob_id, codes[0])

    token = farm_client.post("/auth/login", json={"username": "bob", "password": "password123"}).json()["mfa_token"]
    response = farm_client.post("/auth/login/2fa", json={"mfa_token": token, "method": "recovery", "code": codes[1]})
    assert response.status_code == 200
    assert mfa.remove_totp(db, bob_id)
    started = farm_client.post("/auth/my/2fa/totp", headers={"Authorization": f"Bearer {response.json()['token']}"})
    assert started.status_code == 400
    assert "unavailable" in started.json()["detail"]
