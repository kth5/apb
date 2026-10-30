"""Farm two-factor authentication: TOTP, WebAuthn security keys and recovery codes.

Plain functions on the farm's sqlite connection; token handling stays in `apb.farm.core`.
"""

import hashlib
import json
import logging
import re
import secrets
import sqlite3
import time
from collections.abc import Mapping
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import pyotp
import segno
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from apb.constants import MFA_METHOD_RECOVERY, MFA_METHOD_TOTP, MFA_METHOD_WEBAUTHN
from apb.farm.secret_store import Keyring, decrypt_value, encrypt_value, is_legacy_plaintext, needs_reencryption
from apb.models import MfaStatusResponse, SecurityKeyInfo
from apb.upstream import webauthn_origin

logger = logging.getLogger(__name__)

TOKEN_SCOPE_FULL = "full"
TOKEN_SCOPE_MFA_PENDING = "mfa_pending"
TOKEN_SCOPE_MFA_SETUP = "mfa_setup"
MFA_PENDING_TTL_SECONDS = 300
MFA_SETUP_TTL_SECONDS = 900
MFA_MAX_ATTEMPTS = 5

METHOD_TOTP = MFA_METHOD_TOTP
METHOD_WEBAUTHN = MFA_METHOD_WEBAUTHN
METHOD_RECOVERY = MFA_METHOD_RECOVERY

RP_NAME = "APB Farm"
WEBAUTHN_CHALLENGE_TTL_SECONDS = 300
CHALLENGE_REGISTER = "register"
CHALLENGE_AUTHENTICATE = "authenticate"

RECOVERY_CODE_COUNT = 10


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def init_tables(db: sqlite3.Connection) -> None:
    """Create the 2FA tables (idempotent)."""
    db.executescript('''
        CREATE TABLE IF NOT EXISTS user_totp (
            user_id INTEGER PRIMARY KEY,
            secret TEXT NOT NULL,
            confirmed BOOLEAN NOT NULL DEFAULT 0,
            last_used_step INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id BLOB UNIQUE NOT NULL,
            credential_data BLOB NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            name TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_used_at REAL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used_at REAL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        CREATE TABLE IF NOT EXISTS webauthn_challenges (
            token_hash TEXT PRIMARY KEY,
            purpose TEXT NOT NULL,
            state TEXT NOT NULL,
            expires_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id);
        CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id);
    ''')
    db.commit()


def relying_party(farm_url: str) -> Tuple[str, str]:
    """WebAuthn relying party ID and origin for the public farm URL."""
    return urlparse(farm_url).hostname or "localhost", webauthn_origin(farm_url)


# TOTP

def _totp_row(db: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    return db.execute(
        'SELECT secret, confirmed, last_used_step FROM user_totp WHERE user_id = ?', (user_id,)
    ).fetchone()


def _totp_aad(user_id: int) -> str:
    return f"apb-totp:{user_id}"


def _decrypt_totp_secret(keyring: Keyring, user_id: int, stored: str) -> Optional[str]:
    secret = decrypt_value(keyring, stored, _totp_aad(user_id))
    if secret is None: logger.warning(f"TOTP secret of user {user_id} cannot be decrypted with the configured keys")
    return secret


def is_totp_enabled(db: sqlite3.Connection, user_id: int) -> bool:
    row = _totp_row(db, user_id)
    return bool(row and row[1])


def pending_totp_secret(db: sqlite3.Connection, keyring: Keyring, user_id: int) -> Optional[str]:
    row = _totp_row(db, user_id)
    return _decrypt_totp_secret(keyring, user_id, row[0]) if row and not row[1] else None


def totp_provisioning_uri(secret: str, username: str, farm_url: str) -> str:
    rp_id, _ = relying_party(farm_url)
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=f"{RP_NAME} ({rp_id})")


def totp_qr_svg(provisioning_uri: str) -> str:
    """Inline SVG QR code; rendered locally so the secret never leaves the farm."""
    return segno.make(provisioning_uri, error="m").svg_inline(scale=5, border=2, dark="#000", light="#fff")


def start_totp_enrollment(db: sqlite3.Connection, keyring: Keyring, user_id: int) -> str:
    """New unconfirmed TOTP secret (replaces an unconfirmed one); raises ValueError if TOTP is active or unavailable."""
    if is_totp_enabled(db, user_id):
        raise ValueError("Authenticator app is already enabled; remove it first")
    if not keyring.is_usable:
        raise ValueError("Authenticator app unavailable: the farm has no TOTP encryption key")
    secret = pyotp.random_base32()
    db.execute(
        'INSERT OR REPLACE INTO user_totp (user_id, secret, confirmed, last_used_step, created_at) VALUES (?, ?, 0, 0, ?)',
        (user_id, encrypt_value(keyring, secret, _totp_aad(user_id)), time.time()),
    )
    db.commit()
    return secret


def verify_totp(
    db: sqlite3.Connection, keyring: Keyring, user_id: int, code: Optional[str], *, confirm: bool = False, now: Optional[float] = None
) -> bool:
    """Check a code for the active (or, with confirm, the pending) secret; each time step is accepted once."""
    row = _totp_row(db, user_id)
    code = re.sub(r"\s", "", code or "")
    if not row or bool(row[1]) == confirm or not code.isdigit():
        return False
    stored, _, last_used_step = row
    secret = _decrypt_totp_secret(keyring, user_id, stored)
    if secret is None:
        return False
    totp = pyotp.TOTP(secret)
    current_step = int((now if now is not None else time.time()) // totp.interval)
    for step in (current_step - 1, current_step, current_step + 1):
        if step > last_used_step and secrets.compare_digest(totp.generate_otp(step), code):
            db.execute('UPDATE user_totp SET last_used_step = ?, confirmed = 1 WHERE user_id = ?', (step, user_id))
            db.commit()
            return True
    return False


def migrate_totp_secrets(db: sqlite3.Connection, keyring: Keyring) -> Dict[str, int]:
    """Encrypt plaintext secrets and move secrets of older keys to the active key; counts per outcome."""
    counts = {"encrypted": 0, "reencrypted": 0, "undecryptable": 0}
    rows = db.execute('SELECT user_id, secret FROM user_totp').fetchall()
    if not keyring.is_usable:
        if rows: logger.error(f"No TOTP encryption key: {len(rows)} authenticator app(s) cannot be used until the key file is fixed")
        counts["undecryptable"] = len(rows)
        return counts
    for user_id, stored in rows:
        aad = _totp_aad(user_id)
        if is_legacy_plaintext(stored):
            secret, outcome = stored, "encrypted"
        else:
            secret = decrypt_value(keyring, stored, aad)
            outcome = "reencrypted" if needs_reencryption(keyring, stored) else None
        if secret is None:
            counts["undecryptable"] += 1
            continue
        if outcome is None:
            continue
        db.execute('UPDATE user_totp SET secret = ? WHERE user_id = ?', (encrypt_value(keyring, secret, aad), user_id))
        counts[outcome] += 1
    db.commit()
    if counts["encrypted"] or counts["reencrypted"]:
        logger.info(f"TOTP secrets: {counts['encrypted']} encrypted, {counts['reencrypted']} re-encrypted with key {keyring.active_id}")
    if counts["undecryptable"]:
        logger.error(
            f"{counts['undecryptable']} TOTP secret(s) cannot be decrypted with the configured keys; "
            "affected users must sign in with a security key or recovery code and re-enroll, or an admin resets their 2FA"
        )
    return counts


def remove_totp(db: sqlite3.Connection, user_id: int) -> bool:
    cursor = db.execute('DELETE FROM user_totp WHERE user_id = ? AND confirmed = 1', (user_id,))
    db.commit()
    return cursor.rowcount > 0


# WebAuthn security keys

def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _jsonable(value[key]) for key in value}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return websafe_encode(value)
    if isinstance(value, str):
        return str(value)
    return value


def fido2_server(farm_url: str) -> Fido2Server:
    rp_id, origin = relying_party(farm_url)
    return Fido2Server(
        PublicKeyCredentialRpEntity(name=RP_NAME, id=rp_id),
        verify_origin=lambda client_origin: client_origin == origin,
    )


def _store_challenge(db: sqlite3.Connection, session_token: str, purpose: str, state: Dict[str, Any]) -> None:
    """One outstanding ceremony per token: a new request replaces the previous challenge."""
    db.execute(
        'INSERT OR REPLACE INTO webauthn_challenges (token_hash, purpose, state, expires_at) VALUES (?, ?, ?, ?)',
        (sha256_hex(session_token), purpose, json.dumps(state), time.time() + WEBAUTHN_CHALLENGE_TTL_SECONDS),
    )
    db.execute('DELETE FROM webauthn_challenges WHERE expires_at < ?', (time.time(),))
    db.commit()


def _pop_challenge(db: sqlite3.Connection, session_token: str, purpose: str) -> Optional[Dict[str, Any]]:
    token_hash = sha256_hex(session_token)
    row = db.execute(
        'SELECT state, expires_at FROM webauthn_challenges WHERE token_hash = ? AND purpose = ?', (token_hash, purpose)
    ).fetchone()
    if not row:
        return None
    db.execute('DELETE FROM webauthn_challenges WHERE token_hash = ?', (token_hash,))
    db.commit()
    return json.loads(row[0]) if row[1] >= time.time() else None


def _credential_rows(db: sqlite3.Connection, user_id: int) -> List[sqlite3.Row]:
    return db.execute(
        'SELECT id, credential_data, sign_count FROM webauthn_credentials WHERE user_id = ? ORDER BY id', (user_id,)
    ).fetchall()


def _attested_credentials(db: sqlite3.Connection, user_id: int) -> List[AttestedCredentialData]:
    return [AttestedCredentialData(row[1]) for row in _credential_rows(db, user_id)]


def list_security_keys(db: sqlite3.Connection, user_id: int) -> List[SecurityKeyInfo]:
    rows = db.execute(
        'SELECT id, name, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY id', (user_id,)
    ).fetchall()
    return [SecurityKeyInfo(id=row[0], name=row[1], created_at=row[2], last_used_at=row[3]) for row in rows]


def registration_options(db: sqlite3.Connection, farm_url: str, session_token: str, user_id: int, username: str) -> Dict[str, Any]:
    """CredentialCreationOptions (JSON form) for registering a new key; stores the challenge for the token."""
    options, state = fido2_server(farm_url).register_begin(
        PublicKeyCredentialUserEntity(name=username, id=str(user_id).encode(), display_name=username),
        credentials=_attested_credentials(db, user_id),
        user_verification=UserVerificationRequirement.DISCOURAGED,
        resident_key_requirement=ResidentKeyRequirement.DISCOURAGED,
    )
    _store_challenge(db, session_token, CHALLENGE_REGISTER, state)
    return _jsonable(options)


def register_security_key(
    db: sqlite3.Connection, farm_url: str, session_token: str, user_id: int, name: str, credential: Dict[str, Any]
) -> None:
    """Verify a registration response and store the key; raises ValueError with a user-facing message."""
    state = _pop_challenge(db, session_token, CHALLENGE_REGISTER)
    if not state:
        raise ValueError("No security key registration in progress; please try again")
    try:
        auth_data = fido2_server(farm_url).register_complete(state, credential)
    except (ValueError, KeyError, TypeError) as e:
        logger.info(f"Security key registration failed for user {user_id}: {e}")
        raise ValueError("Security key response could not be verified") from e
    credential_data = auth_data.credential_data
    try:
        db.execute(
            'INSERT INTO webauthn_credentials (user_id, credential_id, credential_data, sign_count, name, created_at) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (user_id, credential_data.credential_id, bytes(credential_data), auth_data.counter, name.strip(), time.time()),
        )
        db.commit()
    except sqlite3.IntegrityError as e:
        raise ValueError("This security key is already registered") from e
    logger.info(f"Registered security key '{name}' for user {user_id}")


def authentication_options(db: sqlite3.Connection, farm_url: str, session_token: str, user_id: int) -> Dict[str, Any]:
    """CredentialRequestOptions (JSON form) for the user's keys; raises ValueError without keys."""
    credentials = _attested_credentials(db, user_id)
    if not credentials:
        raise ValueError("No security keys registered")
    options, state = fido2_server(farm_url).authenticate_begin(
        credentials, user_verification=UserVerificationRequirement.DISCOURAGED
    )
    _store_challenge(db, session_token, CHALLENGE_AUTHENTICATE, state)
    return _jsonable(options)


def verify_security_key(
    db: sqlite3.Connection, farm_url: str, session_token: str, user_id: int, credential: Optional[Dict[str, Any]]
) -> bool:
    """Verify an assertion against the outstanding challenge; rejects non-increasing sign counters."""
    state = _pop_challenge(db, session_token, CHALLENGE_AUTHENTICATE)
    if not state or not credential:
        return False
    rows = _credential_rows(db, user_id)
    credentials = [AttestedCredentialData(row[1]) for row in rows]
    keys = {data.credential_id: (row[0], row[2]) for data, row in zip(credentials, rows)}
    try:
        matched = fido2_server(farm_url).authenticate_complete(state, credentials, credential)
        counter = AuthenticationResponse.from_dict(credential).response.authenticator_data.counter
    except (ValueError, KeyError, TypeError) as e:
        logger.info(f"Security key login failed for user {user_id}: {e}")
        return False
    key_id, sign_count = keys[matched.credential_id]
    if (counter or sign_count) and counter <= sign_count:
        logger.warning(f"Security key {key_id} of user {user_id} reported sign count {counter} <= {sign_count}; possible clone")
        return False
    db.execute('UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE id = ?', (counter, time.time(), key_id))
    db.commit()
    return True


def remove_security_key(db: sqlite3.Connection, user_id: int, key_id: int) -> bool:
    cursor = db.execute('DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?', (key_id, user_id))
    db.commit()
    return cursor.rowcount > 0


def has_security_key(db: sqlite3.Connection, user_id: int, key_id: int) -> bool:
    return db.execute('SELECT 1 FROM webauthn_credentials WHERE id = ? AND user_id = ?', (key_id, user_id)).fetchone() is not None


# Recovery codes

def _normalize_recovery_code(code: str) -> str:
    return re.sub(r"[\s-]", "", code or "").lower()


def generate_recovery_codes(db: sqlite3.Connection, user_id: int) -> List[str]:
    """Replace all recovery codes of the user; the plain codes are only returned here."""
    codes = [f"{raw[:5]}-{raw[5:]}" for raw in (secrets.token_hex(5) for _ in range(RECOVERY_CODE_COUNT))]
    db.execute('DELETE FROM recovery_codes WHERE user_id = ?', (user_id,))
    db.executemany(
        'INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)',
        [(user_id, sha256_hex(_normalize_recovery_code(code))) for code in codes],
    )
    db.commit()
    return codes


def consume_recovery_code(db: sqlite3.Connection, user_id: int, code: Optional[str]) -> bool:
    normalized = _normalize_recovery_code(code or "")
    if not normalized:
        return False
    cursor = db.execute(
        'UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL',
        (time.time(), user_id, sha256_hex(normalized)),
    )
    db.commit()
    return cursor.rowcount > 0


def recovery_codes_remaining(db: sqlite3.Connection, user_id: int) -> int:
    return db.execute('SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL', (user_id,)).fetchone()[0]


# Status and policy

def factor_count(db: sqlite3.Connection, user_id: int) -> int:
    key_count = db.execute('SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?', (user_id,)).fetchone()[0]
    return key_count + int(is_totp_enabled(db, user_id))


def has_second_factor(db: sqlite3.Connection, user_id: int) -> bool:
    return factor_count(db, user_id) > 0


def users_with_second_factor(db: sqlite3.Connection) -> set:
    rows = db.execute(
        'SELECT user_id FROM user_totp WHERE confirmed = 1 UNION SELECT user_id FROM webauthn_credentials'
    ).fetchall()
    return {row[0] for row in rows}


def is_mfa_required(db: sqlite3.Connection, user_id: int, is_admin: bool) -> bool:
    return is_admin or has_second_factor(db, user_id)


def available_methods(db: sqlite3.Connection, user_id: int) -> List[str]:
    checks = (
        (METHOD_WEBAUTHN, bool(_credential_rows(db, user_id))),
        (METHOD_TOTP, is_totp_enabled(db, user_id)),
        (METHOD_RECOVERY, recovery_codes_remaining(db, user_id) > 0),
    )
    return [method for method, is_available in checks if is_available]


def mfa_status(db: sqlite3.Connection, user_id: int, is_admin: bool) -> MfaStatusResponse:
    return MfaStatusResponse(
        enabled=has_second_factor(db, user_id),
        required=is_admin,
        totp_enabled=is_totp_enabled(db, user_id),
        security_keys=list_security_keys(db, user_id),
        recovery_codes_remaining=recovery_codes_remaining(db, user_id),
    )


def ensure_can_remove_factor(db: sqlite3.Connection, user_id: int, is_admin: bool) -> None:
    if is_admin and factor_count(db, user_id) <= 1:
        raise ValueError("Admins must keep at least one second factor; add another one first")


def after_factor_removed(db: sqlite3.Connection, user_id: int) -> None:
    """Without any second factor left, 2FA is off and recovery codes are useless."""
    if not has_second_factor(db, user_id):
        db.execute('DELETE FROM recovery_codes WHERE user_id = ?', (user_id,))
        db.commit()


def reset_user_mfa(db: sqlite3.Connection, user_id: int) -> None:
    for table in ("user_totp", "webauthn_credentials", "recovery_codes"):
        db.execute(f'DELETE FROM {table} WHERE user_id = ?', (user_id,))
    db.commit()
    logger.info(f"Reset two-factor authentication for user {user_id}")


def verify_second_factor(
    db: sqlite3.Connection,
    keyring: Keyring,
    farm_url: str,
    session_token: str,
    user_id: int,
    method: str,
    code: Optional[str] = None,
    credential: Optional[Dict[str, Any]] = None,
) -> bool:
    if method == METHOD_TOTP:
        return verify_totp(db, keyring, user_id, code)
    if method == METHOD_RECOVERY:
        return consume_recovery_code(db, user_id, code)
    if method == METHOD_WEBAUTHN:
        return verify_security_key(db, farm_url, session_token, user_id, credential)
    return False
