"""Encryption at rest for farm secrets that must stay recoverable (TOTP secrets).

Keys live in a keyring file outside the database: one `<key_id> <base64url 32-byte key>` per line,
the last line is the active key. Stored values look like `v1:<key_id>:<base64url(nonce || ciphertext)>`.
"""

import base64
import binascii
import logging
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

FORMAT_PREFIX = "v1"
KEY_BYTES = 32
NONCE_BYTES = 12
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class Keyring(BaseModel):
    model_config = ConfigDict(frozen=True)

    keys: Dict[str, bytes] = {}
    active_id: Optional[str] = None

    @property
    def is_usable(self) -> bool:
        return self.active_id is not None and self.active_id in self.keys


EMPTY_KEYRING = Keyring()


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_key_line() -> str:
    return f"{secrets.token_hex(4)} {_b64encode(secrets.token_bytes(KEY_BYTES))}"


def parse_keyring(text: str) -> Keyring:
    """Parse keyring file content; raises ValueError on malformed lines or duplicate key IDs."""
    keys: Dict[str, bytes] = {}
    active_id = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or not KEY_ID_PATTERN.match(parts[0]):
            raise ValueError(f"line {line_number}: expected '<key_id> <base64url key>'")
        key_id, encoded_key = parts
        try:
            key = _b64decode(encoded_key)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"line {line_number}: key is not valid base64url") from e
        if len(key) != KEY_BYTES:
            raise ValueError(f"line {line_number}: key must be {KEY_BYTES} bytes")
        if key_id in keys:
            raise ValueError(f"line {line_number}: duplicate key ID '{key_id}'")
        keys[key_id] = key
        active_id = key_id
    return Keyring(keys=keys, active_id=active_id)


def generate_keyring() -> Keyring:
    """In-memory keyring with one random key."""
    return parse_keyring(new_key_line())


def _create_keyring_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as keyring_file:
        keyring_file.write("# APB farm TOTP encryption keys; the last key is active. Back up separately from farm.db.\n")
        keyring_file.write(new_key_line() + "\n")
    logger.warning(f"Generated new TOTP encryption key file {path}; back it up separately from farm.db")


def load_keyring(path: Path) -> Keyring:
    """Load (or create) the keyring file; returns an empty keyring when it cannot be used."""
    try:
        if not path.exists(): _create_keyring_file(path)
    except FileExistsError:
        pass
    except OSError as e:
        logger.error(f"Cannot create TOTP key file {path}: {e}; authenticator app logins are disabled")
        return EMPTY_KEYRING
    try:
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            logger.warning(f"TOTP key file {path} is accessible by group or others; restrict it to mode 0600")
        keyring = parse_keyring(path.read_text())
    except (OSError, UnicodeDecodeError, ValueError) as e:
        logger.error(f"Cannot load TOTP key file {path}: {e}; authenticator app logins are disabled")
        return EMPTY_KEYRING
    if not keyring.is_usable:
        logger.error(f"TOTP key file {path} contains no keys; authenticator app logins are disabled")
    return keyring


def is_legacy_plaintext(stored: str) -> bool:
    return not stored.startswith(f"{FORMAT_PREFIX}:")


def stored_key_id(stored: str) -> Optional[str]:
    parts = stored.split(":", 2)
    return parts[1] if len(parts) == 3 and parts[0] == FORMAT_PREFIX else None


def needs_reencryption(keyring: Keyring, stored: str) -> bool:
    return keyring.is_usable and stored_key_id(stored) != keyring.active_id


def encrypt_value(keyring: Keyring, plaintext: str, aad: str) -> str:
    """Encrypt with the active key; raises ValueError without a usable keyring."""
    if not keyring.is_usable:
        raise ValueError("No encryption key available")
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(keyring.keys[keyring.active_id]).encrypt(nonce, plaintext.encode(), aad.encode())
    return f"{FORMAT_PREFIX}:{keyring.active_id}:{_b64encode(nonce + ciphertext)}"


def decrypt_value(keyring: Keyring, stored: str, aad: str) -> Optional[str]:
    """Plaintext of an encrypted value, or None for unknown keys, tampering or a wrong AAD."""
    key_id = stored_key_id(stored)
    key = keyring.keys.get(key_id) if key_id else None
    if key is None:
        return None
    try:
        data = _b64decode(stored.split(":", 2)[2])
        return AESGCM(key).decrypt(data[:NONCE_BYTES], data[NONCE_BYTES:], aad.encode()).decode()
    except (binascii.Error, ValueError, InvalidTag, UnicodeDecodeError):
        return None
