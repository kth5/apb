"""APB farm authentication client."""

import getpass
import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

import httpx
from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client, UserInteraction

from apb.constants import MFA_METHOD_RECOVERY, MFA_METHOD_TOTP, MFA_METHOD_WEBAUTHN
from apb.http import create_sync_client
from apb.models import LoginResponse, MfaChallengeResponse, MfaSetupRequiredResponse, UserResponse
from apb.upstream import upstream_url, webauthn_origin

logger = logging.getLogger(__name__)

AUTH_TIMEOUT = 30.0
CLI_MFA_METHODS = {"totp": MFA_METHOD_TOTP, "key": MFA_METHOD_WEBAUTHN, "recovery": MFA_METHOD_RECOVERY}
MFA_CODE_PROMPTS = {MFA_METHOD_TOTP: "Authentication code: ", MFA_METHOD_RECOVERY: "Recovery code: "}


def _print_failure(prefix: str, response: httpx.Response) -> None:
    try:
        print(f"{prefix}: {response.json().get('detail', 'Unknown error')}")
    except ValueError:
        print(f"{prefix}: HTTP {response.status_code}")


def find_security_keys() -> List[Any]:
    """Connected FIDO2 HID devices; empty when none are present or HID access is unavailable."""
    try:
        from fido2.hid import CtapHidDevice

        return list(CtapHidDevice.list_devices())
    except Exception as e:
        logger.debug(f"Could not list FIDO2 devices: {e}")
        return []


def choose_mfa_method(methods: Sequence[str], requested: Optional[str], has_security_key: bool) -> Optional[str]:
    """Second factor to use: the requested one if enrolled, else a connected key, the authenticator app, recovery codes."""
    if requested:
        method = CLI_MFA_METHODS.get(requested)
        return method if method in methods else None
    if MFA_METHOD_WEBAUTHN in methods and has_security_key:
        return MFA_METHOD_WEBAUTHN
    for method in (MFA_METHOD_TOTP, MFA_METHOD_RECOVERY, MFA_METHOD_WEBAUTHN):
        if method in methods:
            return method
    return None


class _TerminalInteraction(UserInteraction):
    def prompt_up(self) -> None:
        print("Touch your security key...")

    def request_pin(self, permissions, rp_id) -> Optional[str]:
        return getpass.getpass("Security key PIN: ")

class APBAuthClient:
    """Handles authentication for APB client"""

    def __init__(self, farm_url: str, config_path: Optional[Path] = None):
        self.farm_url = farm_url.rstrip('/')
        self.config_path = config_path or Path.home() / ".apb" / "auth.json"
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._token = None
        self._load_token()

    def _load_token(self):
        """Load stored token from config file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                    farm_tokens = data.get('tokens', {})
                    self._token = farm_tokens.get(self.farm_url)
        except Exception as e:
            print(f"Warning: Could not load stored token: {e}")

    def _save_token(self, token: str):
        """Save token to config file"""
        try:
            # Load existing config
            config = {}
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config = json.load(f)

            # Update token for this farm
            if 'tokens' not in config:
                config['tokens'] = {}
            config['tokens'][self.farm_url] = token

            # Save config
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)

            # Set restrictive permissions
            self.config_path.chmod(0o600)
            self._token = token

        except Exception as e:
            print(f"Warning: Could not save token: {e}")

    def _clear_token(self):
        """Clear stored token"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config = json.load(f)

                if 'tokens' in config and self.farm_url in config['tokens']:
                    del config['tokens'][self.farm_url]

                    with open(self.config_path, 'w') as f:
                        json.dump(config, f, indent=2)

            self._token = None
        except Exception as e:
            print(f"Warning: Could not clear token: {e}")

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        with create_sync_client(timeout=AUTH_TIMEOUT) as client:
            return client.request(method, upstream_url(self.farm_url, path), **kwargs)

    def login(
        self,
        username: str,
        password: str,
        mfa_method: Optional[str] = None,
        prompt: Callable[[str], str] = getpass.getpass,
    ) -> bool:
        """Login with username and password, completing two-factor authentication when required"""
        try:
            response = self._request(
                "POST",
                "/auth/login",
                json={"username": username, "password": password},
            )
            if response.status_code != 200:
                _print_failure("Login failed", response)
                return False

            data = response.json()
            if data.get("mfa_setup_required"):
                setup = MfaSetupRequiredResponse.model_validate(data)
                print("Two-factor authentication is required for admin accounts.")
                print(f"Set up an authenticator app or security key in a browser first: {setup.setup_url}")
                return False
            if data.get("mfa_required"):
                response = self._complete_mfa(MfaChallengeResponse.model_validate(data), mfa_method, prompt)
                if response is None:
                    return False
                if response.status_code != 200:
                    _print_failure("Two-factor authentication failed", response)
                    return False
                data = response.json()

            login_response = LoginResponse.model_validate(data)
            self._save_token(login_response.token)
            print(f"Successfully logged in as {login_response.user.username}")
            return True

        except Exception as e:
            print(f"Login error: {e}")
            return False

    def _complete_mfa(
        self, challenge: MfaChallengeResponse, mfa_method: Optional[str], prompt: Callable[[str], str]
    ) -> Optional[httpx.Response]:
        is_key_allowed = MFA_METHOD_WEBAUTHN in challenge.methods and mfa_method in (None, "key")
        devices = find_security_keys() if is_key_allowed else []
        method = choose_mfa_method(challenge.methods, mfa_method, bool(devices))
        if not method:
            print(f"Two-factor method '{mfa_method}' is not set up for this account (available: {', '.join(challenge.methods)})")
            return None

        if method == MFA_METHOD_WEBAUTHN:
            credential = self._security_key_assertion(challenge.mfa_token, devices)
            if credential is None:
                return None
            payload = {"credential": credential}
        else:
            payload = {"code": prompt(MFA_CODE_PROMPTS[method]).strip()}
        return self._request("POST", "/auth/login/2fa", json={"mfa_token": challenge.mfa_token, "method": method, **payload})

    def _security_key_assertion(self, mfa_token: str, devices: List[Any]) -> Optional[Dict[str, Any]]:
        if not devices:
            print("No FIDO2 security key found. Connect it, or use --2fa-method totp or --2fa-method recovery.")
            return None
        response = self._request("POST", "/auth/login/2fa/webauthn-options", json={"mfa_token": mfa_token})
        if response.status_code != 200:
            _print_failure("Security key login failed", response)
            return None

        client = Fido2Client(
            devices[0], DefaultClientDataCollector(webauthn_origin(self.farm_url)), user_interaction=_TerminalInteraction()
        )
        try:
            assertion = client.get_assertion(response.json()["publicKey"])
            return dict(assertion.get_response(0))
        except ClientError as e:
            print(f"Security key error: {e}")
            return None

    def logout(self) -> bool:
        """Logout (revoke current token)"""
        if not self._token:
            return True

        try:
            response = self._request("POST", "/auth/logout", headers=self.get_auth_headers())

            # Clear token regardless of response
            self._clear_token()

            if response.status_code == 200:
                print("Successfully logged out")
                return True
            else:
                print(f"Logout response: HTTP {response.status_code}")
                return True  # Still consider it successful since we cleared local token

        except Exception as e:
            print(f"Logout error: {e}")
            self._clear_token()  # Clear local token anyway
            return True

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for requests"""
        if self._token:
            return {"Authorization": f"Bearer {self._token}"}
        return {}

    def is_authenticated(self) -> bool:
        """Check if we have a stored token"""
        return self._token is not None

    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """Get current user information"""
        if not self._token:
            return None

        try:
            response = self._request("GET", "/auth/me", headers=self.get_auth_headers())

            if response.status_code == 200:
                return UserResponse.model_validate(response.json()).model_dump()
            elif response.status_code == 401:
                # Token is invalid, clear it
                self._clear_token()
                return None
            else:
                print(f"Failed to get user info: HTTP {response.status_code}")
                return None

        except Exception as e:
            print(f"Error getting user info: {e}")
            return None

