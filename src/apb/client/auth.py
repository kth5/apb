"""APB farm authentication client."""

import getpass
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from apb import VERSION
from apb.http import create_sync_client

logger = logging.getLogger(__name__)

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

    def login(self, username: str, password: str) -> bool:
        """Login with username and password"""
        try:
            response = requests.post(
                f"{self.farm_url}/auth/login",
                json={"username": username, "password": password},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                token = data.get('token')
                if token:
                    self._save_token(token)
                    print(f"Successfully logged in as {username}")
                    return True
            else:
                try:
                    error_data = response.json()
                    print(f"Login failed: {error_data.get('detail', 'Unknown error')}")
                except:
                    print(f"Login failed: HTTP {response.status_code}")
                return False

        except Exception as e:
            print(f"Login error: {e}")
            return False

    def logout(self) -> bool:
        """Logout (revoke current token)"""
        if not self._token:
            return True

        try:
            response = requests.post(
                f"{self.farm_url}/auth/logout",
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=30
            )

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
            response = requests.get(
                f"{self.farm_url}/auth/me",
                headers=self.get_auth_headers(),
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
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

