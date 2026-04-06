"""
pgp_mobile/lib/api_client.py — HTTP client for PGP Vault Flask server
"""

import httpx
import os
import sys
import urllib.parse


def _get_bundled_ca_cert() -> str | None:
    """
    Return the path to the bundled CA cert if running as a bundled app
    (PyInstaller EXE or Flet APK), otherwise None.

    Search order:
    1. PyInstaller _MEIPASS bundle root (desktop EXE)
    2. Flet app directory (next to main.py / main.exe)
    3. Script directory (pgp_mobile/)
    4. Parent of script directory (repo root — for dev runs from repo root)
    5. Current working directory (for dev runs from pgp_tmp_restored/)
    """
    candidates = []

    if getattr(sys, '_MEIPASS', None):
        candidates.append(os.path.join(sys._MEIPASS, 'pgpvault-ca.crt'))

    # Flet / PyInstaller app dir — next to the executable
    app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.extend([
        os.path.join(app_dir, 'pgpvault-ca.crt'),
        os.path.join(app_dir, 'pgpvault', 'pgpvault-ca.crt'),
    ])

    # Also check parent of pgp_mobile (repo root) — common in dev setups
    candidates.append(os.path.join(os.path.dirname(app_dir), 'pgpvault-ca.crt'))

    # CWD — when running from pgp_tmp_restored/ or the repo root
    candidates.append(os.path.join(os.getcwd(), 'pgpvault-ca.crt'))

    for path in candidates:
        if os.path.exists(path):
            return path
    return None


class PGPVaultClient:
    """HTTP client for the PGP Vault server API."""

    def __init__(self, base_url: str, token: str, verify_tls: bool = True, ca_cert_path: str | None = None):
        self.base_url = base_url.rstrip('/')
        self.token = token

        # resolve verify — True means use system CAs + optional custom CA
        if verify_tls is True:
            bundled = _get_bundled_ca_cert()
            self.verify_tls = ca_cert_path or bundled or True
        else:
            self.verify_tls = verify_tls

        self._client = httpx.Client(
            timeout=30.0,
            verify=self.verify_tls,
            headers={'Authorization': f'Bearer {token}'},
        )

    def close(self):
        self._client.close()

    def list_messages(self, recipient=None, since=None, limit=50, offset=0, direction=None):
        params = {}
        if recipient:
            params['recipient'] = recipient
        if since:
            params['since'] = since
        if limit:
            params['limit'] = limit
        if offset:
            params['offset'] = offset
        if direction:
            params['direction'] = direction
        resp = self._client.get(f'{self.base_url}/api/messages', params=params)
        resp.raise_for_status()
        return resp.json()

    def send_message(self, recipient: str, plaintext: str, subject: str = '') -> dict:
        resp = self._client.post(
            f'{self.base_url}/api/messages',
            json={'recipient': recipient, 'plaintext': plaintext, 'subject': subject},
        )
        resp.raise_for_status()
        return resp.json()

    def get_message(self, msg_id: int) -> dict:
        resp = self._client.get(f'{self.base_url}/api/messages/{msg_id}')
        resp.raise_for_status()
        return resp.json()

    def delete_message(self, msg_id: int) -> dict:
        resp = self._client.delete(f'{self.base_url}/api/messages/{msg_id}')
        resp.raise_for_status()
        return resp.json()

    def mark_read(self, msg_id: int) -> dict:
        resp = self._client.patch(f'{self.base_url}/api/messages/{msg_id}')
        resp.raise_for_status()
        return resp.json()

    def test_connection(self) -> tuple[bool, str]:
        """Test the connection. Returns (ok, message)."""
        try:
            resp = self._client.get(f'{self.base_url}/api/messages', params={'limit': 1})
            if resp.status_code == 401:
                return False, 'Invalid auth token'
            if resp.status_code == 403:
                return False, 'Token forbidden'
            resp.raise_for_status()
            return True, 'Connected'
        except httpx.RequestError as e:
            return False, f'Connection failed: {e}'
        except httpx.HTTPStatusError as e:
            return False, f'HTTP {e.response.status_code}: {e.response.text[:100]}'
        except Exception as e:
            return False, str(e)
