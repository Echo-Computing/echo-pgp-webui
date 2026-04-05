"""
pgp_mobile/lib/api_client.py — HTTP client for PGP Vault Flask server
"""

import httpx
import urllib.parse


class PGPVaultClient:
    """HTTP client for the PGP Vault server API."""

    def __init__(self, base_url: str, token: str, verify_tls: bool = True):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.verify_tls = verify_tls
        self._client = httpx.Client(
            timeout=30.0,
            verify=verify_tls,
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
