# PGP Web UI

Standalone Flask interface for GPG encrypt/decrypt operations.

## Quick Start

```bash
git clone <repo>
cd pgp-publish
pip install flask gnupg

# Configure identity (replace these before deploying)
export PGP_SENDER_ID="echo@vault.local"
export PGP_DIR="/path/to/.gnupg"

python3 pgp_webui.py
# Opens http://localhost:8765
```

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PGP_SENDER_ID` | Yes | — | Key ID or email of the sending key (e.g. `echo@vault.local`) |
| `PGP_DIR` | No | `~/.gnupg` | Path to GPG home directory |
| `PGP_RECIPIENT_ID` | No | Same as `PGP_SENDER_ID` | Default recipient for encryption |
| `FLASK_HOST` | No | `0.0.0.0` | Host to bind |
| `FLASK_PORT` | No | `8765` | Port to bind |
| `FLASK_DEBUG` | No | `false` | Enable Flask debug mode |
| `SECRET_KEY` | No | random | Flask secret key for sessions |

## Expected GPG Layout

```
PGP_DIR/
├── private-keys-v1.d/
│   └── <keygrip>.key
├── public-keys-v1.d/
│   └── <keygrip>.pub
├── trustdb.gpg
└── gpg.conf
```

## API Endpoints

- `GET /` — UI dashboard
- `POST /encrypt` — Encrypt a message
  - Body: `{ "plaintext": "...", "recipient": "coda@vault.local" }`
  - Returns: `{ "ciphertext": "-----BEGIN PGP MESSAGE-----..." }`
- `POST /decrypt` — Decrypt a message
  - Body: `{ "ciphertext": "-----BEGIN PGP MESSAGE-----..." }`
  - Returns: `{ "plaintext": "..." }`

## Deploy Notes

**SANITIZED PUBLISH VERSION** — replace identity placeholders before deploying:
- Set `PGP_SENDER_ID` to your actual sending key
- Ensure `PGP_DIR` points to a GPG homedir with your private key imported
- Never commit private keys to the repository
