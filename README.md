# PGP Vault Web UI

A standalone, self-hosted Flask web interface for GPG encrypt/decrypt operations. SQLite-backed message storage with multi-user support — everything stays on your machine.

## Features at a Glance

- **Encrypt/Decrypt** — PGP message encryption and decryption in the browser
- **Multi-user** — per-user GPG homedirs, message databases, and keyrings
- **Inbox** — messages delivered to recipients on the same server, lazy decrypt
- **Key Management** — import, list, and delete public keys; auto-import on message receipt
- **Dark/Light Mode** — toggle with persistent cookie
- **Admin Panel** — create/delete users, reset passwords, view audit log, unlock accounts
- **Confirmation Guard** — optional passphrase before encrypt/decrypt operations
- **CSRF Protection** — double-submit cookie pattern on all forms
- **REST API** — full message CRUD via Bearer token auth
- **HTTPS by default** — self-signed CA + server cert auto-generated on first launch
- **Mobile-friendly** — responsive layout adapts to phone, tablet, and desktop

---

## Quick Start

```bash
git clone https://github.com/Echo-Computing/echo-pgp-webui
cd echo-pgp-webui
pip install -r requirements-server.txt

# Create an admin account (password must be 8+ characters)
python pgp_webui.py --init-admin admin yourpassword admin@example.com

# Start the server — HTTPS certs are auto-generated on first launch
python3 pgp_webui.py
# Opens https://localhost:8765
```

> **HTTPS note:** The server uses a self-signed certificate. Your browser will show "Not private" or "Unsafe" on first visit — click **Advanced → Proceed to localhost (unsafe)**. To suppress the warning on other devices, download the CA cert from Settings and install it.

---

## Setup Guide

### 1. Prerequisites

- **Python 3.8+** — [python.org](https://python.org) or Windows Store
- **GnuPG** — see OS-specific instructions below
- **Flask + flask-cors + zeroconf** — `pip install -r requirements-server.txt`

Verify GPG is installed:

```bash
gpg --version
```

#### OS-Specific GPG Installation

**Windows (option A — Git Bash / MSYS2)**

GPG is bundled with Git. If you installed Git, you already have GPG:

```bash
gpg --version
# Should show "gpg (GnuPG) 2.4.x" from "C:\Program Files\Git\usr\bin\gpg.exe"
```

**Windows (option B — GnuPG standalone)**

- Download from [gpg4win.org](https://www.gpg4win.org) and install
- The web UI auto-detects `C:\Program Files (x86)\GnuPG\bin\gpg.exe`

**WSL (Windows Subsystem for Linux)**

```bash
sudo apt update && sudo apt install gnupg
gpg --version
```

Set your GPG home dir to a WSL-native path:

```bash
export GNUPGHOME="$HOME/.gnupg"
export PGP_DIR="$HOME/.gnupg"
```

> **WSL Note:** If you switch between Windows GPG and WSL GPG with the same homedir, key permissions and agent sockets can conflict. Use separate homedirs per environment.

**macOS**

```bash
brew install gnupg
gpg --version
```

**Linux (Debian/Ubuntu)**

```bash
sudo apt update && sudo apt install gnupg
gpg --version
```

**Linux (Fedora/RHEL)**

```bash
sudo dnf install gnupg
gpg --version
```

**Linux (Arch)**

```bash
sudo pacman -S gnupg
gpg --version
```

### 2. Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PGP_DIR` | No | Script's parent directory | Root directory for keys, certs, databases |
| `PGP_DB_PATH` | No | `PGP_DIR/messages.db` | Path to legacy shared message DB |
| `PGP_WEBUI_PORT` | No | `8765` | Port to listen on |
| `PGP_CLIPBOARD_CLEAR_SECONDS` | No | `30` | Auto-clear clipboard after N seconds |
| `PGP_MAX_ATTEMPTS` | No | `5` | Failed login attempts before lockout |
| `PGP_CORS_ORIGINS` | No | (empty) | Comma-separated allowed origins for API CORS |
| `SECRET_KEY` | No | random | Flask session secret |

---

## Multi-User Setup

PGP Vault supports multiple users with per-user isolation:

- **Per-user GPG homedir** — each user's private keys are isolated at `users/{username}/.gnupg/`
- **Per-user message database** — each user has their own `users/{username}/messages.db`
- **Per-user public keys** — each user's keyring is separate; importing a key = adding a contact
- **Per-user key passphrase** — new keys are generated with a random 64-char passphrase, stored in `users/{username}/.gpg_passphrase`
- **Admin panel** — create/delete users, reset passwords, assign admin role
- **Brute-force protection** — 5 failed login attempts per IP triggers a 15-minute lockout

### Creating Users

```bash
# Create the first admin user (password must be 8+ characters)
python pgp_webui.py --init-admin admin yourpassword admin@example.com
```

After that, create additional users via the **Admin → Users** page in the web UI. Each new user automatically gets:

- A GPG keypair (RSA-4096, passphrase-protected)
- An isolated GPG homedir and message database
- Other users' public keys auto-imported into their keyring

---

## Messaging People Outside Your Network

PGP Vault works with **anyone who uses PGP**, not just people on your server. Here's how to communicate with friends, colleagues, or contacts on other platforms:

### How It Works

PGP uses **public/private key pairs**. You share your **public key** with others; they use it to encrypt messages that only your **private key** can decrypt. The reverse is also true — you encrypt with their public key, and they decrypt with their private key. The server never sees plaintext.

### Step 1: Share Your Public Key

Your public key is at `PGP_DIR/users/yourname/pubkey.asc` — or go to **Keys** in the web UI to view and copy it. Share it via any channel:

- Email it as an attachment
- Post it on a keyserver (`gpg --send-keys YOUR_KEY_ID`)
- Share it via Signal, Telegram, USB drive, etc.

### Step 2: Import Their Public Key

When someone sends you their public key:

1. Go to **Keys** → **Import a Friend's Public Key**
2. Paste the `-----BEGIN PGP PUBLIC KEY BLOCK-----` block
3. Click **Import Key**

Their email now appears in your **Recipient** dropdown on the Compose page.

### Step 3: Send an Encrypted Message

1. Go to **Compose**
2. Select your friend from the **Recipient** dropdown
3. Type your message
4. Click **Encrypt & Send**

The encrypted `.asc` file is stored in your Sent log. Copy or download the ciphertext and send it to your friend via **any channel** — email, Signal, Telegram, USB drive, carrier pigeon. Only they can decrypt it.

### Step 4: Receive an Encrypted Message

When someone sends you an encrypted `.asc` file:

1. Copy the `-----BEGIN PGP MESSAGE-----` block
2. Go to **Compose** → **Decrypt** panel
3. Paste the ciphertext
4. Click **Decrypt** — the plaintext appears below

### For Friends Not Using PGP Vault

Your friends don't need to install PGP Vault. They just need GPG on their own machine:

```bash
# They encrypt to you:
echo "Secret message" | gpg --armor --encrypt --recipient your@email.com --output message.asc

# They decrypt from you:
gpg --decrypt message.asc
```

Or they can use any PGP-compatible tool: GPG4Win, Kleopatra, Mailvelope, OpenKeychain (Android), etc.

---

## AI Model Integration

Use the Web UI as a local API for AI pipelines that need encrypted I/O.

### REST API

All `/api/*` endpoints require a Bearer token (shown on the Settings page):

```bash
TOKEN=$(cat PGP_DIR/.auth_token)
curl -H "Authorization: Bearer $TOKEN" https://localhost:8765/api/messages
```

#### `POST /api/messages`

Encrypt and store a new message.

```bash
curl -X POST https://localhost:8765/api/messages \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"recipient": "friend@example.com", "plaintext": "Hello!", "subject": "Hi"}'
```

#### `GET /api/messages`

List messages. Supports `?recipient=`, `?since=`, `?limit=`, `?offset=`.

#### `GET /api/messages/<id>`

Decrypt and return a single message by ID.

#### `DELETE /api/messages/<id>`

Delete a message from DB and disk.

#### `PATCH /api/messages/<id>/read`

Mark a message as read.

#### `POST /api/wipe`

Kill GPG agent, wipe all messages and DB. Requires `{"confirm": "yes"}` and admin session.

### Web UI Routes

| Route | Methods | Description |
|-------|---------|-------------|
| `/` | GET | Redirect to /compose |
| `/login` | GET, POST | Login page |
| `/logout` | POST | Logout and clear session |
| `/compose` | GET, POST | Encrypt or decrypt messages |
| `/inbox` | GET | View received messages (lazy decrypt) |
| `/inbox/decrypt_file/<filename>` | GET | Decrypt a file inline (AJAX) |
| `/inbox/raw/<filename>` | GET | Serve raw `.asc` file content |
| `/inbox/delete_file/<filename>` | POST | Delete a `.asc` file from inbox/sent |
| `/sent` | GET | View sent messages |
| `/sent/clear` | POST | Clear the sent log (admin only) |
| `/keys` | GET, POST | List, import, or delete public keys |
| `/settings` | GET, POST | Confirmation guard, dark mode, environment info |
| `/settings/ca-cert` | GET | Download CA certificate |
| `/settings/regen-token` | POST | Regenerate API auth token (admin only) |
| `/settings/kill-agent` | POST | Kill gpg-agent and clear passphrase cache |
| `/admin/users` | GET, POST | Create, delete users, reset passwords |
| `/admin/audit` | GET | View failed login attempts |
| `/admin/unlock` | POST | Unlock locked IPs/usernames |
| `/toggle-dark` | POST | Toggle dark mode |

---

## Security Features

### Confirmation Guard

The **Settings → Confirmation Guard** adds a passphrase prompt before encrypt/decrypt operations. Useful on shared machines.

### GPG Agent

The GPG Agent (`gpg-agent`) caches your private key passphrase in memory. PGP Vault manages the passphrase automatically — each user's key is protected with a random 64-character passphrase stored in `users/{username}/.gpg_passphrase` (file permissions `0600`).

To manually manage the agent:

```bash
gpgconf --kill gpg-agent    # stop the agent
gpg-agent --daemon           # start fresh
```

The **Settings → Kill Agent** button in the web UI does the same thing.

### Clipboard Auto-Clear

Decrypted plaintext is copied to clipboard and auto-clears after 30 seconds (configurable via `PGP_CLIPBOARD_CLEAR_SECONDS`).

### Login Lockout

5 failed login attempts per IP triggers a 15-minute lockout. Admins can unlock from **Admin → Audit**.

---

## File Layout

```
echo-pgp-webui/
├── pgp_webui.py              # Flask application
├── requirements-server.txt   # pip install -r requirements-server.txt
├── README.md
├── LICENSE
└── .gitignore

PGP_DIR/                      # set via PGP_DIR env var (default: script's parent directory)
├── sessions.db               # SQLite — users, sessions, login attempts
├── .auth_token               # Bearer token for API access
├── pgpvault.crt              # TLS server certificate (auto-generated)
├── pgpvault.key              # TLS server private key
├── pgpvault-ca.crt           # TLS CA certificate
├── pgpvault-ca.key            # TLS CA private key
└── users/
    └── {username}/
        ├── .gnupg/           # per-user GPG homedir (private keys isolated)
        ├── .gpg_passphrase   # per-user key passphrase (0600 permissions)
        ├── messages.db       # per-user SQLite — message metadata + encrypted payloads
        ├── pubkey.asc        # user's exported public key
        ├── inbox/            # received .asc files
        └── sent/             # sent .asc files
```

---

## Troubleshooting

### `gpg: error: no such user ID` — Recipient not found

You haven't imported your friend's public key yet. Go to **Keys → Import a Friend's Public Key** and paste their `.asc` block.

### `gpg: keyserver receive failed: No data`

The key block may be malformed. Make sure you copied the full `-----BEGIN PGP PUBLIC KEY BLOCK-----` through `-----END PGP PUBLIC KEY BLOCK-----` lines.

### `FileNotFoundError: [WinError 2] The system cannot find the file specified`

GPG isn't in your system PATH. This is auto-detected in the latest version — make sure you're running the [latest release](https://github.com/Echo-Computing/echo-pgp-webui/releases).

### GPG asks for passphrase on every operation

PGP Vault manages passphrases automatically via `--pinentry-mode loopback`. If you see passphrase prompts, make sure you're on v2.2.0+ which handles this automatically.

---

## Production Deployment

### Option 1: Gunicorn (recommended)

```bash
pip install gunicorn
gunicorn --workers 2 --bind 0.0.0.0:8765 --keyfile PGP_DIR/pgpvault.key --certfile PGP_DIR/pgpvault.crt pgp_webui:app
```

### Option 2: Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl;
    server_name pgpvault.example.com;

    ssl_certificate     /path/to/pgpvault-ca.crt;
    ssl_certificate_key /path/to/pgpvault.key;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

When running behind a reverse proxy, add ProxyFix to `pgp_webui.py`:

```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
```

### Option 3: systemd Service (Linux)

```ini
[Unit]
Description=PGP Vault Web UI
After=network.target

[Service]
Type=simple
User=pgpvault
WorkingDirectory=/opt/echo-pgp-webui
ExecStart=/opt/echo-pgp-webui/venv/bin/gunicorn --workers 2 --bind 0.0.0.0:8765 pgp_webui:app
Restart=on-failure
Environment=PGP_DIR=/opt/pgpvault-data

[Install]
WantedBy=multi-user.target
```

### Option 4: Docker

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y gnupg && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt gunicorn
COPY pgp_webui.py .
EXPOSE 8765
ENV PGP_DIR=/data
VOLUME /data
CMD ["gunicorn", "--workers", "2", "--bind", "0.0.0.0:8765", "pgp_webui:app"]
```

```bash
docker build -t pgpvault .
docker run -d -p 8765:8765 -v /path/to/pgp-data:/data pgpvault
```

### Accessing from Other Devices on Your LAN

1. Find your server's LAN IP (shown on startup, or `ip addr` / `ifconfig`)
2. Install the CA certificate (`PGP_DIR/pgpvault-ca.crt`) on client devices:
   - **Windows:** Double-click the `.crt` → Install Certificate → Local Machine → Trusted Root CA
   - **macOS:** Double-click → Add to Keychain → set to "Always Trust"
   - **Linux:** `sudo cp pgpvault-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`
   - **Android:** Settings → Security → Install from storage
   - **iOS:** Open the `.crt` in Safari → Install Profile
3. Open `https://YOUR-LAN-IP:8765` on the client device

---

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| CSRF attacks | Double-submit cookie pattern on all POST routes |
| XSS attacks | `html.escape()` on all user input in HTML responses |
| SQL injection | Parameterized queries throughout |
| Brute force login | 5 failed attempts per IP → 15-minute lockout |
| Path traversal | `Path(filename).name` strips directory components |
| GPG injection | List-form subprocess args, regex-validated usernames/emails |
| Key passphrase leakage | `--passphrase-file` with temp files (never on command line) |
| Secret key exposure | Per-user `users/{username}/.gnupg/` isolation |
| Message tampering | SHA-256 content hashes stored with each message |
| Auth token timing attacks | `secrets.compare_digest()` instead of `==` |
| Session hijacking | HttpOnly + Secure + SameSite=Lax cookies, 7-day expiry |
| Stack trace leakage | Generic error messages, GPG errors logged server-side only |
| CORS | Restricted to `PGP_CORS_ORIGINS` env var (empty by default) |

---

## License

MIT — See [LICENSE](LICENSE) for details.