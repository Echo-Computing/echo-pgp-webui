# PGP Vault Web UI

A standalone, self-hosted Flask web interface for GPG encrypt/decrypt operations. SQLite-backed message storage — everything stays on your machine.

**Use cases:**
- Encrypt messages to friends using their public PGP keys
- Decrypt messages sent to you by anyone
- Integrate into AI pipelines that need to encrypt LLM outputs or decrypt inputs
- Collaborate securely with friends via encrypted file drops

---

## Quick Start

```bash
git clone https://github.com/Echo-Computing/echo-pgp-webui
cd echo-pgp-webui
pip install flask requests gnupg

# Configure your identity
export PGP_SENDER_ID="you@yourdomain.com"
export PGP_DIR="$HOME/.gnupg"        # your GPG home directory
export PGP_DB_PATH="$HOME/.gnupg/messages.db"  # SQLite database (default: PGP_DIR/messages.db)
export PGP_WEBUI_PORT=8765

python3 pgp_webui.py
# Opens http://localhost:8765
```

---

## Setup Guide

### 1. Prerequisites

- **Python 3.8+** — [python.org](https://python.org) or Windows Store
- **GnuPG** — see OS-specific instructions below
- **Flask + requests** — `pip install flask requests`

Verify GPG is installed:

```bash
gpg --version
```

#### OS-Specific GPG Installation

**Windows (option A — Git Bash / MSYS2)**

GPG is bundled with Git. If you installed Git, you already have GPG:

```bash
# Verify
gpg --version
# Should show "gpg (GnuPG) 2.4.x" from "C:\Program Files\Git\usr\bin\gpg.exe"
```

**Windows (option B — GnuPG standalone)**
- Download from [gpg4win.org](https://www.gpg4win.org) and install
- The web UI auto-detects `C:\Program Files (x86)\GnuPG\bin\gpg.exe`

**WSL (Windows Subsystem for Linux)**

```bash
sudo apt update && sudo apt install gnupg
# Verify
gpg --version
```

Set your GPG home dir to a WSL-native path:

```bash
export GNUPGHOME="$HOME/.gnupg"
export PGP_DIR="$HOME/.gnupg"
```

> **Note:** If you switch between Windows GPG and WSL GPG with the same homedir,
> key permissions and agent sockets can conflict. Use separate homedirs per environment.

**macOS**

```bash
brew install gnupg
# Verify
gpg --version
```

**Linux (Debian/Ubuntu)**

```bash
sudo apt update && sudo apt install gnupg
# Verify
gpg --version
```

**Linux (Fedora/RHEL)**

```bash
sudo dnf install gnupg
# Verify
gpg --version
```

**Linux (Arch)**

```bash
sudo pacman -S gnupg
# Verify
gpg --version
```

### 2. GPG Directory Layout

Your `PGP_DIR` should contain:

```
~/.gnupg/
├── private-keys-v1.d/     # your private keys (NEVER share these)
├── public-keys-v1.d/       # imported friends' public keys
├── trustdb.gpg
└── gpg.conf
```

On Windows, GPG's home is typically:
- **Git Bash / MSYS2:** `C:\Program Files\Git\usr\bin\gpg.exe` (auto-detected)
- **GnuPG standalone:** `C:\Program Files (x86)\GnuPG\bin\gpg.exe`

### 3. Generate Your Own PGP Key (First Time)

```bash
gpg --full-generate-key
# Choose RSA 4096, your email, and a strong passphrase
```

### 4. Configure the Web UI

| Environment Variable | Required | Default | Description |
|---|---|---|---|
| `PGP_SENDER_ID` | **Yes** | — | Your sending key — email or key ID (e.g. `you@example.com`) |
| `PGP_DIR` | No | `~/.gnupg` | Path to your GPG home directory |
| `PGP_DB_PATH` | No | `PGP_DIR/messages.db` | Path to SQLite database for message storage |
| `PGP_WEBUI_PORT` | No | `8765` | Port to listen on |
| `PGP_CLIPBOARD_CLEAR_SECONDS` | No | `30` | Auto-clear clipboard after N seconds |
| `PGP_MAX_ATTEMPTS` | No | `5` | Failed decrypt attempts before lockout |
| `SECRET_KEY` | No | random | Flask session secret |

---

## Friend-to-Friend Encrypted Messaging

### Exchanging Keys (Both Sides)

**You → Friend:** Export and share your public key

```bash
gpg --armor --export your@email.com > my_public_key.asc
```

**Friend → You:** They do the same and send you their `.asc` file.

### Import Your Friend's Key

1. Go to **Keys** in the navigation bar
2. Paste their public key block into the import box
3. Click **Import Key**

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

hQGMAwQh...
... (their full public key)
-----END PGP PUBLIC KEY BLOCK-----
```

### Send an Encrypted Message

1. Go to **Compose**
2. Select your friend from the **Recipient** dropdown
3. Type your message
4. Click **Encrypt & Save** — saves `replyN.asc` to your `PGP_DIR`
5. Send the `.asc` file to your friend via any channel (email, Signal, file drop)

### Decrypt a Received Message

1. Go to **Compose**
2. In the **Decrypt** panel, paste the `.asc` content
3. Click **Decrypt** — the plaintext appears below

---

## AI Model Integration

Use the Web UI as a local API for AI pipelines that need encrypted I/O.

### With Local LLMs (LM Studio, Ollama, etc.)

```python
import requests

# Encrypt your prompt before sending to local AI
response = requests.post("http://localhost:8765/encrypt", json={
    "plaintext": "Summarize this document...",
    "recipient": "friend@friend.com"
})
ciphertext = response.json()["ciphertext"]

# Send ciphertext to AI, get encrypted response back...
# Then decrypt locally:
decrypted = requests.post("http://localhost:8765/decrypt", json={
    "ciphertext": ai_response_ciphertext
})
print(decrypted.json()["plaintext"])
```

### Via CLI (script-friendly)

```bash
# Encrypt — pipe plaintext to gpg, save as .asc
echo "Hello world" | gpg --armor --encrypt --recipient friend@friend.com \
  --output message.asc

# Decrypt — read .asc file, output to stdout
gpg --decrypt message.asc

# Or use the web UI's compose endpoint directly:
curl -X POST http://localhost:8765/compose \
  -d "action=decrypt" \
  -d "ciphertext=$(cat message.asc)"
```

### AI-as-a-Judgment Use Case

Encrypt sensitive documents client-side (in-browser or via this UI) before sending to an AI API — the AI never sees plaintext, only the encrypted blob. You decrypt the response locally.

```python
# Full example: encrypt → send to AI API → decrypt response
import requests, json

plaintext = "Here's my medical record, please summarize..."
recipient = "ai-service@openai.com"  # the AI service's public key

# Encrypt first
enc_resp = requests.post("http://localhost:8765/compose", data={
    "action": "encrypt",
    "message": plaintext,
    "recipient": recipient
})

# Send to AI (AI decrypts with its private key, re-encrypts response to you)
ai_response = callservice(key=enc_resp["ciphertext"])

# Decrypt AI's response
dec_resp = requests.post("http://localhost:8765/compose", data={
    "action": "decrypt",
    "ciphertext": ai_response.encrypted_blob
})
print(dec_resp["plaintext"])
```

---

## Security Features

### Confirmation Guard
The **Settings → Confirmation Guard** adds a passphrase prompt before encrypt/decrypt operations. Useful on shared machines.

### GPG Agent

The GPG Agent (`gpg-agent`) is a daemon that comes bundled with GPG — you don't install it separately. It caches your private key passphrase in memory so you don't have to retype it on every operation.

**Do home users need it?** It depends on your setup:

- **Local AI only, single-user machine, no roommates/partners:** GPG Agent is optional. You'll be prompted for your passphrase each time you encrypt/decrypt. If you prefer not to deal with this, GPG Agent caches it for you automatically once started.
- **Shared machine, even at home:** GPG Agent is recommended — set a short cache TTL (see below).
- **AI running on a different machine than the web UI:** GPG Agent runs wherever your private keys are (i.e., the machine running the web UI).

**Check if GPG Agent is running:**

```bash
gpg-agent --version          # confirms it's installed
gpgconf --list-dir agent     # shows agent socket path
```

**Configure passphrase cache TTL** (optional — add to `~/.gnupg/gpg.conf` or `%APPDATA%\gnupg\gpg.conf`):

```
default-cache-ttl 3600       # cache passphrase for 1 hour
max-cache-ttl 86400          # max cache time: 24 hours
```

**Restart agent after changing config:**

```bash
gpgconf --kill gpg-agent    # stop
gpg-agent --daemon          # start fresh (or just start the web UI)
```

The **Settings → Kill Agent** button in the web UI does both steps — kills the agent and relaunches it with a fresh cache.

**WSL特别注意:** If you're using WSL GPG with the web UI on Windows, make sure both environments use the same `GNUPGHOME` path or different homedirs to avoid socket conflicts.

### Clipboard Auto-Clear
Decrypted plaintext is copied to clipboard and auto-clears after 30 seconds (configurable via `PGP_CLIPBOARD_CLEAR_SECONDS`).

### Lockout
After 5 failed decrypt attempts (wrong key/passphrase), the UI locks for 5 minutes.

---

## File Layout

```
echo-pgp-webui/
├── pgp_webui.py       # Flask application — all routes, DB logic, and Jinja templates inline
├── README.md
├── LICENSE
└── .gitignore

PGP_DIR/               # set via PGP_DIR env var (default: script's parent directory)
├── messages.db        # SQLite — message metadata + encrypted payloads
├── reply0.asc         # encrypted output files (reply{N}.asc, sequential)
├── reply1.asc
├── sent_log.json      # legacy log (updated on new sends for backwards compat)
├── inbox/             # received .asc files (auto-scanned on first load)
└── .tmp_*.asc         # temp files (cleaned up after decrypt/import)
```

### SQLite Database Schema

The `messages.db` stores all message metadata and encrypted payloads:

```sql
CREATE TABLE messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,        -- ISO 8601, e.g. "2026-03-30T03:14:47"
    sender          TEXT    NOT NULL,        -- your identity (PGP_SENDER_ID)
    recipient       TEXT    NOT NULL,        -- recipient email/key ID
    subject         TEXT    DEFAULT '',
    file_path       TEXT    DEFAULT '',      -- path to .asc file on disk
    content_hash    TEXT    NOT NULL,        -- SHA-256 of encrypted payload
    verified        INTEGER DEFAULT 0,       -- GPG signature verification
    encrypted_payload TEXT  NOT NULL,        -- full ASCII-armored PGP message
    created_at      TEXT    DEFAULT (datetime('now'))
);

CREATE INDEX idx_recipient    ON messages(recipient);
CREATE INDEX idx_timestamp   ON messages(timestamp);
CREATE INDEX idx_sender      ON messages(sender);
```

> **Security:** The `encrypted_payload` column holds the full ASCII-armored PGP message — private keys never leave the GPG keyring, only the ciphertext is in the DB.

---

## API Reference

### REST API — `/api/*`

All `/api/*` endpoints accept and return JSON. Use this for programmatic access.

#### `POST /api/messages`

Encrypt and store a new message. Stores in SQLite DB and writes `.asc` file to disk.

```bash
curl -X POST http://localhost:8765/api/messages \
  -H "Content-Type: application/json" \
  -d '{"recipient": "friend@example.com", "plaintext": "Hello!", "subject": "Hi"}'
```

**Response:**
```json
{
  "id": 106,
  "timestamp": "2026-03-30T12:00:00.000Z",
  "recipient": "friend@example.com",
  "subject": "Hi",
  "file": "reply106.asc",
  "content_hash": "a1b2c3..."
}
```

#### `GET /api/messages`

List messages with optional filters. Returns message metadata (not plaintext).

```bash
# All messages, most recent first
curl "http://localhost:8765/api/messages"

# Filter by recipient
curl "http://localhost:8765/api/messages?recipient=friend@example.com"

# Messages since a date
curl "http://localhost:8765/api/messages?since=2026-03-01"

# Pagination
curl "http://localhost:8765/api/messages?limit=20&offset=40"
```

**Response:**
```json
[
  {
    "id": 106,
    "timestamp": "2026-03-30T12:00:00",
    "sender": "you@yourdomain.com",
    "recipient": "friend@example.com",
    "subject": "Hi",
    "file_path": "D:/pgp/reply106.asc",
    "content_hash": "a1b2c3..."
  }
]
```

#### `GET /api/messages/<id>`

Decrypt and return a single message by ID.

```bash
curl "http://localhost:8765/api/messages/106"
```

**Response:**
```json
{
  "id": 106,
  "timestamp": "2026-03-30T12:00:00",
  "sender": "you@yourdomain.com",
  "recipient": "friend@example.com",
  "subject": "Hi",
  "plaintext": "Hello!",
  "content_hash": "a1b2c3..."
}
```

#### `DELETE /api/messages/<id>`

Delete a message from both SQLite DB AND the `.asc` file on disk.

```bash
curl -X DELETE "http://localhost:8765/api/messages/106"
```

#### `POST /api/wipe`

**Kill GPG agent, wipe all messages from DB, delete all `.asc` files in `PGP_DIR`.** Irreversible.

```bash
curl -X POST "http://localhost:8765/api/wipe" \
  -H "Content-Type: application/json" \
  -d '{"confirm": "yes"}'
```

---

### Web UI — `POST /compose`

Encrypt or decrypt a message.

**Encrypt:**
```
POST /compose
Content-Type: application/x-www-form-urlencoded

action=encrypt
message=Hello world
recipient=friend@email.com
subject=Greeting          # optional
```

**Decrypt:**
```
POST /compose
Content-Type: application/x-www-form-urlencoded

action=decrypt
ciphertext=-----BEGIN PGP MESSAGE-----...
local_user=you@email.com    # optional — auto-detected if omitted
```

### `GET /keys`
View all public keys in your keyring.

### `POST /keys`
Import or delete public keys.

**Import:**
```
POST /keys
action=import
key_data=-----BEGIN PGP PUBLIC KEY BLOCK-----...
```

**Delete:**
```
POST /keys
action=delete
key_id=ABC123DEF456
```

---

### Web UI Routes

| Route | Methods | Description |
|-------|---------|-------------|
| `/compose` | GET, POST | Encrypt or decrypt messages |
| `/inbox` | GET | View all messages (lazy decrypt — click to reveal) |
| `/inbox/decrypt_file/<filename>` | GET | Decrypt a file inline (lazy decrypt) |
| `/inbox/raw/<filename>` | GET | Serve raw `.asc` file content |
| `/inbox/delete_file/<filename>` | DELETE | Delete a disk-scanned `.asc` file (not tracked in DB) |
| `/sent` | GET | View sent log |
| `/sent/clear` | GET | Clear sent_log.json |
| `/keys` | GET, POST | Key management — list, import, delete public keys |
| `/keys/delete/<filename>` | DELETE | Delete a public key file from disk |
| `/settings` | GET, POST | Settings — GPG homedir, confirmation guard, dark mode |
| `/settings/kill-agent` | GET | Kill gpg-agent, clear passphrase cache |
| `/toggle-dark` | POST | Toggle dark mode (cookie-based) |
| `/api/messages` | GET, POST | REST API — list or create messages |
| `/api/messages/<id>` | GET, DELETE | REST API — decrypt or delete single message |
| `/api/wipe` | POST | Kill GPG agent, wipe DB, delete all `.asc` files |
| `/health` | GET | Health check endpoint |

---

## Troubleshooting

### `gpg: error:哽嚥踝: no such user ID` — Recipient not found
You haven't imported your friend's public key yet. Go to **Keys → Import a Friend's Public Key** and paste their `.asc` block.

### `gpg: keyserver receive failed: No data` — Key import failed
The key block may be malformed. Make sure you copied the full `-----BEGIN PGP PUBLIC KEY BLOCK-----` through `-----END PGP PUBLIC KEY BLOCK-----` lines.

### `FileNotFoundError: [WinError 2] The system cannot find the file specified`
GPG isn't in your system PATH. This is fixed in the latest version by auto-detecting the GPG binary. Make sure you're running the [latest release](https://github.com/Echo-Computing/echo-pgp-webui/releases).

### GPG asks for passphrase on every operation
The GPG agent is caching the passphrase for a limited time. Use `gpgconf --kill gpg-agent` to restart it, or set `default-cache-ttl 86400` in your `gpg.conf` for 24-hour caching.

---

## Production Deployment

**Do not** use Flask's built-in dev server (`python pgp_webui.py`) in production. Use a WSGI server:

```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:8765 pgp_webui:app
```

Or behind a reverse proxy (nginx/Caddy) with HTTPS.

---

## License

MIT — See [LICENSE](LICENSE) for details.
