#!/usr/bin/env python3
"""
PGP Web UI — standalone Flask interface for encrypt/decrypt operations.

PGP Vault Web UI
Run: python3 pgp_webui.py
Opens: http://localhost:8765
"""
import logging
import os
import shutil
import sys
import json
import subprocess
import time
import threading
import re
import sqlite3
import hmac
import html
import hashlib
import secrets
import ssl
import socket
import traceback
import argparse
from pathlib import Path
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# ── Paths (all configurable via env vars) ────────────────────────────────────
# PGP_DIR: directory for keys, reply*.asc files, sent_log.json
# DB_PATH: path to SQLite messages.db (defaults to PGP_DIR/messages.db)
_MEIPASS = getattr(sys, '_MEIPASS', None)
if _MEIPASS:
    # Running as PyInstaller EXE — use user-writable LOCALAPPDATA
    import os
    _default_pgp_dir = os.path.expandvars('%LOCALAPPDATA%\\pgp_vault')
else:
    _default_pgp_dir = str(Path(__file__).parent.resolve())

_PGP_DIR_ENV = os.environ.get('PGP_DIR', _default_pgp_dir)
PGP_DIR = Path(_PGP_DIR_ENV)
DB_PATH = Path(os.environ.get('PGP_DB_PATH', str(PGP_DIR / 'messages.db')))

# ─── Multi-user configuration ────────────────────────────────────────────────
USERS_DIR = PGP_DIR / 'users'
SESSION_COOKIE = 'pgp_session'
CSRF_COOKIE = 'pgp_csrf'
SESSION_EXPIRY_SECONDS = 86400 * 7   # 7 days
BRUTEFORCE_WINDOW_SECS = 15 * 60     # 15 minutes
BRUTEFORCE_MAX_ATTEMPTS = 5           # max failures per IP in window
BRUTEFORCE_LOCKOUT_SECS = 15 * 60     # 15 minute lockout
BRUTEFORCE_LOG = PGP_DIR / 'pgp_auth_attempts.log'
DARK_MODE_COOKIE = 'dm'

# SENDER_IDENTITY is set per-user at send time via g.current_user['pgp_key_email'].
# A module-level fallback is kept for legacy single-user mode only.
SENDER_IDENTITY = os.environ.get('PGP_SENDER_ID', 'changeme@vault.local')

_auth_logger = None
def _get_auth_logger():
    global _auth_logger
    if _auth_logger is None:
        _auth_logger = logging.getLogger('pgp_auth')
        _auth_logger.setLevel(logging.INFO)
        _auth_logger.propagate = False
        handler = logging.FileHandler(str(BRUTEFORCE_LOG), encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        _auth_logger.addHandler(handler)
    return _auth_logger

# Thread-local for session and user DB connections
_thread_local = threading.local()

# ─── Auth token for API clients ───────────────────────────────────────
_AUTH_TOKEN_FILE = PGP_DIR / '.auth_token'

def _load_auth_token():
    if _AUTH_TOKEN_FILE.exists():
        return _AUTH_TOKEN_FILE.read_text().strip()
    token = secrets.token_hex(32)
    try:
        _AUTH_TOKEN_FILE.write_text(token)
        _AUTH_TOKEN_FILE.chmod(0o600)
    except Exception:
        pass
    return token

AUTH_TOKEN = os.environ.get('PGP_AUTH_TOKEN', _load_auth_token())

# ─── TLS certificates ───────────────────────────────────────────────────────────
CERT_PATH = PGP_DIR / 'pgpvault.crt'
KEY_PATH = PGP_DIR / 'pgpvault.key'
CA_CERT_PATH = PGP_DIR / 'pgpvault-ca.crt'

# Resolve gpg executable at startup — avoids FileNotFoundError on Windows where
# Python subprocess doesn't always inherit the shell's PATH.
def _resolve_gpg():
    gpg = shutil.which('gpg') or shutil.which('gpg2')
    if gpg and Path(gpg).exists():
        return gpg
    for candidate in [
        Path('C:/Program Files/Git/usr/bin/gpg.exe'),
        Path('C:/Program Files (x86)/GnuPG/bin/gpg.exe'),
    ]:
        if candidate.exists():
            return str(candidate)
    return 'gpg'

GPG_BIN = _resolve_gpg()

try:
    from flask import Flask, request, render_template_string, jsonify, redirect, url_for
    from flask_cors import CORS
except ImportError:
    print("[ERROR] Flask and flask-cors are required: pip install flask flask-cors")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)
app = Flask(__name__)
app.config['PGP_DIR'] = PGP_DIR
app.config['DB_PATH'] = DB_PATH

# Enable CORS for API clients — restricted to same origin
CORS(app, resources={r"/api/*": {"origins": os.environ.get('PGP_CORS_ORIGINS', '').split(',') if os.environ.get('PGP_CORS_ORIGINS') else []}})


@app.after_request
def set_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; connect-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response


# ─── CSRF Protection ──────────────────────────────────────────────────────────

def _generate_csrf_token():
    """Generate a CSRF token and store it in the session DB."""
    token = secrets.token_hex(32)
    return token


def csrf_token():
    """Get CSRF token from cookie, or generate a new one if missing."""
    token = request.cookies.get(CSRF_COOKIE)
    if token:
        return token
    token = getattr(g, '_csrf_token', None)
    if not token:
        token = secrets.token_hex(32)
        g._csrf_token = token
    return token


def csrf_input():
    """Return HTML hidden input for CSRF token."""
    return f'<input type="hidden" name="csrf_token" value="{html.escape(csrf_token())}">'


def _set_csrf_cookie(resp):
    """Set CSRF cookie on response if a new token was generated this request."""
    new_token = getattr(g, '_csrf_token', None)
    if new_token:
        resp.set_cookie(CSRF_COOKIE, new_token, max_age=SESSION_EXPIRY_SECONDS,
                        httponly=True, samesite='Lax', secure=True)
    return resp


def validate_csrf():
    """Validate CSRF token from form submission against cookie. Returns True if valid."""
    form_token = request.form.get('csrf_token', '')
    cookie_token = request.cookies.get(CSRF_COOKIE, '')
    if not form_token or not cookie_token:
        return False
    return hmac.compare_digest(form_token, cookie_token)


def csrf_protect(f):
    """Decorator that validates CSRF token on POST requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST' and not validate_csrf():
            return '<h1>403 Forbidden</h1><p>CSRF token validation failed. Please try again.</p>', 403
        return f(*args, **kwargs)
    return decorated

# ─── Session DB Infrastructure ─────────────────────────────────────────────────

def _get_session_db() -> sqlite3.Connection:
    """Get thread-local session DB connection (users + sessions + login_attempts)."""
    if not hasattr(threading.current_thread(), '_session_db') or threading.current_thread()._session_db is None:
        conn = sqlite3.connect(str(PGP_DIR / 'sessions.db'), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        _init_session_db_schema(conn)
        threading.current_thread()._session_db = conn
    return threading.current_thread()._session_db


def _init_session_db_schema(conn: sqlite3.Connection):
    """Initialize session DB schema (users + sessions + login_attempts tables)."""
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            pgp_key_email TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            is_admin INTEGER DEFAULT 0
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username TEXT,
            attempted_at TEXT DEFAULT (datetime('now')),
            success INTEGER DEFAULT 0
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip_address)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_attempts_username ON login_attempts(username)')
    conn.commit()


def check_login_attempts(ip_address: str, username: str = None) -> tuple[bool, str]:
    """
    Check if IP or username is locked out due to too many failed attempts.
    Returns (blocked, reason).
    """
    conn = _get_session_db()
    cutoff = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    # Purge attempts older than 2 hours
    conn.execute(
        "DELETE FROM login_attempts WHERE attempted_at < datetime('now', '-2 hours')"
    )
    conn.commit()

    # Check IP lockout: 5 failures in 15-minute window
    ip_failures = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND success = 0 AND attempted_at > datetime('now', '-15 minutes')",
        (ip_address,)
    ).fetchone()[0]
    if ip_failures >= BRUTEFORCE_MAX_ATTEMPTS:
        return True, f'IP locked due to {ip_failures} failed attempts. Try again in 15 minutes.'

    # Check username lockout: 3 failures in 15-minute window
    if username:
        user_failures = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND success = 0 AND attempted_at > datetime('now', '-15 minutes')",
            (username,)
        ).fetchone()[0]
        if user_failures >= 3:
            return True, f'Account locked due to {user_failures} failed attempts. Contact admin to unlock.'

    return False, ''


def record_failed_attempt(ip_address: str, username: str = None):
    """Record a failed login attempt."""
    conn = _get_session_db()
    conn.execute(
        "INSERT INTO login_attempts (ip_address, username, success) VALUES (?, ?, 0)",
        (ip_address, username)
    )
    conn.commit()
    auth_log = _get_auth_logger()
    auth_log.warning('LOGIN FAILED ip=%s user=%s', ip_address, username or 'unknown')


def record_login_attempt(ip_address: str, username: str, success: bool):
    """Record a login attempt (success or failure)."""
    conn = _get_session_db()
    conn.execute(
        "INSERT INTO login_attempts (ip_address, username, success) VALUES (?, ?, ?)",
        (ip_address, username, 1 if success else 0)
    )
    conn.commit()
    auth_log = _get_auth_logger()
    if success:
        auth_log.info('LOGIN SUCCESS ip=%s user=%s', ip_address, username)
    else:
        auth_log.warning('LOGIN FAILED ip=%s user=%s', ip_address, username)


def clear_failed_attempts(ip_address: str, username: str = None):
    """Clear failed attempts on successful login."""
    conn = _get_session_db()
    if username:
        conn.execute(
            "DELETE FROM login_attempts WHERE ip_address = ? AND username = ?",
            (ip_address, username)
        )
    else:
        conn.execute(
            "DELETE FROM login_attempts WHERE ip_address = ?",
            (ip_address,)
        )
    conn.commit()


def admin_clear_lockout(ip_address: str = None, username: str = None) -> int:
    """Admin: clear lockout for a specific IP or username. Returns rowcount."""
    conn = _get_session_db()
    if ip_address:
        result = conn.execute(
            "DELETE FROM login_attempts WHERE ip_address = ? AND success = 0",
            (ip_address,)
        )
    elif username:
        result = conn.execute(
            "DELETE FROM login_attempts WHERE username = ? AND success = 0",
            (username,)
        )
    else:
        return 0
    conn.commit()
    return result.rowcount


def create_session(user_id: int) -> str:
    """Create a new session for a user. Returns session ID."""
    session_id = secrets.token_hex(32)
    expires_at = datetime.fromtimestamp(
        datetime.utcnow().timestamp() + SESSION_EXPIRY_SECONDS
    ).strftime('%Y-%m-%d %H:%M:%S')
    conn = _get_session_db()
    # Purge expired sessions on each login to prevent accumulation
    conn.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")
    conn.execute(
        "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
        (session_id, user_id, expires_at)
    )
    conn.commit()
    return session_id


def get_session_user(session_id: str) -> dict:
    """Look up a session and return the user dict if valid and not expired."""
    conn = _get_session_db()
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    row = conn.execute('''
        SELECT u.id, u.username, u.pgp_key_email, u.is_admin, u.created_at,
               s.created_at as session_created, s.expires_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.id = ? AND s.expires_at > ?
    ''', (session_id, now)).fetchone()
    if not row:
        return None
    return dict(row)


def delete_session(session_id: str):
    """Delete a session (logout)."""
    conn = _get_session_db()
    conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
    conn.commit()


def admin_required(f):
    """Decorator requiring a valid admin session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import g
        if not hasattr(g, 'current_user') or not g.current_user:
            return redirect(url_for('login_page'))
        if g.current_user.get('is_admin') != 1:
            return '<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p>', 403
        return f(*args, **kwargs)
    return decorated


@app.before_request
def auth_middleware():
    """Authenticate user via session cookie, skip for public routes."""
    from flask import g, redirect
    g.current_user = None
    # Public routes — no auth required
    if request.path in ('/health', '/favicon.ico', '/login'):
        return
    if request.method == 'OPTIONS':
        return
    # API paths: Bearer token auth
    if request.path.startswith('/api/'):
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            if secrets.compare_digest(token, AUTH_TOKEN):
                # API access with valid token — set a minimal g.current_user
                g.current_user = {'username': 'api', 'pgp_key_email': 'api', 'is_admin': 0}
                return
        # Invalid or missing token — reject
        return jsonify({'error': 'Unauthorized'}), 401
    # All other routes: session cookie required
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        user = get_session_user(session_id)
        if user:
            g.current_user = user
            return
    # No valid session — redirect to login
    if request.path.startswith('/admin/'):
        from flask import make_response
        return make_response(redirect(url_for('login_page')))
    if not request.path.startswith('/static'):
        return redirect(url_for('login_page'))


def get_user_db(username: str = None) -> sqlite3.Connection:
    """
    Get a user's personal messages.db connection.
    Uses current user if username is None.
    Per-user DB lives at users/{username}/messages.db
    """
    import html
    if username is None:
        from flask import g
        if hasattr(g, 'current_user') and g.current_user:
            username = g.current_user['username']
        else:
            raise ValueError('No username and no current user in request context')
    # Validate username to prevent path traversal
    if not re.match(r'^[a-zA-Z0-9_.-]{1,64}$', username):
        raise ValueError(f'Invalid username: {username}')
    user_dir = USERS_DIR / username
    user_dir.mkdir(parents=True, exist_ok=True)
    user_db = user_dir / 'messages.db'
    conn = sqlite3.connect(str(user_db), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    _init_db_schema(conn)
    return conn


# Global error handler — log unhandled exceptions but let Flask handle HTTP errors normally
@app.errorhandler(Exception)
def handle_exception(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return None  # Let Flask handle HTTP exceptions (404, 405, etc.) normally
    logger.exception("Unhandled exception: %s", e)
    return "<h1>Internal Server Error</h1><p>An unexpected error occurred.</p>", 500

# ─── Login / Logout ─────────────────────────────────────────────────────────────

def _get_login_form(error=''):
    """Render the login form HTML with CSRF token."""
    csrf = csrf_input()
    error_html = f'<div class="alert error">{error}</div>' if error else ''
    return f'''
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Login — PGP Vault</title>
      <style>
        body {{ background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
        .login-box {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 2rem; width: 360px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }}
        h1 {{ color: #58a6ff; font-size: 1.2rem; margin-bottom: 1.5rem; text-align: center; }}
        label {{ display: block; color: #8b949e; font-size: 0.85rem; margin-bottom: 0.3rem; }}
        input {{ width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; padding: 0.6rem; font-size: 0.9rem; box-sizing: border-box; margin-bottom: 1rem; }}
        input:focus {{ outline: none; border-color: #58a6ff; }}
        button {{ width: 100%; background: #238636; border: none; border-radius: 6px; color: #fff; padding: 0.7rem; font-size: 0.9rem; cursor: pointer; font-weight: 500; }}
        button:hover {{ background: #2ea043; }}
        .error {{ background: #2d1117; border: 1px solid #f85149; color: #f85149; border-radius: 6px; padding: 0.8rem; margin-bottom: 1rem; font-size: 0.85rem; }}
        p {{ color: #8b949e; font-size: 0.8rem; text-align: center; margin-top: 1rem; }}
      </style>
    </head>
    <body>
    <div class="login-box">
      <h1>🔐 PGP Vault</h1>
      {error_html}
      <form method="post">
        {csrf}
        <label for="username">Username</label>
        <input type="text" name="username" id="username" autocomplete="username" autofocus required>
        <label for="password">Password</label>
        <input type="password" name="password" id="password" autocomplete="current-password" required>
        <button type="submit">Sign In</button>
      </form>
      <p>Ask your admin to create an account.</p>
    </div>
    </body>
    </html>'''


@app.route('/login', methods=['GET', 'POST'])
@csrf_protect
def login_page():
    """Login page with session-based authentication."""
    if request.method == 'GET':
        resp = app.make_response(_get_login_form())
        _set_csrf_cookie(resp)
        return resp

    ip_address = request.remote_addr or '127.0.0.1'
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password', '')

    # Check brute-force lockout first
    blocked, block_reason = check_login_attempts(ip_address, username)
    if blocked:
        resp = app.make_response(_get_login_form(f'Account locked: {block_reason}'))
        _set_csrf_cookie(resp)
        return resp, 429

    # Look up user
    conn = _get_session_db()
    user_row = conn.execute(
        'SELECT * FROM users WHERE username = ?', (username,)
    ).fetchone()

    if user_row and check_password_hash(user_row['password_hash'], password):
        # Successful login
        clear_failed_attempts(ip_address, username)
        record_login_attempt(ip_address, username, success=True)
        session_id = create_session(user_row['id'])
        resp = app.make_response(redirect(url_for('compose')))
        resp.set_cookie(SESSION_COOKIE, session_id, max_age=SESSION_EXPIRY_SECONDS,
                        httponly=True, samesite='Lax', secure=True)
        resp.set_cookie(CSRF_COOKIE, csrf_token(), max_age=SESSION_EXPIRY_SECONDS,
                        httponly=True, samesite='Lax', secure=True)
        return resp
    else:
        # Failed login
        record_login_attempt(ip_address, username, success=False)
        # Refresh lockout check after recording
        blocked, block_reason = check_login_attempts(ip_address, username)
        if blocked:
            resp = app.make_response(_get_login_form(f'Login failed. {block_reason}'))
            _set_csrf_cookie(resp)
            return resp, 429
        resp = app.make_response(_get_login_form('Invalid username or password'))
        _set_csrf_cookie(resp)
        return resp, 401


@app.route('/logout', methods=['POST'])
@csrf_protect
def logout():
    """Clear session cookie and redirect to login."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        delete_session(session_id)
    resp = app.make_response(redirect(url_for('login_page')))
    resp.set_cookie(SESSION_COOKIE, '', expires=0)
    resp.set_cookie(CSRF_COOKIE, '', expires=0)
    return resp


# ─── Admin Routes ───────────────────────────────────────────────────────────────

@app.route('/admin/audit', methods=['GET'])
@admin_required
def admin_audit():
    """Show failed login attempts log."""
    import html
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    conn = _get_session_db()
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    # Failed attempts in last 24h
    recent = conn.execute('''
        SELECT ip_address, username, attempted_at, success
        FROM login_attempts
        WHERE attempted_at > datetime('now', '-24 hours')
        ORDER BY attempted_at DESC
        LIMIT 200
    ''').fetchall()

    # Currently locked IPs (5+ failures in 15-min window)
    locked_ips = conn.execute('''
        SELECT ip_address, COUNT(*) as c FROM login_attempts
        WHERE success = 0 AND attempted_at > datetime('now', '-15 minutes')
        GROUP BY ip_address HAVING c >= ?
    ''', (BRUTEFORCE_MAX_ATTEMPTS,)).fetchall()

    # Currently locked usernames
    locked_users = conn.execute('''
        SELECT username, COUNT(*) as c FROM login_attempts
        WHERE success = 0 AND attempted_at > datetime('now', '-15 minutes') AND username IS NOT NULL
        GROUP BY username HAVING c >= 3
    ''').fetchall()

    rows_html = ''
    for r in recent:
        status = '✅' if r['success'] else '❌'
        rows_html += f'''<tr>
          <td>{html.escape(r['ip_address'])}</td>
          <td>{html.escape(r['username'] or '—')}</td>
          <td>{r['attempted_at']}</td>
          <td>{status}</td>
        </tr>'''

    locked_ips_html = ''
    for r in locked_ips:
        locked_ips_html += f'''<tr><td>{html.escape(r['ip_address'])}</td><td>{r['c']} failures</td><td>
        <form method="post" action="{url_for('admin_unlock')}">
          {csrf_input()}
          <input type="hidden" name="ip_address" value="{html.escape(r['ip_address'])}">
          <button type="submit" class="btn small danger">Unlock</button>
        </form></td></tr>'''

    locked_users_html = ''
    for r in locked_users:
        locked_users_html += f'''<tr><td>{html.escape(r['username'])}</td><td>{r['c']} failures</td><td>
        <form method="post" action="{url_for('admin_unlock')}">
          {csrf_input()}
          <input type="hidden" name="username" value="{html.escape(r['username'])}">
          <button type="submit" class="btn small danger">Unlock</button>
        </form></td></tr>'''

    body = f'''
    <div class="alert info">Failed login attempts in the last 24 hours.</div>
    <div class="card">
    <h2>Locked Out</h2>
    <table><thead><tr><th>IP / Username</th><th>Failures</th><th>Action</th></tr></thead>
    <tbody>
    {locked_ips_html}{locked_users_html}
    </tbody></table>
    {"<p style='color:#8b949e;padding:1rem'>No accounts currently locked.</p>" if not locked_ips and not locked_users else ""}
    </div>
    <div class="card">
    <h2>Recent Attempts</h2>
    <table><thead><tr><th>IP</th><th>Username</th><th>Time</th><th>Result</th></tr></thead>
    <tbody>{rows_html}</tbody></table>
    {"<p style='color:#8b949e;padding:1rem'>No attempts in the last 24 hours.</p>" if not recent else ""}
    </div>'''
    return render('Login Audit', 'admin_audit', body, dark)


@app.route('/admin/unlock', methods=['POST'])
@admin_required
@csrf_protect
def admin_unlock():
    """Admin: clear a lockout by IP or username."""
    ip_address = request.form.get('ip_address', '').strip()
    username = request.form.get('username', '').strip()
    count = admin_clear_lockout(ip_address=ip_address or None, username=username or None)
    resp = app.make_response(redirect(url_for('admin_audit')))
    if count > 0:
        resp.set_cookie('flash', f'Unlocked {count} record(s)', max_age=30, samesite='Lax', secure=True)
    return resp


@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
@csrf_protect
def admin_users():
    """Admin: create, list, and delete user accounts."""
    import html
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    msg = request.cookies.get('flash', '')

    conn = _get_session_db()
    user_rows = conn.execute('SELECT id, username, pgp_key_email, is_admin, created_at FROM users ORDER BY created_at').fetchall()

    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'create':
            username = (request.form.get('username') or '').strip()
            password = request.form.get('password', '')
            password2 = request.form.get('password2', '')
            pgp_email = (request.form.get('pgp_email') or '').strip()
            is_admin = 1 if request.form.get('is_admin') else 0

            if not username or not password or not pgp_email:
                msg = '<div class="alert error">All fields are required.</div>'
            elif len(password) < 8:
                msg = '<div class="alert error">Password must be at least 8 characters.</div>'
            elif password != password2:
                msg = '<div class="alert error">Passwords do not match.</div>'
            elif not re.match(r'^[a-zA-Z0-9_.-]{1,64}$', username):
                msg = '<div class="alert error">Username may only contain letters, numbers, dots, dashes, and underscores (max 64 chars).</div>'
            elif not re.match(r'^[^\s<>:@/\\]+@[^\s<>:@/\\]+$', pgp_email):
                msg = '<div class="alert error">Invalid email address.</div>'
            else:
                existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
                if existing:
                    msg = '<div class="alert error">Username already exists.</div>'
                else:
                    pw_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=32)
                    conn.execute(
                        'INSERT INTO users (username, password_hash, pgp_key_email, is_admin) VALUES (?, ?, ?, ?)',
                        (username, pw_hash, pgp_email, is_admin)
                    )
                    conn.commit()
                    # Create user directory
                    user_dir = USERS_DIR / username
                    user_dir.mkdir(parents=True, exist_ok=True)
                    # Generate GPG keypair for user
                    try:
                        _generate_gpg_key(username, pgp_email)
                        # Auto-import all existing users' pubkeys into new user's keyring so they can
                        # message any existing user immediately (contact discovery bootstrap).
                        for dirent in os.listdir(USERS_DIR):
                            if dirent == username:
                                continue
                            existing_pubkey = USERS_DIR / dirent / 'pubkey.asc'
                            if existing_pubkey.exists():
                                run_gpg_user(['--import', str(existing_pubkey)], username)
                        msg = f'<div class="alert success">User {html.escape(username)} created with GPG key.</div>'
                    except Exception as e:
                        msg = f'<div class="alert info">User {html.escape(username)} created but key generation failed: {html.escape(str(e))}. Create their GPG key manually.</div>'
                    user_rows = conn.execute('SELECT id, username, pgp_key_email, is_admin, created_at FROM users ORDER BY created_at').fetchall()

        elif action == 'delete':
            username = (request.form.get('username') or '').strip()
            if username == 'admin':
                msg = '<div class="alert error">Cannot delete the admin account.</div>'
            elif not re.match(r'^[a-zA-Z0-9_.-]{1,64}$', username):
                msg = '<div class="alert error">Invalid username.</div>'
            else:
                user_row = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
                if user_row:
                    # Delete sessions first
                    conn.execute('DELETE FROM sessions WHERE user_id = ?', (user_row['id'],))
                    conn.execute('DELETE FROM users WHERE username = ?', (username,))
                    conn.commit()
                    # Remove user directory
                    user_dir = USERS_DIR / username
                    if user_dir.exists():
                        shutil.rmtree(user_dir)
                    msg = f'<div class="alert success">User {html.escape(username)} deleted.</div>'
                    user_rows = conn.execute('SELECT id, username, pgp_key_email, is_admin, created_at FROM users ORDER BY created_at').fetchall()

        elif action == 'reset_password':
            user_id = (request.form.get('user_id') or '').strip()
            new_password = request.form.get('new_password', '')
            new_password2 = request.form.get('new_password2', '')
            if not new_password or new_password != new_password2:
                msg = '<div class="alert error">Passwords do not match or are empty.</div>'
            elif len(new_password) < 8:
                msg = '<div class="alert error">Password must be at least 8 characters.</div>'
            elif user_id.isdigit():
                pw_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=32)
                conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (pw_hash, int(user_id)))
                conn.commit()
                msg = '<div class="alert success">Password reset.</div>'

    user_rows_html = ''
    for u in user_rows:
        admin_badge = ' <span style="color:#d29922;font-size:0.75rem">[admin]</span>' if u['is_admin'] else ''
        user_rows_html += f'''<tr>
          <td>{html.escape(u['username'])}{admin_badge}</td>
          <td><code>{html.escape(u['pgp_key_email'])}</code></td>
          <td>{u['created_at'][:16]}</td>
          <td>
            <form method="post" style="display:inline">
              {csrf_input()}
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="username" value="{html.escape(u['username'])}">
              <button type="submit" class="btn small danger" onclick="return confirm('Delete user {html.escape(u["username"])}? This deletes all their messages.')">Delete</button>
            </form>
            <form method="post" style="display:inline">
              {csrf_input()}
              <input type="hidden" name="action" value="reset_password">
              <input type="hidden" name="user_id" value="{u['id']}">
              <input type="password" name="new_password" placeholder="New password" style="width:120px;margin-bottom:0">
              <input type="password" name="new_password2" placeholder="Confirm" style="width:120px;margin-bottom:0">
              <button type="submit" class="btn small">Reset</button>
            </form>
          </td>
        </tr>'''

    body = f'''
    {msg}
    <div class="card">
    <h2>User Accounts</h2>
    <table><thead><tr><th>Username</th><th>PGP Email</th><th>Created</th><th>Actions</th></tr></thead>
    <tbody>{user_rows_html}</tbody></table>
    </div>
    <div class="card">
    <h2>Create User</h2>
    <form method="post">
      {csrf_input()}
      <input type="hidden" name="action" value="create">
      <div class="form-row">
        <label for="username">Username</label>
        <input type="text" name="username" id="username" placeholder="alice" autocomplete="username" required pattern="[a-zA-Z0-9_.-]+">
      </div>
      <div class="form-row">
        <label for="pgp_email">PGP Email</label>
        <input type="email" name="pgp_email" id="pgp_email" placeholder="alice@vault.local" required>
      </div>
      <div class="form-row">
        <label for="password">Password</label>
        <input type="password" name="password" id="password" autocomplete="new-password" required>
      </div>
      <div class="form-row">
        <label for="password2">Confirm Password</label>
        <input type="password" name="password2" id="password2" autocomplete="new-password" required>
      </div>
      <div class="form-row">
        <label>
          <input type="checkbox" name="is_admin" value="1"> Make this user an admin
        </label>
      </div>
      <button type="submit" class="btn primary">Create User</button>
    </form>
    </div>'''
    return render('User Management', 'admin_users', body, dark)


def _generate_gpg_key(username: str, email: str):
    """Generate an RSA-4096 GPG keypair for a user in their personal homedir."""
    # Validate inputs to prevent GPG batch injection
    if not re.match(r'^[a-zA-Z0-9_.-]{1,64}$', username):
        raise ValueError(f'Invalid username: {username}')
    if not re.match(r'^[^\s<>:@/\\]+@[^\s<>:@/\\]+$', email):
        raise ValueError(f'Invalid email address: {email}')

    user_dir = USERS_DIR / username
    user_dir.mkdir(parents=True, exist_ok=True)
    gpg_home = user_dir / '.gnupg'
    gpg_home.mkdir(exist_ok=True)

    # Generate a random passphrase for the private key
    passphrase = secrets.token_hex(32)

    batch = (
        f'Key-Type: RSA\n'
        f'Key-Length: 4096\n'
        f'Subkey-Type: RSA\n'
        f'Subkey-Length: 4096\n'
        f'Name-Real: {username}\n'
        f'Name-Email: {email}\n'
        f'Expire-Date: 0\n'
        f'Passphrase: {passphrase}\n'
        f'%commit\n'
    ).encode()

    tmp = PGP_DIR / (f'.keygen_{secrets.token_hex(8)}.batch')
    tmp.write_bytes(batch)
    try:
        # Generate key in user's personal homedir
        run_gpg(['--batch', '--gen-key', '--homedir', str(gpg_home), str(tmp)],
                input_text=None, input_file=None)
        # Export public key to users/{username}/pubkey.asc
        pub_out, err, code = run_gpg(
            ['--homedir', str(gpg_home), '--armor', '--export', email],
            input_text=None, input_file=None
        )
        if code == 0 and pub_out:
            (user_dir / 'pubkey.asc').write_text(pub_out)
        # Store passphrase (only the app needs it for decrypt operations)
        pass_file = user_dir / '.gpg_passphrase'
        pass_file.write_text(passphrase)
        try:
            pass_file.chmod(0o600)
        except Exception:
            pass
    finally:
        tmp.unlink(missing_ok=True)


def _init_admin_user(username: str, password: str, pgp_email: str):
    """Create the first admin user. Called via --init-admin CLI flag."""
    if len(password) < 8:
        print(f'[!] Password must be at least 8 characters.')
        sys.exit(1)
    pw_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=32)
    conn = _get_session_db()
    conn.execute(
        'INSERT INTO users (username, password_hash, pgp_key_email, is_admin) VALUES (?, ?, ?, 1)',
        (username, pw_hash, pgp_email)
    )
    conn.commit()
    user_dir = USERS_DIR / username
    user_dir.mkdir(parents=True, exist_ok=True)
    _generate_gpg_key(username, pgp_email)


# ─── SQLite Storage ──────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """Get thread-local DB connection."""
    if not hasattr(threading.current_thread(), '_db'):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _init_db_schema(conn)
        threading.current_thread()._db = conn
    return threading.current_thread()._db





def _init_db_schema(conn: sqlite3.Connection):
    """Initialize DB schema if not exists."""
    conn.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            subject TEXT DEFAULT '',
            file_path TEXT DEFAULT '',
            content_hash TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            encrypted_payload TEXT NOT NULL,
            direction TEXT DEFAULT 'unknown',
            created_at TEXT DEFAULT (datetime('now'))
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_recipient ON messages(recipient)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sender ON messages(sender)')
    # Atomic reply number sequence — prevents race condition duplicates
    conn.execute('CREATE TABLE IF NOT EXISTS reply_seq (num INTEGER PRIMARY KEY)')
    conn.execute("INSERT OR IGNORE INTO reply_seq (num) VALUES (0)")  # seed row if not exists
    # Add direction column if missing (existing DBs won't have it)
    try:
        conn.execute("ALTER TABLE messages ADD COLUMN direction TEXT DEFAULT 'unknown'")
    except Exception:
        pass  # column already exists in newer DBs
    # Add read column if missing
    try:
        conn.execute("ALTER TABLE messages ADD COLUMN read INTEGER DEFAULT 0")
    except Exception:
        pass  # column already exists
    # Add sender_username column for multi-user (per-user inbox filtering)
    try:
        conn.execute("ALTER TABLE messages ADD COLUMN sender_username TEXT DEFAULT ''")
    except Exception:
        pass  # column already exists
    conn.execute('CREATE INDEX IF NOT EXISTS idx_direction ON messages(direction)')
    # Backfill direction for existing entries that don't have it
    try:
        conn.execute("UPDATE messages SET direction='sent' WHERE direction='unknown'")
    except Exception:
        pass
    conn.commit()

def _import_sent_log() -> int:
    """Import existing sent_log.json into DB on first run. Returns count."""
    conn = get_db()
    sent_log = PGP_DIR / 'sent_log.json'
    if not sent_log.exists():
        return 0
    # Check if already imported (look for any existing rows with a file_path)
    row = conn.execute("SELECT COUNT(*) as c FROM messages WHERE file_path LIKE ?",
                     (str(PGP_DIR / 'reply%'),)).fetchone()
    if row['c'] > 0:
        return 0  # Already imported

    count = 0
    try:
        entries = json.loads(sent_log.read_text())
        for e in entries:
            fp = Path(e.get('output', ''))
            if not fp.exists():
                continue
            content = fp.read_text(errors='replace')
            h = hashlib.sha256(content.encode()).hexdigest()
            conn.execute('''
                INSERT OR IGNORE INTO messages
                    (timestamp, sender, recipient, subject, file_path, content_hash, encrypted_payload, direction)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'sent')
            ''', (e.get('timestamp', ''), e.get('recipient', ''),
                  e.get('subject', ''), str(fp), h, content))
            count += 1
        conn.commit()
        print(f"[*] Imported {count} entries from sent_log.json")
    except Exception as ex:
        print(f"[!] sent_log import failed: {ex}")
    return count

# ─── Dark mode toggle via cookie ───────────────────────────────────────────────

@app.context_processor
def inject_dark_mode():
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    return dict(dark_mode=dark)

# ─── GPG Passthrough ────────────────────────────────────────────────────────────

def run_gpg(args, input_text=None, input_file=None, decode=True, homedir=None):
    kwargs = {'capture_output': True}
    if input_text:
        kwargs['input'] = input_text.encode('utf-8')
    if input_file:
        kwargs['input'] = Path(input_file).read_bytes()
    full_args = [GPG_BIN]
    if homedir:
        full_args.extend(['--homedir', str(homedir)])
    full_args.extend(args)
    result = subprocess.run(full_args, **kwargs)
    if decode:
        stdout = result.stdout.decode('utf-8', errors='replace')
        stderr = result.stderr.decode('utf-8', errors='replace')
    else:
        stdout, stderr = result.stdout, result.stderr
    return stdout, stderr, result.returncode

def list_public_keys(username):
    out, err, code = run_gpg_user(['--keyid-format=long', '--fixed-list-mode', '--list-keys'], username)
    return out

def import_public_key(key_data: str, username: str) -> tuple[str, str, int]:
    """Import a public key into user's keyring. Returns (stdout, stderr, returncode)."""
    key_data = key_data.rstrip('\r\n')
    armor = key_data.lstrip()
    leading = key_data[:len(key_data) - len(armor)]
    if armor.startswith('-----BEGIN') and not leading.endswith('\n\n'):
        key_data = '\n' + key_data
    tmp = app.config['PGP_DIR'] / f'.tmp_import_{secrets.token_hex(8)}.asc'
    tmp.write_text(key_data)
    out, err, code = run_gpg_user(['--import', str(tmp)], username)
    try:
        tmp.unlink()
    except Exception:
        pass
    return out, err, code

def gpg_agent_status():
    out, err, code = run_gpg(['--list-keys'])
    return 'running' if code == 0 else 'stopped'


def run_gpg_user(args, username, input_text=None, input_file=None, decode=True):
    """Run GPG with the given user's personal homedir."""
    user_homedir = USERS_DIR / username / '.gnupg'
    return run_gpg(args, input_text=input_text, input_file=input_file,
                   decode=decode, homedir=user_homedir)


def encrypt_to_recipient(recipient_email, plaintext, sender_username, armor=True):
    """
    Encrypt plaintext to recipient_email using recipient's public key.
    Server encrypts on behalf of sender — server never stores plaintext.
    Uses sender_username's GPG homedir for signing.

    Returns (stdout, stderr, returncode).
    """
    # Find recipient's public key file by scanning users/*/pubkey.asc
    recipient_pubkey_path = None
    try:
        for dirent in os.listdir(USERS_DIR):
            pubkey = USERS_DIR / dirent / 'pubkey.asc'
            if pubkey.exists():
                content = pubkey.read_text()
                if f'<{recipient_email}>' in content:
                    recipient_pubkey_path = pubkey
                    break
    except OSError:
        pass

    if not recipient_pubkey_path:
        return '', f'Recipient public key not found: {recipient_email}', 1

    # Import recipient's pubkey into sender's homedir for encryption
    run_gpg_user(['--import', str(recipient_pubkey_path)], sender_username)

    args = ['--batch', '--yes', '--encrypt', '--always-trust', '--pinentry-mode', 'loopback']
    pass_file = None
    passphrase = _get_user_passphrase(sender_username)
    if passphrase:
        pass_file = _passphrase_file(passphrase)
        args.extend(['--passphrase-file', str(pass_file)])
    if armor:
        args.append('--armor')
    args += ['--recipient', recipient_email, '--local-user', sender_username]
    try:
        return run_gpg_user(args, sender_username, input_text=plaintext)
    finally:
        if pass_file:
            pass_file.unlink(missing_ok=True)


def _get_user_passphrase(username):
    """Read the stored GPG passphrase for a user's private key."""
    pass_file = USERS_DIR / username / '.gpg_passphrase'
    if pass_file.exists():
        return pass_file.read_text().strip()
    return None


def _passphrase_file(passphrase):
    """Write passphrase to a temp file and return its path. Caller must unlink."""
    if not passphrase:
        return None
    tmp = PGP_DIR / f'.passphrase_{secrets.token_hex(8)}'
    tmp.write_text(passphrase)
    try:
        tmp.chmod(0o600)
    except Exception:
        pass
    return tmp


def decrypt_with_user_key(ciphertext, username):
    """
    Decrypt ciphertext using username's private key from their personal homedir.
    Returns (stdout, stderr, returncode).
    """
    ciphertext = ciphertext.strip()
    while ciphertext.startswith('\n'):
        ciphertext = ciphertext.lstrip('\n')
    if not ciphertext.startswith('-----BEGIN'):
        ciphertext = '-----BEGIN PGP MESSAGE-----\n\n' + ciphertext
    tmp = PGP_DIR / f'.tmp_dec_{secrets.token_hex(8)}.asc'
    tmp.write_text(ciphertext)
    pass_file = None
    try:
        args = ['--decrypt', '--output', '-', '--pinentry-mode', 'loopback']
        passphrase = _get_user_passphrase(username)
        if passphrase:
            pass_file = _passphrase_file(passphrase)
            args.extend(['--passphrase-file', str(pass_file)])
        else:
            # Legacy keys created with %no-protection — still need batch mode
            args.append('--batch')
        args.append(str(tmp))
        return run_gpg_user(args, username)
    finally:
        tmp.unlink(missing_ok=True)
        if pass_file:
            pass_file.unlink(missing_ok=True)


def get_user_public_key_emails(exclude_username=None):
    """
    Return list of public key emails the current user has imported into their keyring.
    These are the user's "contacts" — only people whose keys they've added via the Keys page
    or who have messaged them (auto-imported on first receipt) appear here.
    Excludes the current user from the recipient list.
    """
    emails = []
    if not exclude_username:
        return emails  # safety: require caller to pass current_user

    # List keys in the current user's personal keyring
    out, err, code = run_gpg_user(['--list-keys', '--keyid-format=long'], exclude_username)
    if code != 0:
        return emails

    # Parse fingerprints from key listing, then match against known pubkey.asc files
    # Format: "uid  [ unknown] Name <email>" lines follow "pub  rsa4096/FINGERPRINT" lines
    fingerprint_to_email = {}
    current_fingerprint = None
    for line in out.splitlines():
        stripped = line.lstrip()
        if stripped.startswith('pub '):
            # Extract full 40-char fingerprint from pub line
            parts = stripped.split()
            fp = next((p for p in parts if len(p.replace(' ', '')) >= 32
                       and all(c in '0123456789ABCDEF' for c in p.replace(':', '').replace(' ', ''))), None)
            if fp:
                # Normalize: remove spaces and take last 16 chars (short keyid) or full fingerprint
                fp_clean = fp.replace(' ', '').replace(':', '')
                if len(fp_clean) >= 16:
                    current_fingerprint = fp_clean[-16:]  # short keyid for matching
                else:
                    current_fingerprint = fp_clean
            else:
                current_fingerprint = None
        elif stripped.startswith('uid ') and current_fingerprint:
            # Extract email from UID line
            m = re.search(r'<([^<>@]+@[^<>@]+)>', stripped)
            if m:
                fingerprint_to_email[current_fingerprint] = m.group(1).strip()

    # For each fingerprint in keyring, find the matching user's pubkey.asc and get email
    found_emails = set()
    for short_id, email in fingerprint_to_email.items():
        # Scan users/*/pubkey.asc to find which user this key belongs to
        try:
            for dirent in os.listdir(USERS_DIR):
                if dirent == exclude_username:
                    continue
                pubkey = USERS_DIR / dirent / 'pubkey.asc'
                if pubkey.exists():
                    content = pubkey.read_text()
                    if short_id in content.replace(' ', '').replace(':', ''):
                        found_emails.add(email)
                        break
        except OSError:
            pass

    return list(found_emails)

# ─── Settings state ────────────────────────────────────────────────────────────

class Settings:
    confirm_guard = False
    confirm_passphrase_hash = ''  # SHA-256 hash of the passphrase
    clipboard_auto_clear = int(os.environ.get('PGP_CLIPBOARD_CLEAR_SECONDS', '30'))
    lockout_active = False
    lockout_remaining = int(os.environ.get('PGP_MAX_ATTEMPTS', '5'))
    sent_log = []

    @classmethod
    def guard_enabled(cls):
        return cls.confirm_guard and bool(cls.confirm_passphrase_hash)

    @classmethod
    def load_sent_log(cls):
        log_path = app.config['PGP_DIR'] / 'sent_log.json'
        if log_path.exists():
            try:
                cls.sent_log = json.loads(log_path.read_text())
            except Exception:
                cls.sent_log = []
        return cls.sent_log

    @classmethod
    def next_reply_num(cls):
        pgp_dir = app.config['PGP_DIR']
        max_num = 0
        for f in pgp_dir.glob('reply*.asc'):
            try:
                num = int(f.stem.replace('reply', ''))
                if num > max_num:
                    max_num = num
            except ValueError:
                pass
        return max_num + 1

settings = Settings()

# ─── Templates ────────────────────────────────────────────────────────────────

DARK_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 15px; line-height: 1.6; min-height: 100vh; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 1100px; margin: 0 auto; padding: 2rem 1rem; }
header { background: linear-gradient(160deg, #1c2128 0%, #161b22 60%, #1a2332 100%); border: 1px solid #30363d; border-radius: 10px; padding: 1rem 1.5rem; margin-bottom: 2rem; box-shadow: 0 4px 20px rgba(0,0,0,0.4), 0 0 0 1px #58a6ff08; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; }
header h1 { font-size: 1.1rem; font-weight: 700; color: #58a6ff; letter-spacing: -0.02em; text-shadow: 0 0 20px #58a6ff50; }
.header-brand { display: flex; align-items: center; gap: 0.6rem; }
.header-brand-icon { font-size: 1.3rem; filter: drop-shadow(0 0 8px #58a6ff60); }
.header-right { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
.header-user { font-size: 0.82rem; color: #8b949e; background: #161b22; border: 1px solid #30363d; padding: 0.3rem 0.8rem; border-radius: 20px; font-weight: 500; }
header .links a { margin-left: 1.5rem; color: #8b949e; font-size: 0.9rem; transition: color 0.2s ease; text-decoration: none; }
header .links a.active { color: #e6edf3; text-shadow: 0 0 10px #58a6ff80; }
header .links a:hover { color: #e6edf3; }
.btn { display: inline-flex; align-items: center; justify-content: center; gap: 0.3rem; padding: 0.4rem 1rem; border-radius: 6px; border: 1px solid #30363d; background: #21262d; color: #e6edf3; cursor: pointer; font-size: 0.85rem; font-family: inherit; font-weight: 500; transition: all 0.15s ease; white-space: nowrap; }
.btn:hover { background: #30363d; transform: translateY(-1px); box-shadow: 0 3px 8px rgba(0,0,0,0.3); }
.btn.danger { border-color: #f85149; color: #f85149; }
.btn.danger:hover { background: #f8514922; }
.btn.primary { background: #238636; border-color: #238636; }
.btn.primary:hover { background: #2ea043; transform: translateY(-1px); box-shadow: 0 3px 12px rgba(46,160,67,0.4); }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 0; margin-bottom: 1.5rem; box-shadow: 0 4px 20px rgba(0,0,0,0.35); }
.card h2 { font-size: 0.75rem; font-weight: 700; color: #8b949e; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0; padding: 0.9rem 1.25rem 0.8rem; border-bottom: 1px solid #21262d; border-left: 3px solid #30363d; background: linear-gradient(135deg, #1c2128 0%, #161b22 100%); }
.card > *:not(h2) { padding: 1.1rem 1.25rem; }
label { display: block; margin-bottom: 0.5rem; color: #8b949e; font-size: 0.85rem; }
input[type=text], input[type=password], textarea, select { width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; padding: 0.6rem; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 0.9rem; transition: border-color 0.15s ease, box-shadow 0.15s ease; }
input:focus, textarea:focus, select:focus { outline: none; border-color: #58a6ff; box-shadow: 0 0 0 3px #58a6ff22; }
textarea { resize: vertical; min-height: 150px; }
.form-row { margin-bottom: 1rem; }
.form-row label { margin-bottom: 0.3rem; }
.status-bar { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
.status-item { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 0.6rem 1rem; font-size: 0.8rem; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }
.status-item .label { color: #8b949e; }
.status-item .value { color: #e6edf3; margin-left: 0.5rem; }
.status-item .value.ok { color: #3fb950; }
.status-item .value.warn { color: #d29922; }
.status-item .value.danger { color: #f85149; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; table-layout: auto; }
th { text-align: left; color: #8b949e; border-bottom: 1px solid #30363d; padding: 0.5rem; }
td { padding: 0.5rem; border-bottom: 1px solid #21262d; }
tr:hover td { background: #21262d; }
.toggle-row { display: flex; align-items: center; justify-content: space-between; padding: 0.6rem 0; border-bottom: 1px solid #21262d; }
.toggle-row:last-child { border-bottom: none; }
.toggle { position: relative; width: 40px; height: 20px; }
.toggle input { opacity: 0; width: 0; height: 0; }
.toggle .slider { position: absolute; cursor: pointer; inset: 0; background: #30363d; border-radius: 20px; transition: 0.2s; }
.toggle .slider:before { content: ''; position: absolute; width: 14px; height: 14px; left: 3px; bottom: 3px; background: #8b949e; border-radius: 50%; transition: 0.2s; }
.toggle input:checked + .slider { background: #238636; }
.toggle input:checked + .slider:before { transform: translateX(20px); background: #fff; }
.alert { padding: 0.8rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; border-left: 3px solid; }
.alert.success { background: #0d2119; border: 1px solid #3fb950; color: #3fb950; }
.alert.error { background: #2d1117; border: 1px solid #f85149; color: #f85149; }
.alert.info { background: #0d1726; border: 1px solid #58a6ff; color: #58a6ff; }
.output-block { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }
.grid2 { display: flex; gap: 1rem; flex-wrap: wrap; }
.grid2 > .card { flex: 1 1 380px; }
table { table-layout: auto; }
td { padding: 0.5rem; border-bottom: 1px solid #21262d; }
td.col-actions { white-space: nowrap; overflow: visible; }
td.col-fprint { font-family: 'Courier New', Courier, monospace; font-size: 0.78rem; color: #8b949e; }
td code { font-size: 0.85rem; }
@keyframes fadeSlideIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
.card { animation: fadeSlideIn 0.35s ease forwards; }
.card:nth-child(2) { animation-delay: 0.05s; }
.card:nth-child(3) { animation-delay: 0.10s; }
.card:nth-child(4) { animation-delay: 0.15s; }
.card:nth-child(5) { animation-delay: 0.20s; }
"""

LIGHT_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #f6f8fa; color: #1f2328; font-family: 'Courier New', monospace; min-height: 100vh; }
a { color: #0969da; text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 1100px; margin: 0 auto; padding: 2rem 1rem; }
header { background: linear-gradient(160deg, #ffffff 0%, #f6f8fa 60%, #f0f2f5 100%); border: 1px solid #d0d7de; border-radius: 10px; padding: 1rem 1.5rem; margin-bottom: 2rem; box-shadow: 0 4px 20px rgba(0,0,0,0.08), 0 0 0 1px #0969da08; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; }
header h1 { font-size: 1.1rem; font-weight: 700; color: #0969da; letter-spacing: -0.02em; text-shadow: 0 0 20px #0969da30; }
.header-brand { display: flex; align-items: center; gap: 0.6rem; }
.header-brand-icon { font-size: 1.3rem; filter: drop-shadow(0 0 8px #0969da40); }
.header-right { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
.header-user { font-size: 0.82rem; color: #57606a; background: #ffffff; border: 1px solid #d0d7de; padding: 0.3rem 0.8rem; border-radius: 20px; font-weight: 500; }
header .links a { margin-left: 1.5rem; color: #57606a; font-size: 0.9rem; transition: color 0.2s ease; text-decoration: none; }
header .links a.active { color: #1f2328; text-shadow: 0 0 10px #0969da60; }
header .links a:hover { color: #1f2328; }
.btn { display: inline-flex; align-items: center; justify-content: center; gap: 0.3rem; padding: 0.4rem 1rem; border-radius: 6px; border: 1px solid #d0d7de; background: #f6f8fa; color: #1f2328; cursor: pointer; font-size: 0.85rem; font-family: inherit; font-weight: 500; transition: all 0.15s ease; white-space: nowrap; }
.btn:hover { background: #eaeef2; transform: translateY(-1px); box-shadow: 0 3px 8px rgba(0,0,0,0.1); }
.btn.danger { border-color: #cf222e; color: #cf222e; }
.btn.danger:hover { background: #ffebe9; }
.btn.primary { background: #2da44e; border-color: #2da44e; color: #fff; }
.btn.primary:hover { background: #2c974b; transform: translateY(-1px); box-shadow: 0 3px 12px rgba(45,164,78,0.35); }
.card { background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 0; margin-bottom: 1.5rem; box-shadow: 0 4px 20px rgba(0,0,0,0.08); overflow: hidden; }
.card h2 { font-size: 0.75rem; font-weight: 700; color: #57606a; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0; padding: 0.9rem 1.25rem 0.8rem; border-bottom: 1px solid #eaeef2; border-left: 3px solid #d0d7de; background: linear-gradient(135deg, #f6f8fa 0%, #ffffff 100%); }
.card > *:not(h2) { padding: 1.1rem 1.25rem; }
label { display: block; margin-bottom: 0.5rem; color: #57606a; font-size: 0.85rem; }
input[type=text], input[type=password], textarea, select { width: 100%; background: #fff; border: 1px solid #d0d7de; border-radius: 6px; color: #1f2328; padding: 0.6rem; font-family: 'Courier New', monospace; font-size: 0.9rem; }
input:focus, textarea:focus, select:focus { outline: none; border-color: #0969da; box-shadow: 0 0 0 3px #0969da22; }
textarea { resize: vertical; min-height: 150px; }
.form-row { margin-bottom: 1rem; }
.form-row label { margin-bottom: 0.3rem; }
.status-bar { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
.status-item { background: #fff; border: 1px solid #d0d7de; border-radius: 6px; padding: 0.6rem 1rem; font-size: 0.8rem; box-shadow: 0 2px 6px rgba(0,0,0,0.06); }
.status-item .label { color: #57606a; }
.status-item .value { color: #1f2328; margin-left: 0.5rem; }
.status-item .value.ok { color: #2da44e; }
.status-item .value.warn { color: #9a6700; }
.status-item .value.danger { color: #cf222e; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { text-align: left; color: #57606a; border-bottom: 1px solid #d0d7de; padding: 0.5rem; }
td { padding: 0.5rem; border-bottom: 1px solid #eaeef2; }
tr:hover td { background: #f6f8fa; }
.toggle-row { display: flex; align-items: center; justify-content: space-between; padding: 0.6rem 0; border-bottom: 1px solid #eaeef2; }
.toggle-row:last-child { border-bottom: none; }
.toggle { position: relative; width: 40px; height: 20px; }
.toggle input { opacity: 0; width: 0; height: 0; }
.toggle .slider { position: absolute; cursor: pointer; inset: 0; background: #d0d7de; border-radius: 20px; transition: 0.2s; }
.toggle .slider:before { content: ''; position: absolute; width: 14px; height: 14px; left: 3px; bottom: 3px; background: #fff; border-radius: 50%; transition: 0.2s; box-shadow: 0 1px 2px rgba(0,0,0,0.2); }
.toggle input:checked + .slider { background: #2da44e; }
.toggle input:checked + .slider:before { transform: translateX(20px); }
.alert { padding: 0.8rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; }
.alert.success { background: #dafbe1; border: 1px solid #2da44e; color: #1a7f37; }
.alert.error { background: #ffebe9; border: 1px solid #cf222e; color: #cf222e; }
.alert.info { background: #dbedff; border: 1px solid #0969da; color: #0969da; }
.output-block { background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 1rem; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }
.grid2 { display: flex; gap: 1rem; flex-wrap: wrap; }
.grid2 > .card { flex: 1 1 380px; }
table { table-layout: auto; }
td { padding: 0.5rem; border-bottom: 1px solid #d0d7de; }
td.col-actions { white-space: nowrap; overflow: visible; }
td.col-fprint { font-family: 'Courier New', Courier, monospace; font-size: 0.78rem; color: #57606a; }
td code { font-size: 0.85rem; }
"""

BASE_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{ title }} — PGP Vault</title>
  <style id="theme-css">
    * { box-sizing: border-box; margin: 0; padding: 0; }
    {{ page_css | safe }}
  </style>
</head>
<body data-dark="{{ '1' if dark_mode else '0' }}">
<div class="container">
<header>
  <div class="header-brand">
    <span class="header-brand-icon">🔐</span>
    <h1>PGP Vault</h1>
  </div>
  <div class="header-right">
    {% if current_user %}<span class="header-user">{{ current_user.username }}<form method="post" action="{{ url_for('logout') }}" style="display:inline;margin:0;padding:0 0 0 6px"><input type="hidden" name="csrf_token" value="{{ csrf_token_val }}"><button type="submit" class="btn small" style="font-size:0.7rem;padding:1px 6px">Logout</button></form></span>{% endif %}
    <div class="links">
    {% for endpoint, label in tabs %}
    <a href="{{ url_for(endpoint) }}" class="{{ 'active' if active_tab == endpoint else '' }}">{{ label }}</a>
    {% endfor %}
    {% if current_user and current_user.is_admin %}
    <a href="{{ url_for('admin_users') }}" class="{{ 'active' if active_tab == 'admin_users' else '' }}">Users</a>
    <a href="{{ url_for('admin_audit') }}" class="{{ 'active' if active_tab == 'admin_audit' else '' }}">Audit</a>
    {% endif %}
    <a href="#" id="dark_toggle" onclick="toggleDark(); return false;" style="background:none;border:none;color:#8b949e;cursor:pointer;font-size:0.8rem;text-decoration:none">{{ '☀ light' if dark_mode else '🌙 dark' }}</a>
  </div>
</header>
<script>
window.__DARK_CSS__ = {{ dark_css | tojson }};
window.__LIGHT_CSS__ = {{ light_css | tojson }};
window.__CSRF_TOKEN__ = {{ csrf_token_val | tojson }};
function toggleDark() {
  var isDark = document.body.getAttribute("data-dark") === "1";
  var newDark = isDark ? "0" : "1";
  document.body.setAttribute("data-dark", newDark);
  document.getElementById("dark_toggle").textContent = newDark === "1" ? "☀ light" : "🌙 dark";
  document.getElementById("theme-css").textContent = newDark === "1" ? window.__DARK_CSS__ : window.__LIGHT_CSS__;
  fetch("{{ url_for('toggle_dark_mode') }}", {method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:"dark="+newDark+"&csrf_token="+encodeURIComponent(window.__CSRF_TOKEN__)}).catch(function(){{}});
}
</script>
{{ body | safe }}
</div>
<script>
var tc=document.getElementById('theme-css');
if(tc)tc.textContent=tc.textContent.replace(//g,'{').replace(//g,'}');
</script>
</body>
</html>
"""

def render(title, active_tab, body_html, dark_mode=True, set_cookie=False, current_user=None):
    from flask import g
    css_raw = DARK_CSS if dark_mode else LIGHT_CSS
    css_safe = css_raw.replace('{', '\x01').replace('}', '\x02')
    tab_links = [
        ('compose', 'Compose'),
        ('inbox', 'Inbox'),
        ('sent', 'Sent Log'),
        ('keys_page', 'Keys'),
        ('settings_page', 'Settings'),
    ]
    html = render_template_string(BASE_TEMPLATE,
        title=title,
        body=body_html,
        tabs=tab_links,
        active_tab=active_tab,
        dark_mode=dark_mode,
        dark_css=DARK_CSS,
        light_css=LIGHT_CSS,
        page_css=css_safe,
        url_for=url_for,
        current_user=getattr(g, 'current_user', None),
        csrf_token_val=csrf_token(),
    )
    resp = app.make_response(html)
    if set_cookie:
        resp.set_cookie(DARK_MODE_COOKIE, '0' if dark_mode else '1', samesite='Lax', secure=True)
    _set_csrf_cookie(resp)
    return resp

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('compose'))

@app.route('/compose', methods=['GET', 'POST'])
@csrf_protect
def compose():
    from flask import g
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    reply_to = request.args.get('reply_to', '').strip()
    current_user = getattr(g, 'current_user', None)
    username = current_user['username'] if current_user else None
    current_email = current_user['pgp_key_email'] if current_user else ''

    # Recipient dropdown: scan users/*/pubkey.asc for all registered users
    recipients = get_user_public_key_emails(exclude_username=username)
    recipients.sort()

    alert = ''
    output = ''
    if request.method == 'POST':
        action = request.form.get('action')
        msg = request.form.get('message', '').strip()
        recipient_email = request.form.get('recipient', '').strip()
        if action == 'encrypt' and msg and recipient_email:
            confirm = request.form.get('confirm_phrase', '').strip()
            if settings.confirm_guard and not hmac.compare_digest(hashlib.sha256(confirm.encode()).hexdigest(), settings.confirm_passphrase_hash):
                alert = '<div class="alert error">Confirmation phrase mismatch.</div>'
            elif not username:
                alert = '<div class="alert error">You must be logged in to send messages.</div>'
            else:
                out, err, code = encrypt_to_recipient(recipient_email, msg, username)
                if code == 0:
                    ts = datetime.utcnow().isoformat()
                    subject = request.form.get('subject', '')[:200]
                    h = hashlib.sha256(out.encode()).hexdigest()
                    sender_db = get_user_db(username)
                    reply_num = _next_reply_num(sender_db)

                    # Write encrypted blob to SENDER's sent folder: users/{username}/sent/
                    sent_dir = USERS_DIR / username / 'sent'
                    sent_dir.mkdir(parents=True, exist_ok=True)
                    out_path_sent = sent_dir / f'reply{reply_num}.asc'
                    out_path_sent.write_text(out)

                    # Write encrypted blob to RECIPIENT's inbox folder: users/{recipient}/inbox/
                    # Find recipient username from their email
                    recipient_username = None
                    for dirent in os.listdir(USERS_DIR):
                        pubkey = USERS_DIR / dirent / 'pubkey.asc'
                        if pubkey.exists() and recipient_email in pubkey.read_text():
                            recipient_username = dirent
                            break
                    if recipient_username:
                        inbox_dir = USERS_DIR / recipient_username / 'inbox'
                        inbox_dir.mkdir(parents=True, exist_ok=True)
                        out_path_recv = inbox_dir / f'reply{reply_num}.asc'
                        out_path_recv.write_text(out)

                        # Auto-import sender's pubkey into recipient's keyring so recipient can reply.
                        # This is the "contact discovery" mechanism: receiving a message automatically
                        # adds the sender as a contact (they appear in recipient's compose dropdown).
                        sender_pubkey = USERS_DIR / username / 'pubkey.asc'
                        if sender_pubkey.exists():
                            run_gpg_user(['--import', str(sender_pubkey)], recipient_username)
                    else:
                        out_path_recv = out_path_sent  # fallback

                    # Record in SENDER's per-user DB as 'sent'
                    sender_db.execute('''
                        INSERT INTO messages (timestamp, sender, sender_username, recipient, subject, file_path, content_hash, encrypted_payload, direction)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sent')
                    ''', (ts, current_email, username, recipient_email, subject, str(out_path_sent), h, out))
                    sender_db.commit()

                    # Record in RECIPIENT's per-user DB as 'received'
                    if recipient_username:
                        recv_db = get_user_db(recipient_username)
                        recv_db.execute('''
                            INSERT INTO messages (timestamp, sender, sender_username, recipient, subject, file_path, content_hash, encrypted_payload, direction)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'received')
                        ''', (ts, current_email, username, recipient_email, subject, str(out_path_recv), h, out))
                        recv_db.commit()

                    output = f'<div class="alert success">Message encrypted and delivered to {html.escape(recipient_email)}.</div>'
                else:
                    logger.error('GPG encrypt failed: %s', err)
                    alert = '<div class="alert error">Encryption failed. Check that the recipient\'s key is imported and valid.</div>'
        elif action == 'decrypt':
            ciphertext = request.form.get('ciphertext', '').strip()
            confirm_dec = request.form.get('confirm_phrase_dec', '').strip()
            if settings.confirm_guard and not hmac.compare_digest(hashlib.sha256(confirm_dec.encode()).hexdigest(), settings.confirm_passphrase_hash):
                alert = '<div class="alert error">Confirmation phrase mismatch.</div>'
            elif not username:
                alert = '<div class="alert error">You must be logged in to decrypt.</div>'
            elif ciphertext:
                out, err, code = decrypt_with_user_key(ciphertext, username)
                if code == 0:
                    output = f'<div class="alert success">Decrypted:</div><div class="output-block">{html.escape(out)}</div>'
                else:
                    logger.error('GPG decrypt failed: %s', err)
                    alert = '<div class="alert error">Decryption failed. Check that you have the correct private key.</div>'

    guard_on = settings.confirm_guard

    # Local key selector: show only current user's key (from their personal GPG homedir)
    local_users = [current_email] if current_email else []

    confirm_row_enc = f'''
    <div class="form-row">
      <label for="confirm_phrase">Confirmation phrase {"" if guard_on else "(guard OFF)"}</label>
      <input type="password" name="confirm_phrase" id="confirm_phrase" autocomplete="off" placeholder="{'vaultbot' if guard_on else 'guard is off'}">
    </div>''' if guard_on else ''

    confirm_row_dec = f'''
    <div class="form-row">
      <label for="confirm_phrase_dec">Confirmation phrase {"" if guard_on else "(guard OFF)"}</label>
      <input type="password" name="confirm_phrase_dec" id="confirm_phrase_dec" autocomplete="off" placeholder="{'vaultbot' if guard_on else 'guard is off'}">
    </div>''' if guard_on else ''

    body = f'''
    {alert}
    <div class="grid2">
    <div class="card">
    <h2>Encrypt</h2>
    <form method="post">
      {csrf_input()}
      <input type="hidden" name="action" value="encrypt">
      <div class="form-row">
        <label for="recipient">Recipient (encrypt TO)</label>
        <select name="recipient" id="recipient" onchange="saveDraft()">
          <option value="">— select recipient —</option>
          {' '.join(f'<option value="{html.escape(r)}"{(" selected" if r == reply_to else "")}>{html.escape(r)}</option>' for r in recipients)}
        </select>
      </div>
      <div class="form-row">
        <label for="subject">Subject <span style="font-weight:normal">(optional)</span></label>
        <input type="text" name="subject" id="subject" placeholder="Brief description of this message…" oninput="saveDraft()">
      </div>
      <div class="form-row">
        <label for="message">Plaintext message <span id="draftIndicator" style="color:#8b949e;font-weight:normal;font-size:0.8rem;display:none"> · Draft saved</span></label>
        <textarea name="message" id="message" placeholder="Your message..." oninput="saveDraft()"></textarea>
      </div>
      <p style="color:#8b949e;font-size:0.75rem;margin:0">Draft auto-saved locally</p>
      {confirm_row_enc}
      <button type="submit" class="btn primary">🔒 Encrypt & Send</button>
    </form>
    </div>
    <div class="card">
    <h2>Decrypt</h2>
    <form method="post">
      {csrf_input()}
      <input type="hidden" name="action" value="decrypt">
      <div class="form-row">
        <label for="local_user">Your key (decrypt WITH)</label>
        <select name="local_user" id="local_user">
          <option value="">— auto-detect —</option>
          {' '.join(f'<option value="{html.escape(u)}">{html.escape(u)}</option>' for u in local_users)}
        </select>
      </div>
      <div class="form-row">
        <label for="ciphertext">Ciphertext</label>
        <textarea name="ciphertext" id="ciphertext" placeholder="-----BEGIN PGP MESSAGE-----..."></textarea>
      </div>
      {confirm_row_dec}
      <button type="submit" class="btn">🔓 Decrypt</button>
    </form>
    </div>
    </div>
    {output}'''
    # Draft auto-save/restore via localStorage
    body += f'''
    <script>
    const DRAFT_KEY = 'pgp_compose_draft';
    function saveDraft() {{
      let draft = {{
        recipient: document.getElementById('recipient') ? document.getElementById('recipient').value : '',
        subject: document.getElementById('subject') ? document.getElementById('subject').value : '',
        message: document.getElementById('message') ? document.getElementById('message').value : ''
      }};
      localStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
      let ind = document.getElementById('draftIndicator');
      if (ind) {{ ind.style.display = ''; }}
    }}
    function loadDraft() {{
      try {{
        let raw = localStorage.getItem(DRAFT_KEY);
        if (!raw) return;
        let draft = JSON.parse(raw);
        let msgEl = document.getElementById('message');
        if (draft.message && msgEl && !msgEl.value) {{ msgEl.value = draft.message; }}
        let subEl = document.getElementById('subject');
        if (draft.subject && subEl && !subEl.value) {{ subEl.value = draft.subject; }}
        let recEl = document.getElementById('recipient');
        if (draft.recipient && recEl) {{
          for (let o of recEl.options) {{ if (o.value === draft.recipient) {{ recEl.value = draft.recipient; break; }} }}
        }}
      }} catch(e) {{}}
    }}
    function clearDraft() {{ localStorage.removeItem(DRAFT_KEY); }}
    document.querySelector('form').addEventListener('submit', function(e) {{
      if (e.submitter && e.submitter.textContent.includes('Encrypt')) clearDraft();
    }});
    window.addEventListener('DOMContentLoaded', loadDraft);
    </script>'''
    return render('Compose', 'compose', body, dark)

@app.route('/inbox')
def inbox():
    from flask import g
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    current_user = getattr(g, 'current_user', None)
    username = current_user['username'] if current_user else None
    current_email = current_user['pgp_key_email'] if current_user else ''

    messages = []
    if username:
        # Use per-user DB, filtered to messages where current user is recipient
        conn = get_user_db(username)
        rows = conn.execute('''
            SELECT id, timestamp, sender, sender_username, recipient, subject, file_path, content_hash, "read"
            FROM messages
            WHERE direction = 'received'
            ORDER BY timestamp DESC
            LIMIT 50
        ''').fetchall()

        for r in rows:
            fp = None
            if r['file_path']:
                fp = Path(r['file_path'])
                try:
                    size = fp.stat().st_size if fp.exists() else 0
                except (OSError, PermissionError, FileNotFoundError):
                    size = 0
                    fp = None
            messages.append({
                'id': r['id'],
                'file': Path(r['file_path']).name if r['file_path'] else '',
                'file_path': str(r['file_path']) if r['file_path'] else '',
                'timestamp': r['timestamp'],
                'sender': r['sender'],
                'sender_username': r.get('sender_username', ''),
                'recipient': r['recipient'],
                'subject': r['subject'] or '',
                'size': size if fp else 0,
                'read': r['read'] if 'read' in r.keys() else 0,
            })


    messages.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    html_rows = ''
    for m in messages[:30]:
        has_id = m['id'] is not None
        trash = '🗑'
        safe_file = json.dumps(m['file'])
        safe_file_html = html.escape(m['file'])
        safe_sender = html.escape(m.get('sender', ''))
        safe_sender_js = json.dumps(m.get('sender', ''))
        safe_subject = html.escape(m.get('subject', '')[:40])
        delete_btn = f'<button class="btn danger" onclick="deleteMsg({m["id"]}, this)">{trash} Delete</button>' if has_id else \
                     f'<button class="btn danger" onclick="deleteFile({safe_file}, this)">{trash} Delete</button>'
        row_style = '' if m.get('read') else 'font-weight:bold'
        read_icon = '✓ ' if m.get('read') else ''
        html_rows += f'''<tr data-id="{m['id']}" style="{row_style}">
          <td style="text-align:center"><input type="checkbox" class="row-check" value="{m["id"]}" onclick="updateBulkBtn()"></td>
          <td><code>{read_icon}{safe_file_html}</code></td>
          <td>{safe_sender}</td>
          <td>{safe_subject}</td>
          <td>{m.get('timestamp','')[:16]}</td>
          <td>
            <button class="btn" onclick="decryptFile({safe_file}, this)">🔓 Decrypt</button>
            <button class="btn" onclick="window.location='/compose?reply_to={safe_sender_js}'">↩ Reply</button>
            <button class="btn" onclick="copyFile({safe_file}, this)">📋 Copy</button>
            {delete_btn}
          </td>
        </tr>
        <tr class="decrypted-row" id="row-{safe_file_html}" style="display:none">
          <td colspan="6"><div class="decrypted-content" id="content-{safe_file_html}"></div></td>
        </tr>'''

    body = f'''
    <style>
    .decrypted-content {{ background:#0d1117; border:1px solid #30363d; border-radius:6px; padding:1rem; margin-top:0.5rem; white-space:pre-wrap; word-break:break-all; max-height:400px; overflow-y:auto; font-size:0.85rem; }}
    table {{ width:100%; border-collapse:collapse; }}
    .decrypted-row td {{ padding:0.5rem 1rem 1rem; background:#161b22; }}
    .search-row {{ margin-bottom:0.75rem; }}
    .search-row input {{ padding:0.4rem 0.6rem; border-radius:4px; border:1px solid #30363d; background:#0d1117; color:#e6edf3; width:100%; box-sizing:border-box; font-size:0.9rem; }}
    .search-row input::placeholder {{ color:#8b949e; }}
    .search-row input:focus {{ outline:1px solid #58a6ff; border-color:#58a6ff; }}
    </style>
    {f'<div class="alert info">{len(messages)} messages — lazy decrypt: click to reveal</div>' if messages else f'<div class="alert info">No messages found</div>'}
    <div class="card"><h2>Inbox</h2>
    <div class="search-row"><input type="text" id="searchInput" oninput="filterInbox()" placeholder="Search by subject, sender, or file name…"></div>
    <div style="margin-bottom:0.5rem"><button class="btn danger" id="bulkDeleteBtn" onclick="deleteSelected()" style="display:none">🗑 Delete Selected (<span id="selCount">0</span>)</button></div>
    <table><thead><tr><th style="width:2rem"><input type="checkbox" id="selectAll" onclick="toggleAll(this)"></th><th>File</th><th>From</th><th>Subject</th><th>Time</th><th>Actions</th></tr></thead>
    <tbody>{html_rows}</tbody></table>
    </div>
    <script>
    function toggleAll(src) {{
      document.querySelectorAll('.row-check').forEach(cb => cb.checked = src.checked);
      updateBulkBtn();
    }}
    function updateBulkBtn() {{
      let checked = document.querySelectorAll('.row-check:checked');
      let btn = document.getElementById('bulkDeleteBtn');
      let count = document.getElementById('selCount');
      count.textContent = checked.length;
      btn.style.display = checked.length > 0 ? '' : 'none';
    }}
    async function deleteSelected() {{
      let checked = document.querySelectorAll('.row-check:checked');
      if (!checked.length) return;
      if (!confirm('Delete ' + checked.length + ' message(s) from DB and disk?')) return;
      let ids = Array.from(checked).map(cb => cb.value);
      let errors = [];
      for (let id of ids) {{
        try {{
          let resp = await fetch('/api/messages/' + id, {{method:'DELETE'}});
          if (!resp.ok && resp.status !== 404) errors.push(id);
          else {{
            // Remove both the row and its decrypted-row sibling
            let tr = document.querySelector('tr[data-id="' + id + '"]');
            if (tr) {{ let next = tr.nextElementSibling; if (next && next.classList.contains('decrypted-row')) next.remove(); tr.remove(); }}
            else {{
              // Fallback: remove by checking checkbox's parent row
              let row = document.querySelector('input.row-check[value="' + id + '"]').closest('tr');
              if (row) {{ let next = row.nextElementSibling; if (next && next.classList.contains('decrypted-row')) next.remove(); row.remove(); }}
            }}
          }}
        }} catch(e) {{ errors.push(id); }}
      }}
      if (errors.length) alert('Failed to delete: ' + errors.join(', '));
      updateBulkBtn();
    }}
    function filterInbox() {{
      let term = document.getElementById('searchInput').value.toLowerCase();
      let rows = document.querySelectorAll('tbody tr:not(.decrypted-row)');
      rows.forEach(row => {{
        let text = row.innerText.toLowerCase();
        let visible = text.includes(term);
        row.style.display = visible ? '' : 'none';
        // Sync decrypted-row with parent
        let dec = row.nextElementSibling;
        if (dec && dec.classList.contains('decrypted-row')) {{
          dec.style.display = visible ? '' : 'none';
        }}
      }});
    }}
    async function decryptFile(filename, btn) {{
      let row = document.getElementById('row-' + filename);
      let content = document.getElementById('content-' + filename);
      if (row.style.display === 'table-row') {{ row.style.display='none'; btn.textContent='🔓 Decrypt'; return; }}
      try {{
        let resp = await fetch('/inbox/decrypt_file/' + encodeURIComponent(filename));
        let data = await resp.json();
        if (data.error) {{ content.innerHTML='<div class="alert error">'+data.error+'</div>'; }}
        else {{ content.textContent = data.plaintext;
          // Mark as read: remove bold, add checkmark, fire PATCH silently
          let tr = btn.closest('tr');
          let id = tr.getAttribute('data-id');
          tr.style.fontWeight = '';
          let fileCell = tr.cells[1];
          if (fileCell) {{ let code = fileCell.querySelector('code'); if (code && !code.textContent.startsWith('✓ ')) code.textContent = '✓ ' + filename; }}
          if (id) fetch('/api/messages/' + id + '/read', {{method:'PATCH'}}).catch(()=>{{}});
        }}
        row.style.display='table-row'; btn.textContent='🔒 Hide';
      }} catch(e) {{ content.innerHTML='<div class="alert error">'+e.message+'</div>'; row.style.display='table-row'; }}
    }}
    async function copyFile(filename, btn) {{
      try {{
        let resp = await fetch('/inbox/raw/' + encodeURIComponent(filename));
        if (!resp.ok) throw new Error('Failed');
        await navigator.clipboard.writeText(await resp.text());
        btn.textContent='✓ Copied'; setTimeout(()=>{{btn.textContent='📋 Copy';}},1500);
      }} catch(e) {{ alert('Copy failed: '+e.message); }}
    }}
    async function deleteMsg(id, btn) {{
      if (!confirm('Delete this message from DB and disk?')) return;
      try {{
        let resp = await fetch('/api/messages/' + id, {{method:'DELETE'}});
        if (resp.status === 404) {{
          // Already gone — silently remove from UI
          btn.closest('tr').nextSibling?.remove();
          btn.closest('tr').remove();
          return;
        }}
        if (!resp.ok) throw new Error(await resp.text());
        btn.closest('tr').nextSibling?.remove();
        btn.closest('tr').remove();
      }} catch(e) {{ alert('Delete failed: '+e.message); }}
    }}
    async function deleteFile(filename, btn) {{
      if (!confirm('Delete ' + filename + ' from disk?')) return;
      try {{
        let resp = await fetch('/inbox/delete_file/' + encodeURIComponent(filename), {{method:'POST', headers:{{'Content-Type':'application/x-www-form-urlencoded'}}, body:'csrf_token='+encodeURIComponent(window.__CSRF_TOKEN__)}});
        if (resp.status === 404) {{
          btn.closest('tr').remove();
          return;
        }}
        if (!resp.ok) throw new Error(await resp.text());
        btn.closest('tr').remove();
      }} catch(e) {{ alert('Delete failed: '+e.message); }}
    }}
    </script>'''
    return render('Inbox', 'inbox', body, dark)

@app.route('/inbox/decrypt_file/<filename>')
def inbox_decrypt_file(filename):
    """Decrypt a file by filename using current user's private key."""
    from flask import g
    current_user = getattr(g, 'current_user', None)
    username = current_user['username'] if current_user else None
    if not username:
        return jsonify({'error': 'Not authenticated'}), 401
    safe_name = Path(filename).name
    # File lives in users/{username}/inbox/ or users/{username}/sent/
    inbox_path = USERS_DIR / username / 'inbox' / safe_name
    sent_path = USERS_DIR / username / 'sent' / safe_name
    file_path = inbox_path if inbox_path.exists() else (sent_path if sent_path.exists() else None)
    if not file_path or not file_path.exists():
        return jsonify({'error': 'File not found'}), 404
    content = file_path.read_text(errors='replace')
    out, err, code = decrypt_with_user_key(content, username)
    if code == 0:
        return jsonify({'plaintext': out})
    logger.error('Inbox decrypt failed for user %s file %s: %s', username, safe_name, err)
    return jsonify({'error': 'Decryption failed'}), 500


@app.route('/inbox/raw/<filename>')
def inbox_raw(filename):
    """Serve a raw .asc file from the user's inbox or sent dir."""
    from flask import g
    current_user = getattr(g, 'current_user', None)
    username = current_user['username'] if current_user else None
    safe_name = Path(filename).name
    if username:
        inbox_path = USERS_DIR / username / 'inbox' / safe_name
        sent_path = USERS_DIR / username / 'sent' / safe_name
        file_path = inbox_path if inbox_path.exists() else (sent_path if sent_path.exists() else None)
    else:
        file_path = None
    if not file_path or not file_path.exists() or not file_path.is_file():
        return 'File not found', 404
    return file_path.read_text(errors='replace'), 200, {'Content-Type': 'text/plain'}


@app.route('/inbox/delete_file/<filename>', methods=['POST'])
@csrf_protect
def inbox_delete_file(filename):
    """Delete a file from the user's inbox or sent dir."""
    from flask import g
    current_user = getattr(g, 'current_user', None)
    username = current_user['username'] if current_user else None
    safe_name = Path(filename).name
    if username:
        inbox_path = USERS_DIR / username / 'inbox' / safe_name
        sent_path = USERS_DIR / username / 'sent' / safe_name
        file_path = inbox_path if inbox_path.exists() else (sent_path if sent_path.exists() else None)
    else:
        file_path = None
    if file_path and file_path.exists() and file_path.is_file():
        file_path.unlink(missing_ok=True)
        return jsonify({'deleted': str(file_path)})
    return jsonify({'error': 'File not found'}), 404

@app.route('/sent')
def sent():
    """Show the current user's sent messages from their per-user DB."""
    from flask import g
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    current_user = getattr(g, 'current_user', None)
    username = current_user['username'] if current_user else None
    current_email = current_user['pgp_key_email'] if current_user else ''

    rows_html = ''
    if username:
        conn = get_user_db(username)
        rows = conn.execute('''
            SELECT id, timestamp, sender, sender_username, recipient, subject, file_path
            FROM messages
            WHERE direction = 'sent'
            ORDER BY timestamp DESC
            LIMIT 50
        ''').fetchall()
        for r in rows:
            rows_html += f'''<tr>
              <td>{r['timestamp'][:16]}</td>
              <td>{html.escape(r['recipient'])}</td>
              <td><code>{html.escape(r.get('subject', '')[:40])}</code></td>
            </tr>'''

    table_html = f'''<div class="card"><h2>Sent Messages</h2>
    <table><thead><tr><th>Time (UTC)</th><th>Recipient</th><th>Subject</th></tr></thead>
    <tbody>{rows_html}</tbody></table>
    {"<p style='color:#8b949e;padding:1rem'>No sent messages.</p>" if not rows_html else ""}
    </div>'''
    body = table_html
    return render('Sent Messages', 'sent', body, dark)

@app.route('/sent/clear', methods=['POST'])
@admin_required
@csrf_protect
def clear_sent_log():
    log_path = app.config['PGP_DIR'] / 'sent_log.json'
    if log_path.exists():
        log_path.unlink()
    settings.sent_log = []
    return redirect(url_for('sent'))

@app.route('/settings', methods=['GET', 'POST'])
@csrf_protect
def settings_page():
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    msg = ''

    if request.method == 'POST':
        settings.load_sent_log()
        guard_action = request.form.get('guard_action')
        passphrase = request.form.get('passphrase', '').strip()
        if guard_action == 'enable' and passphrase:
            settings.confirm_guard = True
            settings.confirm_passphrase_hash = hashlib.sha256(passphrase.encode()).hexdigest()
            msg = f'<div class="alert success">Guard ENABLED — phrase set.</div>'
        else:
            settings.confirm_guard = False
            settings.confirm_passphrase_hash = ''
            if guard_action == 'disable':
                msg = '<div class="alert info">Guard DISABLED.</div>'
            elif guard_action == 'enable' and not passphrase:
                msg = '<div class="alert error">Enable failed — passphrase required.</div>'

    guard_on = settings.confirm_guard
    agent_ok = gpg_agent_status() == 'running'
    lockout = settings.lockout_active
    remaining = settings.lockout_remaining
    clipboard_sec = os.environ.get('PGP_CLIPBOARD_CLEAR_SECONDS', '30')
    from flask import g
    current_user = getattr(g, 'current_user', None)
    username = current_user['username'] if current_user else ''
    user_email = current_user.get('pgp_key_email', '') if current_user else ''

    body = f'''
    {msg}
    <div class="card">
    <h2>Your Account</h2>
    <table>
      <tr><td>Username</td><td><code>{html.escape(username)}</code></td></tr>
      <tr><td>PGP Email</td><td><code>{html.escape(user_email)}</code></td></tr>
    </table>
    </div>
    <div class="card">
    <h2>Security</h2>
    <div class="status-bar">
      <div class="status-item">
        <span class="label">Confirmation Guard:</span>
        <span class="value {'ok' if guard_on else 'warn'}">{'ON — phrase set' if guard_on else 'OFF'}</span>
      </div>
      <div class="status-item">
        <span class="label">GPG Agent:</span>
        <span class="value {'ok' if agent_ok else 'danger'}">{agent_ok}</span>
      </div>
      <div class="status-item">
        <span class="label">Clipboard clear:</span>
        <span class="value">{clipboard_sec}s</span>
      </div>
    </div>
    <form method="post" action="{url_for('kill_agent')}" style="display:inline">
      {csrf_input()}
      <button type="submit" class="btn danger" onclick="return confirm('Restart gpg-agent and clear all cached passphrases?')">💀 Kill Agent (clear passphrase cache)</button>
    </form>
    </div>
    <div class="card">
    <h2>Confirmation Guard</h2>
    <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1rem">
      When ON, encrypting and decrypting in the UI requires the phrase below. Disable to use the UI without guard.
    </p>
    <form method="post">
    {csrf_input()}
    <input type="hidden" name="guard_action" value="disable" id="guard_action_default">
    <div class="toggle-row">
      <span>Guard is {'ON' if guard_on else 'OFF'}</span>
      <label class="toggle">
        <input type="checkbox" name="guard_action" id="guard_action_enable" value="enable" {'checked' if guard_on else ''} onchange="document.getElementById('guard_action_default').disabled = this.checked;">
        <span class="slider"></span>
      </label>
    </div>
    <div class="form-row" style="margin-top:1rem;">
      <label for="passphrase_input">Passphrase — {'currently set' if settings.confirm_passphrase_hash else 'not set'}</label>
      <input type="password" name="passphrase" id="passphrase_input" autocomplete="new-password" placeholder="Enter phrase to activate guard...">
    </div>
    <button type="submit" class="btn primary">Apply</button>
    </form>
    </div>
    <div class="card">
    <h2>Environment</h2>
    <table>
      <tr><td>PGP_DIR</td><td><code>{app.config['PGP_DIR']}</code></td></tr>
      <tr><td>PGP_CLIPBOARD_CLEAR_SECONDS</td><td><code>{os.environ.get('PGP_CLIPBOARD_CLEAR_SECONDS','30')}</code></td></tr>
    </table>
    </div>
    <div class="card">
    <h2>API Access</h2>
    <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1rem">
      Auth token for <code>/api/*</code> endpoints. Required in the <code>Authorization: Bearer &lt;token&gt;</code> header.
    </p>
    <table>
      <tr><td>Server LAN address</td><td><code>https://{_get_lan_ip()}:8765</code></td></tr>
      <tr><td>CA certificate</td><td><a href="/settings/ca-cert" class="btn small primary">⬇ Download CA cert</a> — install on client devices for TLS</td></tr>
    </table>
    <script>
    async function regenToken() {{
      if (!confirm('Regenerate the API auth token? All clients will need the new token.')) return;
      let r = await fetch('/settings/regen-token', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
        body: 'csrf_token=' + encodeURIComponent(window.__CSRF_TOKEN__)
      }});
      let d = await r.json();
      document.querySelector('code[style*="font-size:0.7rem"]').textContent = d.token;
      alert('Token regenerated. Update your API clients with the new token.');
    }}
    </script>
    </div>
    <div class="card">
    <h2>Danger Zone</h2>
    <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1rem">
      This wipes ALL messages — kills the GPG agent, purges the SQLite DB, deletes all reply*.asc files, and clears the sent log. <strong>This cannot be undone.</strong>
    </p>
    <button class="btn danger" onclick="doWipe()">☠️ Wipe All Messages</button>
    <script>
    async function doWipe() {{
      if (!confirm('Really wipe ALL messages? This kills GPG agent, deletes the DB, and all .asc files. CANNOT BE UNDONE.')) return;
      if (!confirm('Are you absolutely sure? Type yes to confirm.')) return;
      try {{
        let r = await fetch('/api/wipe', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{confirm: 'yes'}})
        }});
        let d = await r.json();
        alert('Wipe complete: ' + d.files_deleted + ' files deleted, DB deleted: ' + d.db_deleted + ', agent killed: ' + d.agent_killed);
        window.location.reload();
      }} catch(e) {{
        alert('Wipe failed: ' + e.message);
      }}
    }}
    </script>
    </div>'''
    return render('Settings', 'settings', body, dark)

@app.route('/settings/ca-cert')
def serve_ca_cert():
    """Download the CA certificate for Android TLS setup."""
    if not CA_CERT_PATH.exists():
        return 'CA certificate not found — run the server with HTTPS first', 404
    from flask import make_response
    resp = make_response(CA_CERT_PATH.read_text())
    resp.headers['Content-Type'] = 'application/x-x509-ca-cert'
    resp.headers['Content-Disposition'] = 'attachment; filename=pgpvault-ca.crt'
    return resp

@app.route('/settings/regen-token', methods=['POST'])
@admin_required
@csrf_protect
def regen_token():
    """Regenerate the API auth token."""
    global AUTH_TOKEN
    token = secrets.token_hex(32)
    try:
        _AUTH_TOKEN_FILE.write_text(token)
        _AUTH_TOKEN_FILE.chmod(0o600)
    except Exception:
        pass
    AUTH_TOKEN = token
    return jsonify({'token': token})

def _get_lan_ip():
    """Get the LAN IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

@app.route('/settings/kill-agent', methods=['POST'])
@admin_required
@csrf_protect
def kill_agent():
    subprocess.run(['gpgconf', '--kill', 'gpg-agent'], capture_output=True)
    subprocess.run(['gpgconf', '--launch', 'gpg-agent'], capture_output=True)
    settings.lockout_active = False
    settings.lockout_remaining = int(os.environ.get('PGP_MAX_ATTEMPTS', '5'))
    return redirect(url_for('settings_page'))

@app.route('/toggle-dark', methods=['POST'])
@csrf_protect
def toggle_dark_mode():
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    resp = app.make_response(redirect(url_for('compose')))
    resp.set_cookie(DARK_MODE_COOKIE, '0' if dark else '1', samesite='Lax', secure=True)
    return resp

# ─── Key Management ─────────────────────────────────────────────────────────────

@app.route('/keys', methods=['GET', 'POST'])
@csrf_protect
def keys_page():
    from flask import g
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    msg = ''
    current_user = getattr(g, 'current_user', None)
    username = current_user['username'] if current_user else None
    keys_raw = list_public_keys(username) if username else ''

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'import':
            key_data = request.form.get('key_data', '').strip()
            if key_data and username:
                out, err, code = import_public_key(key_data, username)
                if code == 0:
                    if 'not changed' in out or 'not changed' in err:
                        msg = '<div class="alert info">Key already imported (no changes).</div>'
                    else:
                        msg = '<div class="alert success">Key imported successfully!</div>'
                    keys_raw = list_public_keys(username)  # refresh
                else:
                    msg = f'<div class="alert error">Import failed: {html.escape(err or out)}</div>'
        elif action == 'delete':
            key_id = request.form.get('key_id', '').strip()
            if key_id and username:
                # Delete secret key first if it exists (required by GPG before deleting pub key)
                del_args = ['--batch', '--yes', '--pinentry-mode', 'loopback']
                pass_file = None
                passphrase = _get_user_passphrase(username)
                if passphrase:
                    pass_file = _passphrase_file(passphrase)
                    del_args.extend(['--passphrase-file', str(pass_file)])
                del_args.extend(['--delete-secret-keys', key_id])
                out, err, code = run_gpg_user(del_args, username)
                if pass_file:
                    pass_file.unlink(missing_ok=True)
                del_args = ['--batch', '--yes', '--delete-keys', key_id]
                out, err, code = run_gpg_user(del_args, username)
                if code == 0:
                    msg = '<div class="alert success">Key deleted.</div>'
                    keys_raw = list_public_keys(username)
                else:
                    logger.error('GPG key delete failed for user %s: %s', username, err)
                    msg = '<div class="alert error">Key deletion failed.</div>'

    # Parse keys into structured display
    # Output with --keyid-format=long --fixed-list-mode looks like:
    #   pub   rsa4096/0FA4F517F1464254 2026-03-27 [SCEAR]
    #       DC0CD526AF3562D1C1C554706A14CEC641BE97C8  (40 hex chars, leading spaces stripped)
    #   uid          [ultimate] User <user@email>
    #   sub   rsa4096/SUBKEY 2026-03-27 [SCE] [expires: 2027-03-27]
    keys = []
    current_key = {}
    for i, line in enumerate(keys_raw.splitlines()):
        stripped = line.lstrip()
        if stripped.startswith('pub') or stripped.startswith('sec'):
            if current_key:
                keys.append(current_key)
            parts = stripped.split()
            # keyid is the algo/size prefix (e.g. rsa4096/) + key fingerprint suffix
            keyid = next((p for p in parts if p.startswith('rsa') or p.startswith('dsa') or p.startswith('elg') or p.startswith('ecc')), '')
            if '/' in keyid:
                keyid = keyid.split('/')[-1]  # just the hex ID, not the algo prefix
            current_key = {'keyid': keyid, 'fingerprint': '', 'uids': [], 'expires': ''}
            # Check for expiry on pub/sec line
            m = re.search(r'\[expires:\s*(\d{4}-\d{2}-\d{2})\]', stripped)
            if m:
                current_key['expires'] = m.group(1)
            # Next line may be the fingerprint (40 hex chars, leading spaces stripped)
            if i + 1 < len(keys_raw.splitlines()):
                next_line = keys_raw.splitlines()[i + 1]
                next_stripped = next_line.lstrip()
                hex_clean = next_stripped.replace(' ', '')
                if len(hex_clean) >= 32 and all(c in '0123456789ABCDEFabcdef' for c in hex_clean[:32]):
                    current_key['fingerprint'] = hex_clean
        elif stripped.startswith('sub'):
            # Expiry may also appear on sub key line
            m = re.search(r'\[expires:\s*(\d{4}-\d{2}-\d{2})\]', stripped)
            if m and current_key and not current_key.get('expires'):
                current_key['expires'] = m.group(1)
        elif stripped.startswith('uid') and current_key:
            # Extract full UID string (not just email), preserving full format like "Name <email@domain>"
            # Format: "uid  [ unknown] User Name"  or  "uid  [ unknown] User Name <user@domain>"
            # Strip the leading "uid" and bracket label, then extract name + optional email
            stripped_uid = re.sub(r'^uid\s+(?:\[[^\]]*\])?\s*', '', stripped)
            m = re.search(r'^(.*?)<([^>]+)>', stripped_uid)
            if m:
                current_key['uids'].append(f'{m.group(1).strip()} <{m.group(2)}>')
            else:
                current_key['uids'].append(stripped_uid.strip())
    if current_key:
        keys.append(current_key)

    body = f'''
    {msg}
    <div class="card">
    <h2>Your Public Keys</h2>
    <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1rem">
      These are your PUBLIC keys — share these with anyone who wants to send you encrypted messages.
      Your secret keys are stored separately and never leave this machine.
    </p>
    <table style="width:100%;border-collapse:collapse">
      <tr style="text-align:left;color:#8b949e">
        <th>Key ID</th><th>Fingerprint</th><th>User IDs</th><th>Expiry</th><th></th>
      </tr>'''
    for k in keys:
        fprint = k.get('fingerprint', '')
        uid_str = '<br>'.join(html.escape(u) for u in k['uids'])
        # Use fingerprint (full or last 16 chars) as the deletable key identifier
        short_id = fprint[-16:] if fprint else k.get('keyid', '')
        delete_key = fprint if fprint else short_id
        # Build expiry badge for each key
        expiry_badge = ''
        if k.get('expires'):
            from datetime import date
            try:
                exp_date = date.fromisoformat(k['expires'])
                today = date.today()
                days_left = (exp_date - today).days
                if days_left < 0:
                    badge_color = '#f85149'; badge_text = f'expired {abs(days_left)}d ago'
                elif days_left <= 30:
                    badge_color = '#d29922'; badge_text = f'expires in {days_left}d'
                else:
                    badge_color = '#3fb950'; badge_text = f'expires {k["expires"]}'
                expiry_badge = f'<span style="background:#1c2128;color:{badge_color};border:1px solid {badge_color};border-radius:4px;padding:1px 6px;font-size:0.75rem">{badge_text}</span>'
            except Exception:
                expiry_badge = f'<span style="color:#8b949e">{k["expires"]}</span>'
        else:
            expiry_badge = f'<span style="color:#8b949e">never expires</span>'
        body += f'''
      <tr style="border-bottom:1px solid #21262d">
        <td style="padding:0.5rem;font-family:monospace">{short_id}</td>
        <td style="padding:0.5rem;font-family:monospace;font-size:0.75rem">{fprint}</td>
        <td style="padding:0.5rem">{uid_str}</td>
        <td style="padding:0.5rem">{expiry_badge}</td>
        <td style="padding:0.5rem">
          <form method="post" style="display:inline">
            {csrf_input()}
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="key_id" value="{delete_key}">
            <button type="submit" class="btn small danger" onclick="return confirm('Delete this public key?')">Delete</button>
          </form>
        </td>
      </tr>'''
    body += '</table></div>'

    body += f'''
    <div class="card">
    <h2>Import a Friend's Public Key</h2>
    <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1rem">
      Paste a friend's public key block below to add them as a recipient.
      Their public key is a <strong>.asc</strong> file they export from their GPG setup.
    </p>
    <form method="post">
      {csrf_input()}
      <input type="hidden" name="action" value="import">
      <div class="form-row">
        <label for="key_data">Public key block (-----BEGIN PGP PUBLIC KEY BLOCK-----)</label>
        <textarea name="key_data" id="key_data" rows="8" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;&#10;...&#10;-----END PGP PUBLIC KEY BLOCK-----"></textarea>
      </div>
      <button type="submit" class="btn primary">Import Key</button>
    </form>
    </div>

    <div class="card">
    <h2>How to Export Your Public Key</h2>
    <pre style="background:#161b22;padding:1rem;border-radius:6px;font-size:0.8rem;overflow-x:auto">
# Export your public key to a file
gpg --armor --export your@email.com > my_public_key.asc

# Or get the ASCII-armored block directly
gpg --armor --export your@email.com

# Share the .asc file with friends — they import it to add you as a recipient
    </pre>
    <p style="color:#8b949e;font-size:0.85rem;margin-top:0.5rem">
      Once imported here, you can select your friend as a recipient when encrypting messages.
    </p>
    </div>
    '''
    return render('Key Management', 'settings', body, dark)

# ─── Health check ────────────────────────────────────────────────────────────────

@app.route('/health')
def health():
    """Public health endpoint — no auth required, used by monitoring."""
    return {'status': 'ok', 'version': '2.1.0'}

# ─── Favicon ─────────────────────────────────────────────────────────────────────

@app.route('/favicon.ico')
def favicon():
    import base64
    # 16x16 blue lock SVG as data URI
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
        '<rect width="16" height="16" fill="#161b22" rx="3"/>'
        '<text x="8" y="12" font-size="10" text-anchor="middle">🔐</text>'
        '</svg>'
    )
    b64 = base64.b64encode(svg.encode()).decode()
    return f'data:image/svg+xml;base64,{b64}', 200, {'Content-Type': 'image/svg+xml'}

# ─── REST API ──────────────────────────────────────────────────────────────────

@app.route('/api/messages', methods=['GET', 'POST'])
def api_messages():
    """
    GET /api/messages — list messages for the authenticated user.
        ?limit=50 &offset=0
        Header: X-User-ID (required for Bearer token auth to specify user context)
    POST /api/messages — encrypt and deliver a new message to a recipient.
        Header: X-User-ID (required for Bearer token auth)
        body: {"recipient": "...", "plaintext": "...", "subject": "..."}
    """
    from flask import g
    current_user = getattr(g, 'current_user', None)
    api_username = current_user['username'] if current_user else None

    # For Bearer token auth, X-User-ID header overrides the api user context
    x_user = request.headers.get('X-User-ID', '').strip()
    if api_username == 'api' and x_user:
        # Validate X-User-ID exists in session DB
        # Never copy is_admin — API users remain non-admin regardless of X-User-ID
        if not re.match(r'^[a-zA-Z0-9_.-]{1,64}$', x_user):
            return jsonify({'error': 'Invalid X-User-ID'}), 400
        sess_conn = _get_session_db()
        user_row = sess_conn.execute('SELECT username, pgp_key_email FROM users WHERE username = ?', (x_user,)).fetchone()
        if user_row:
            api_username = x_user
            g.current_user = {'username': user_row['username'], 'pgp_key_email': user_row['pgp_key_email'], 'is_admin': 0}

    if not api_username or api_username == 'api':
        return jsonify({'error': 'User context required. Use session cookie or X-User-ID header with Bearer token.'}), 401

    username = api_username
    user_email = g.current_user.get('pgp_key_email', '') if g.current_user else ''

    if request.method == 'GET':
        conn = get_user_db(username)
        rows = conn.execute('''
            SELECT id, timestamp, sender, sender_username, recipient, subject, file_path, content_hash, "read", direction
            FROM messages
            ORDER BY timestamp DESC
            LIMIT 50
        ''').fetchall()
        return jsonify([dict(r) for r in rows])

    # POST — encrypt and deliver new message
    data = request.get_json(force=True)
    recipient_email = (data.get('recipient') or '').strip()
    plaintext = (data.get('plaintext') or '').strip()
    subject = (data.get('subject') or '').strip()[:200]

    if not recipient_email or not plaintext:
        return jsonify({'error': 'recipient and plaintext are required'}), 400

    out, err, code = encrypt_to_recipient(recipient_email, plaintext, username)
    if code != 0:
        logger.error('API encrypt failed for user %s: %s', username, err)
        return jsonify({'error': 'Encryption failed'}), 500

    ts = datetime.utcnow().isoformat()
    h = hashlib.sha256(out.encode()).hexdigest()
    sender_db = get_user_db(username)
    reply_num = _next_reply_num(sender_db)

    # Write to sender's sent dir
    sent_dir = USERS_DIR / username / 'sent'
    sent_dir.mkdir(parents=True, exist_ok=True)
    out_path_sent = sent_dir / f'reply{reply_num}.asc'
    out_path_sent.write_text(out)

    # Write to recipient's inbox dir
    recipient_username = None
    for dirent in os.listdir(USERS_DIR):
        pubkey = USERS_DIR / dirent / 'pubkey.asc'
        if pubkey.exists() and recipient_email in pubkey.read_text():
            recipient_username = dirent
            break
    out_path_recv = out_path_sent
    if recipient_username:
        inbox_dir = USERS_DIR / recipient_username / 'inbox'
        inbox_dir.mkdir(parents=True, exist_ok=True)
        out_path_recv = inbox_dir / f'reply{reply_num}.asc'
        out_path_recv.write_text(out)

    # Record in sender's DB
    sender_db.execute('''
        INSERT INTO messages (timestamp, sender, sender_username, recipient, subject, file_path, content_hash, encrypted_payload, direction)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sent')
    ''', (ts, user_email, username, recipient_email, subject, str(out_path_sent), h, out))
    sender_db.commit()

    # Record in recipient's DB
    if recipient_username:
        recv_db = get_user_db(recipient_username)
        recv_db.execute('''
            INSERT INTO messages (timestamp, sender, sender_username, recipient, subject, file_path, content_hash, encrypted_payload, direction)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'received')
        ''', (ts, user_email, username, recipient_email, subject, str(out_path_recv), h, out))
        recv_db.commit()

    return jsonify({
        'id': reply_num,
        'timestamp': ts,
        'recipient': recipient_email,
        'subject': subject,
        'file': out_path_sent.name,
        'content_hash': h,
    }), 201


@app.route('/api/messages/<int:msg_id>', methods=['GET', 'DELETE', 'PATCH'])
def api_message(msg_id):
    """GET/DELETE/PATCH a message. Requires session cookie or X-User-ID header."""
    from flask import g
    current_user = getattr(g, 'current_user', None)
    api_username = current_user['username'] if current_user else None

    x_user = request.headers.get('X-User-ID', '').strip()
    if api_username == 'api' and x_user:
        if not re.match(r'^[a-zA-Z0-9_.-]{1,64}$', x_user):
            return jsonify({'error': 'Invalid X-User-ID'}), 400
        sess_conn = _get_session_db()
        user_row = sess_conn.execute('SELECT username, pgp_key_email FROM users WHERE username = ?', (x_user,)).fetchone()
        if user_row:
            api_username = x_user
            g.current_user = {'username': user_row['username'], 'pgp_key_email': user_row['pgp_key_email'], 'is_admin': 0}

    if not api_username or api_username == 'api':
        return jsonify({'error': 'User context required'}), 401

    username = api_username
    conn = get_user_db(username)
    row = conn.execute('SELECT * FROM messages WHERE id = ?', (msg_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    if request.method == 'DELETE':
        if row['file_path']:
            asc_path = Path(row['file_path'])
            if asc_path.exists():
                try: asc_path.unlink()
                except Exception: pass
        conn.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
        conn.commit()
        return jsonify({'deleted': msg_id})

    if request.method == 'PATCH':
        conn.execute('UPDATE messages SET "read" = 1 WHERE id = ?', (msg_id,))
        conn.commit()
        return jsonify({'id': msg_id, 'read': 1})

    # GET — decrypt
    plaintext, err, code = decrypt_with_user_key(row['encrypted_payload'], username)
    if code != 0:
        logger.error('API decrypt failed for user %s: %s', username, err)
        return jsonify({'error': 'Decryption failed'}), 500
    return jsonify({
        'id': row['id'],
        'timestamp': row['timestamp'],
        'sender': row['sender'],
        'recipient': row['recipient'],
        'subject': row['subject'],
        'file_path': row['file_path'],
        'content_hash': row['content_hash'],
        'plaintext': plaintext,
    })

# ─── Kill GPG Agent + Wipe ───────────────────────────────────────────────────

@app.route('/api/wipe', methods=['POST'])
def api_wipe():
    """
    Kill GPG agent, wipe all messages from DB, delete all reply*.asc files.
    Requires {"confirm": "yes"} in body. Irreversible. Admin only.
    """
    current_user = getattr(g, 'current_user', None)
    if not current_user or current_user.get('is_admin') != 1:
        return jsonify({'error': 'Admin access required'}), 403
    data = request.get_json(force=True) or {}
    if data.get('confirm') != 'yes':
        return jsonify({'error': 'Must pass {"confirm": "yes"} to confirm wipe'}), 400

    results = {'agent_killed': False, 'files_deleted': 0, 'db_deleted': False, 'errors': []}

    # Kill GPG agent
    try:
        subprocess.run(['gpgconf', '--kill', 'gpg-agent'], capture_output=True)
        results['agent_killed'] = True
    except Exception as e:
        results['errors'].append(f'agent kill: {e}')

    # Delete all reply*.asc files
    try:
        for f in PGP_DIR.glob('reply*.asc'):
            f.unlink()
            results['files_deleted'] += 1
    except Exception as e:
        results['errors'].append(f'file delete: {e}')

    # Delete DB file
    try:
        if DB_PATH.exists():
            DB_PATH.unlink()
            results['db_deleted'] = True
        # Also clear in-memory connection
        if hasattr(threading.current_thread(), '_db'):
            try: threading.current_thread()._db.close()
            except: pass
    except Exception as e:
        results['errors'].append(f'db delete: {e}')

    # Clear sent_log.json
    try:
        sl = PGP_DIR / 'sent_log.json'
        if sl.exists(): sl.unlink()
    except Exception as e:
        results['errors'].append(f'sent_log delete: {e}')

    return jsonify(results)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _next_reply_num(conn) -> int:
    """
    Atomically get the next reply number.
    Uses UPDATE with RETURNING (SQLite 3.38+) for true atomicity.
    Falls back to file scan for older SQLite versions.
    """
    try:
        row = conn.execute("""
            UPDATE reply_seq SET num = num + 1 RETURNING num
        """).fetchone()
        if row:
            conn.commit()
            return row[0]
        raise RuntimeError("RETURNING failed")
    except Exception:
        # Fallback: scan file system for highest reply number (not atomic, but safe)
        nums = []
        for f in PGP_DIR.glob('reply*.asc'):
            import re
            m = re.match(r'reply(\d+)', f.name)
            if m:
                nums.append(int(m.group(1)))
        return (max(nums) if nums else 0) + 1

def _append_sent_log(recipient, file_path):
    """Append to sent_log.json for backwards compat."""
    log_path = PGP_DIR / 'sent_log.json'
    log = []
    if log_path.exists():
        try: log = json.loads(log_path.read_text())
        except: pass
    log.append({'timestamp': datetime.utcnow().isoformat(), 'recipient': recipient, 'output': file_path})
    log_path.write_text(json.dumps(log, indent=2))

# ─── Main ──────────────────────────────────────────────────────────────────────

def _ensure_tls_cert():
    """Generate self-signed CA + server cert on first run."""
    if CERT_PATH.exists() and KEY_PATH.exists() and CA_CERT_PATH.exists():
        return
    PGP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        import subprocess
        ca_key = PGP_DIR / 'pgpvault-ca.key'
        ca_passphrase = secrets.token_hex(32)
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-days', '3650',
            '-subj', '/CN=PGPVaultCA/O=EchoVault',
            '-keyout', str(ca_key), '-out', str(CA_CERT_PATH),
            '-passout', f'pass:{ca_passphrase}', '-nodes',
        ], check=True, capture_output=True)
        subprocess.run([
            'openssl', 'genrsa', '-out', str(KEY_PATH), '4096',
        ], check=True, capture_output=True)
        hostname = socket.gethostname()
        subprocess.run([
            'openssl', 'req', '-new', '-days', '365',
            '-subj', f'/CN={hostname}/O=PGPVault',
            '-key', str(KEY_PATH), '-out', str(CERT_PATH),
            '-CA', str(CA_CERT_PATH), '-CAkey', str(ca_key),
            '-passin', f'pass:{ca_passphrase}', '-nodes',
        ], check=True, capture_output=True)
        print(f"[*] Generated TLS certificates in {PGP_DIR}")
        print(f"[*] Download CA cert: http://localhost:{port}/settings/ca-cert")
    except Exception as e:
        print(f"[!] TLS cert generation failed (openssl not found?): {e}")
        print(f"[!] Server will run over HTTP only.")


def _register_mdns(use_https=True):
    """Register _pgpvault._tcp.local. via mDNS on the LAN."""
    try:
        import zeroconf
    except ImportError:
        return  # python-zeroconf not installed — skip silently

    try:
        from zeroconf import ServiceInfo
        zc = zeroconf.Zeroconf()
        lan_ip = _get_lan_ip()
        scheme = 'https' if use_https else 'http'
        svc = ServiceInfo(
            '_pgpvault._tcp.local.',
            f'PGPVault._pgpvault._tcp.local.',
            addresses=[socket.inet_aton(lan_ip)],
            port=port,
            properties={'scheme': scheme, 'version': '1.0'},
        )
        zc.register_service(svc)
        print(f"[*] mDNS registered: PGPVault._pgpvault._tcp.local. ({scheme}://{lan_ip}:{port})")
    except Exception as e:
        print(f"[!] mDNS registration failed: {e}")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='PGP Vault Web UI')
    parser.add_argument('--init-admin', nargs=3, metavar=('USERNAME', 'PASSWORD', 'EMAIL'),
                        help='Create an admin user: --init-admin alice password alice@vault.local')
    args, _ = parser.parse_known_args()

    # Auto-init admin if no users exist (first run)
    if args.init_admin:
        username, password, pgp_email = args.init_admin
        _init_admin_user(username, password, pgp_email)
        print(f'[*] Admin user created: {username}')
        sys.exit(0)

    # Initialize session DB
    _get_session_db()

    # Initialize message DB and import existing sent_log on first run
    conn = get_db()
    imported = _import_sent_log()

    # Ensure at least one admin exists — prompt if missing
    sess_conn = _get_session_db()
    admin_count = sess_conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
    if admin_count == 0:
        print('[!] No admin user found. Run with:')
        print('    python pgp_webui.py --init-admin <username> <password> <email>')
        print('    Example: python pgp_webui.py --init-admin admin mypass admin@vault.local')
        sys.exit(1)

    port = int(os.environ.get('PGP_WEBUI_PORT', '8765'))

    # Generate TLS certs on first run
    _ensure_tls_cert()
    use_https = CERT_PATH.exists() and KEY_PATH.exists()

    # Register mDNS for LAN discovery
    _register_mdns(use_https=use_https)

    print(r"""
   __   __      _____   _   _  ______  _____
   \ \ / /     |_   _| | \ | ||  ____|/ ____|
    \ V / ______| | |   |  \| || |__  | (___
     \   /|______| | |   | . ` ||  __|  \___ \
     | |         | | |   | |\  || |____ ____) |
     |_|        |___|   |_| \_||______|_____/

   echo-pgp-webui  |  PGP Vault Web UI
   https://github.com/Echo-Computing/echo-pgp-webui
""")
    scheme = 'https' if use_https else 'http'
    print(f'[*] PGP Vault Web UI starting on {scheme}://localhost:{port}')
    print(f'[*] PGP_DIR: {app.config["PGP_DIR"]}')
    print(f'[*] AUTH_TOKEN: {AUTH_TOKEN[:8]}...')
    if imported:
        print(f'[*] Imported {imported} entries from sent_log.json')
    if not use_https:
        print(f'[!] Running over HTTP — API clients should connect via VPN')
    print(f'[*] Press Ctrl+C to stop')

    if use_https:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(str(CERT_PATH), str(KEY_PATH))
        app.run(host='0.0.0.0', port=port, debug=False, ssl_context=ssl_ctx)
    else:
        app.run(host='0.0.0.0', port=port, debug=False)

