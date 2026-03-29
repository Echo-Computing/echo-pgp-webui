#!/usr/bin/env python3
"""
PGP Web UI — standalone Flask interface for encrypt/decrypt operations.

SANITIZED PUBLISH VERSION — replace identity placeholders before deploying.

Run: python3 pgp_webui.py
Opens: http://localhost:8765

Configuration via environment variables:
  PGP_DIR           Directory containing .asc key files and where reply*.asc are saved
  PGP_WEBUI_PORT    Port to listen on (default: 8765)
  PGP_SENDER_ID     Your sender identity — e.g. alice@vault.local (used as --local-user)
  PGP_CLIPBOARD_CLEAR_SECONDS  Seconds before auto-clearing clipboard (default: 30)
  PGP_MAX_ATTEMPTS  Max decryption failures before lockout (default: 5)
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
from pathlib import Path
from datetime import datetime

# ── Identity ─────────────────────────────────────────────────────────────────
# REPLACE THESE with your actual identity before running
SENDER_IDENTITY = os.environ.get('PGP_SENDER_ID', 'CHANGE_ME@vault.local')
PGP_DIR = Path(os.environ.get('PGP_DIR', '.')).resolve()

sys.path.insert(0, str(PGP_DIR))

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
except ImportError:
    print("[ERROR] Flask is required: pip install flask")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)
app = Flask(__name__)
app.config['PGP_DIR'] = PGP_DIR
app.config['SENDER_IDENTITY'] = SENDER_IDENTITY

# ─── Dark mode toggle via cookie ───────────────────────────────────────────────

DARK_MODE_COOKIE = 'dark_mode'
DEFAULT_DARK = True

@app.context_processor
def inject_dark_mode():
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    return dict(dark_mode=dark)

# ─── GPG Passthrough ────────────────────────────────────────────────────────────

def run_gpg(args, input_text=None, input_file=None, decode=True):
    kwargs = {'capture_output': True}
    if input_text:
        kwargs['input'] = input_text.encode('utf-8')
    if input_file:
        kwargs['input'] = Path(input_file).read_bytes()
    result = subprocess.run([GPG_BIN] + args, **kwargs)
    if decode:
        stdout = result.stdout.decode('utf-8', errors='replace')
        stderr = result.stderr.decode('utf-8', errors='replace')
    else:
        stdout, stderr = result.stdout, result.stderr
    return stdout, stderr, result.returncode

def decrypt_text(ciphertext, local_user=None):
    ciphertext = ciphertext.strip()
    while ciphertext.startswith('\n'):
        ciphertext = ciphertext.lstrip('\n')
    if not ciphertext.startswith('-----BEGIN'):
        ciphertext = '-----BEGIN PGP MESSAGE-----\n\n' + ciphertext
    tmp = app.config['PGP_DIR'] / f'.tmp_dec_{int(time.time())}.asc'
    tmp.write_text(ciphertext)
    try:
        args = ['--decrypt', '--output', '-', str(tmp)]
        if local_user:
            args.insert(1, '--local-user')
            args.insert(2, local_user)
        out, err, code = run_gpg(args, decode=True)
        return out, err, code
    finally:
        tmp.unlink(missing_ok=True)

def encrypt_message(recipient, plaintext, armor=True, output=None):
    args = ['--batch', '--yes', '--encrypt', '--always-trust']
    if armor:
        args.append('--armor')
    args += ['--recipient', recipient, '--local-user', app.config['SENDER_IDENTITY']]
    kwargs = {'capture_output': True, 'text': True, 'input': plaintext}
    result = subprocess.run([GPG_BIN] + args, **kwargs)
    if result.returncode == 0 and output:
        Path(output).write_text(result.stdout)
    return result.stdout, result.stderr, result.returncode

def list_public_keys():
    out, err, code = run_gpg(['--list-keys'])
    return out

def list_secret_keys():
    out, err, code = run_gpg(['--list-secret-keys'])
    return out

def import_public_key(key_data: str) -> tuple[str, int]:
    """Import a public key block. Returns (output, returncode)."""
    tmp = app.config['PGP_DIR'] / f'.tmp_import_{int(time.time())}.asc'
    tmp.write_text(key_data.strip())
    out, err, code = run_gpg(['--import', str(tmp)])
    try:
        tmp.unlink()
    except Exception:
        pass
    return out, code

def gpg_agent_status():
    out, err, code = run_gpg(['--list-keys'])
    return 'running' if code == 0 else 'stopped'

# ─── Settings state ────────────────────────────────────────────────────────────

class Settings:
    confirm_guard = False
    confirm_passphrase = ''
    clipboard_auto_clear = int(os.environ.get('PGP_CLIPBOARD_CLEAR_SECONDS', '30'))
    lockout_active = False
    lockout_remaining = int(os.environ.get('PGP_MAX_ATTEMPTS', '5'))
    sent_log = []

    @classmethod
    def guard_enabled(cls):
        return cls.confirm_guard and bool(cls.confirm_passphrase)

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
body { background: #0d1117; color: #e6edf3; font-family: 'Courier New', monospace; min-height: 100vh; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 900px; margin: 0 auto; padding: 2rem 1rem; }
header { display: flex; align-items: center; justify-content: space-between; padding: 1rem 0; border-bottom: 1px solid #30363d; margin-bottom: 2rem; }
header h1 { font-size: 1.2rem; color: #58a6ff; }
header .links a { margin-left: 1.5rem; color: #8b949e; font-size: 0.9rem; }
header .links a.active { color: #e6edf3; }
header .links a:hover { color: #e6edf3; }
.btn { display: inline-block; padding: 0.4rem 1rem; border-radius: 6px; border: 1px solid #30363d; background: #21262d; color: #e6edf3; cursor: pointer; font-size: 0.85rem; font-family: inherit; }
.btn:hover { background: #30363d; }
.btn.danger { border-color: #f85149; color: #f85149; }
.btn.danger:hover { background: #f8514922; }
.btn.primary { background: #238636; border-color: #238636; }
.btn.primary:hover { background: #2ea043; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; margin-bottom: 1.5rem; }
.card h2 { font-size: 0.9rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; }
label { display: block; margin-bottom: 0.5rem; color: #8b949e; font-size: 0.85rem; }
input[type=text], input[type=password], textarea, select { width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; padding: 0.6rem; font-family: 'Courier New', monospace; font-size: 0.9rem; }
input:focus, textarea:focus, select:focus { outline: none; border-color: #58a6ff; }
textarea { resize: vertical; min-height: 150px; }
.form-row { margin-bottom: 1rem; }
.form-row label { margin-bottom: 0.3rem; }
.status-bar { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
.status-item { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 0.6rem 1rem; font-size: 0.8rem; }
.status-item .label { color: #8b949e; }
.status-item .value { color: #e6edf3; margin-left: 0.5rem; }
.status-item .value.ok { color: #3fb950; }
.status-item .value.warn { color: #d29922; }
.status-item .value.danger { color: #f85149; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
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
.alert { padding: 0.8rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; }
.alert.success { background: #0d2119; border: 1px solid #3fb950; color: #3fb950; }
.alert.error { background: #2d1117; border: 1px solid #f85149; color: #f85149; }
.alert.info { background: #0d1726; border: 1px solid #58a6ff; color: #58a6ff; }
.output-block { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
"""

LIGHT_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #f6f8fa; color: #1f2328; font-family: 'Courier New', monospace; min-height: 100vh; }
a { color: #0969da; text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 900px; margin: 0 auto; padding: 2rem 1rem; }
header { display: flex; align-items: center; justify-content: space-between; padding: 1rem 0; border-bottom: 1px solid #d0d7de; margin-bottom: 2rem; }
header h1 { font-size: 1.2rem; color: #0969da; }
header .links a { margin-left: 1.5rem; color: #57606a; font-size: 0.9rem; }
header .links a.active { color: #1f2328; }
header .links a:hover { color: #1f2328; }
.btn { display: inline-block; padding: 0.4rem 1rem; border-radius: 6px; border: 1px solid #d0d7de; background: #f6f8fa; color: #1f2328; cursor: pointer; font-size: 0.85rem; font-family: inherit; }
.btn:hover { background: #eaeef2; }
.btn.danger { border-color: #cf222e; color: #cf222e; }
.btn.danger:hover { background: #ffebe9; }
.btn.primary { background: #2da44e; border-color: #2da44e; color: #fff; }
.btn.primary:hover { background: #2c974b; }
.card { background: #fff; border: 1px solid #d0d7de; border-radius: 6px; padding: 1.5rem; margin-bottom: 1.5rem; }
.card h2 { font-size: 0.9rem; color: #57606a; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; }
label { display: block; margin-bottom: 0.5rem; color: #57606a; font-size: 0.85rem; }
input[type=text], input[type=password], textarea, select { width: 100%; background: #fff; border: 1px solid #d0d7de; border-radius: 6px; color: #1f2328; padding: 0.6rem; font-family: 'Courier New', monospace; font-size: 0.9rem; }
input:focus, textarea:focus, select:focus { outline: none; border-color: #0969da; }
textarea { resize: vertical; min-height: 150px; }
.form-row { margin-bottom: 1rem; }
.form-row label { margin-bottom: 0.3rem; }
.status-bar { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
.status-item { background: #fff; border: 1px solid #d0d7de; border-radius: 6px; padding: 0.6rem 1rem; font-size: 0.8rem; }
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
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
"""

BASE_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{ title }} — PGP Vault</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    {{ css }}
  </style>
</head>
<body>
<div class="container">
<header>
  <h1>🔐 PGP Vault</h1>
  <div class="links">
    {% for endpoint, label in tabs %}
    <a href="{{ url_for(endpoint) }}" class="{{ 'active' if active_tab == endpoint else '' }}">{{ label }}</a>
    {% endfor %}
    <form method="post" action="{{ url_for('toggle_dark_mode') }}" style="display:inline">
      <button type="submit" id="dark_toggle" style="background:none;border:none;color:#8b949e;cursor:pointer;font-size:0.8rem;">{{ '☀ light' if dark_mode else '🌙 dark' }}</button>
    </form>
  </div>
</header>
{{ body | safe }}
</div>
</body>
</html>
"""

def render(title, active_tab, body_html, dark_mode=True, set_cookie=False):
    css = DARK_CSS if dark_mode else LIGHT_CSS
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
        css=css,
        url_for=url_for,
    )
    resp = app.make_response(html)
    if set_cookie:
        resp.set_cookie(DARK_MODE_COOKIE, '0' if dark_mode else '1')
    return resp

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('compose'))

@app.route('/compose', methods=['GET', 'POST'])
def compose():
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    keys_raw = list_public_keys()
    recipients = []
    for line in keys_raw.splitlines():
        if 'uid' in line:
            m = re.search(r'<([^>]+)>', line)
            if m:
                recipients.append(m.group(1))
    recipients = list(dict.fromkeys(recipients))

    alert = ''
    output = ''
    if request.method == 'POST':
        action = request.form.get('action')
        msg = request.form.get('message', '').strip()
        recipient = request.form.get('recipient', '').strip()
        if action == 'encrypt' and msg and recipient:
            confirm = request.form.get('confirm_phrase', '').strip()
            if settings.confirm_guard and confirm != settings.confirm_passphrase:
                alert = '<div class="alert error">Confirmation phrase mismatch.</div>'
            else:
                ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                reply_num = settings.next_reply_num()
                out_path = app.config['PGP_DIR'] / f'reply{reply_num}.asc'
                out, err, code = encrypt_message(recipient, msg, armor=True, output=out_path)
                if code == 0:
                    log_path = app.config['PGP_DIR'] / 'sent_log.json'
                    log = []
                    if log_path.exists():
                        try: log = json.loads(log_path.read_text())
                        except Exception as e:
                            logger.error(f"Failed to read sent_log: {e}")
                    try:
                        log.append({'timestamp': datetime.utcnow().isoformat(), 'recipient': recipient, 'output': str(out_path)})
                        log_path.write_text(json.dumps(log, indent=2))
                    except Exception as e:
                        logger.error(f"Failed to write sent_log: {e}")
                    output = f'<div class="alert success">Encrypted → {out_path.name}</div>'
                else:
                    alert = f'<div class="alert error">Encryption failed: {err}</div>'
        elif action == 'decrypt':
            ciphertext = request.form.get('ciphertext', '').strip()
            local_user = request.form.get('local_user', '').strip()
            confirm = request.form.get('confirm_phrase_dec', '').strip()
            if settings.confirm_guard and confirm != settings.confirm_passphrase:
                alert = '<div class="alert error">Confirmation phrase mismatch.</div>'
            elif ciphertext:
                out, err, code = decrypt_text(ciphertext, local_user=local_user or None)
                if code == 0:
                    output = f'<div class="alert success">Decrypted:</div><div class="output-block">{out}</div>'
                else:
                    alert = f'<div class="alert error">Decryption failed: {err}</div>'

    guard_on = settings.confirm_guard
    secret_keys_raw = list_secret_keys()
    local_users = []
    for line in secret_keys_raw.splitlines():
        if 'uid' in line:
            m = re.search(r'<([^>]+)>', line)
            if m:
                local_users.append(m.group(1))
    local_users = list(dict.fromkeys(local_users))

    confirm_row_enc = f'''
    <div class="form-row">
      <label>Confirmation phrase {"" if guard_on else "(guard OFF)"}</label>
      <input type="password" name="confirm_phrase" placeholder="{'vaultbot' if guard_on else 'guard is off'}">
    </div>''' if guard_on else ''

    confirm_row_dec = f'''
    <div class="form-row">
      <label>Confirmation phrase {"" if guard_on else "(guard OFF)"}</label>
      <input type="password" name="confirm_phrase_dec" placeholder="{'vaultbot' if guard_on else 'guard is off'}">
    </div>''' if guard_on else ''

    body = f'''
    {alert}
    <div class="grid2">
    <div class="card">
    <h2>Encrypt</h2>
    <form method="post">
      <input type="hidden" name="action" value="encrypt">
      <div class="form-row">
        <label>Recipient (encrypt TO)</label>
        <select name="recipient">
          <option value="">— select recipient —</option>
          {' '.join(f'<option value="{r}">{r}</option>' for r in recipients)}
        </select>
      </div>
      <div class="form-row">
        <label>Plaintext message</label>
        <textarea name="message" placeholder="Your message..."></textarea>
      </div>
      {confirm_row_enc}
      <button type="submit" class="btn primary">🔒 Encrypt & Save</button>
    </form>
    </div>
    <div class="card">
    <h2>Decrypt</h2>
    <form method="post">
      <input type="hidden" name="action" value="decrypt">
      <div class="form-row">
        <label>Secret key (decrypt WITH)</label>
        <select name="local_user">
          <option value="">— auto-detect —</option>
          {' '.join(f'<option value="{u}">{u}</option>' for u in local_users)}
        </select>
      </div>
      <div class="form-row">
        <label>Ciphertext</label>
        <textarea name="ciphertext" placeholder="-----BEGIN PGP MESSAGE-----..."></textarea>
      </div>
      {confirm_row_dec}
      <button type="submit" class="btn">🔓 Decrypt</button>
    </form>
    </div>
    </div>
    {output}'''
    return render('Compose', 'compose', body, dark)

@app.route('/inbox')
def inbox():
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    pgp_dir = app.config['PGP_DIR']
    messages = []
    for f in sorted(pgp_dir.glob('*.asc'), key=lambda f: f.stat().st_mtime, reverse=True):
        if any(f.name.startswith(p) for p in ('out_', 'roundtrip', 'reply_')):
            continue
        if '_public.asc' in f.name or '_private.asc' in f.name:
            continue
        try:
            content = f.read_text(errors='replace')
            if '-----BEGIN PGP MESSAGE-----' not in content:
                continue
            out, err, code = decrypt_text(content)
            status = 'decrypted' if code == 0 else 'encrypted'
            messages.append({
                'file': f.name,
                'status': status,
                'preview': out[:200] if code == 0 else ('encrypted — ' + f.name),
                'content': out if code == 0 else '',
            })
        except Exception as e:
            messages.append({'file': f.name, 'status': 'error', 'preview': str(e), 'content': ''})
    rows = ''
    for m in messages[:20]:
        rows += f'''<tr>
          <td><code>{m['file']}</code></td>
          <td><span class="value {'ok' if m['status']=='decrypted' else 'warn'}">{m['status']}</span></td>
          <td><code>{m['preview'][:80]}</code></td>
          <td><button class="btn" onclick="copyFile('{m['file']}', this)">📋 Copy</button></td>
        </tr>'''
    body = f'''
    {f'<div class="alert info">{len(messages)} messages found</div>' if messages else '<div class="alert info">No .asc files found in {pgp_dir}</div>'}
    <div class="card"><h2>Inbox</h2>
    <table><thead><tr><th>File</th><th>Status</th><th>Preview</th><th></th></tr></thead>
    <tbody>{rows}</tbody></table>
    </div>
    <script>
    async function copyFile(filename, btn) {{
      try {{
        let resp = await fetch('/inbox/raw/' + encodeURIComponent(filename));
        if (!resp.ok) throw new Error('Failed to load file');
        let text = await resp.text();
        await navigator.clipboard.writeText(text);
        btn.textContent = '✓ Copied';
        setTimeout(() => {{ btn.textContent = '📋 Copy'; }}, 1500);
      }} catch(e) {{
        alert('Copy failed: ' + e.message);
      }}
    }}
    </script>'''
    return render('Inbox', 'inbox', body, dark)

@app.route('/inbox/raw/<filename>')
def inbox_raw(filename):
    pgp_dir = app.config['PGP_DIR']
    safe_name = Path(filename).name
    file_path = pgp_dir / safe_name
    if not file_path.exists() or not file_path.is_file():
        return 'File not found', 404
    return file_path.read_text(errors='replace'), 200, {'Content-Type': 'text/plain'}

@app.route('/sent')
def sent():
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    settings.load_sent_log()
    rows = ''
    for e in reversed(settings.sent_log[-30:]):
        rows += f'''<tr>
          <td>{e.get('timestamp','')}</td>
          <td>{e.get('recipient','')}</td>
          <td><code>{e.get('output','')}</code></td>
        </tr>'''
    table_html = f'<div class="card"><h2>Sent Log</h2><table><thead><tr><th>Time (UTC)</th><th>Recipient</th><th>File</th></tr></thead><tbody>{rows}</tbody></table></div>'
    body = table_html + f'''
    <div class="card"><h2>Sent Log File</h2>
    <p style="color:#8b949e;font-size:0.8rem;margin-bottom:1rem">{app.config['PGP_DIR'] / 'sent_log.json'}</p>
    <a href="{url_for('clear_sent_log')}" class="btn danger" onclick="return confirm(\'Clear sent log?\')">🗑 Clear Log</a>
    </div>'''
    return render('Sent Log', 'sent', body, dark)

@app.route('/sent/clear')
def clear_sent_log():
    log_path = app.config['PGP_DIR'] / 'sent_log.json'
    if log_path.exists():
        log_path.unlink()
    settings.sent_log = []
    return redirect(url_for('sent'))

@app.route('/settings', methods=['GET', 'POST'])
def settings_page():
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    msg = ''

    if request.method == 'POST':
        settings.load_sent_log()
        guard_action = request.form.get('guard_action')
        passphrase = request.form.get('passphrase', '').strip()
        if guard_action == 'enable' and passphrase:
            settings.confirm_guard = True
            settings.confirm_passphrase = passphrase
            msg = f'<div class="alert success">Guard ENABLED — phrase set.</div>'
        else:
            settings.confirm_guard = False
            settings.confirm_passphrase = ''
            if guard_action == 'disable':
                msg = '<div class="alert info">Guard DISABLED.</div>'
            elif guard_action == 'enable' and not passphrase:
                msg = '<div class="alert error">Enable failed — passphrase required.</div>'

    guard_on = settings.confirm_guard
    agent_ok = gpg_agent_status() == 'running'
    lockout = settings.lockout_active
    remaining = settings.lockout_remaining
    clipboard_sec = os.environ.get('PGP_CLIPBOARD_CLEAR_SECONDS', '30')

    body = f'''
    {msg}
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
        <span class="label">Lockout:</span>
        <span class="value {'danger' if lockout else 'ok'}">{'LOCKED' if lockout else f'Clear ({remaining} attempts left)'}</span>
      </div>
      <div class="status-item">
        <span class="label">Clipboard clear:</span>
        <span class="value">{clipboard_sec}s</span>
      </div>
    </div>
    <a href="{url_for('kill_agent')}" class="btn danger" onclick="return confirm(\'Restart gpg-agent and clear all cached passphrases?\')">💀 Kill Agent (clear passphrase cache)</a>
    </div>
    <div class="card">
    <h2>Confirmation Guard</h2>
    <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1rem">
      When ON, encrypting and decrypting in the UI requires the phrase below. Disable to use the UI without guard.
    </p>
    <form method="post">
    <input type="hidden" name="guard_action" value="disable" id="guard_action_default">
    <div class="toggle-row">
      <span>Guard is {'ON' if guard_on else 'OFF'}</span>
      <label class="toggle">
        <input type="checkbox" name="guard_action" id="guard_action_enable" value="enable" {'checked' if guard_on else ''} onchange="document.getElementById('guard_action_default').disabled = this.checked;">
        <span class="slider"></span>
      </label>
    </div>
    <div class="form-row" style="margin-top:1rem;">
      <label for="passphrase_input">Passphrase — {'currently set' if settings.confirm_passphrase else 'not set'}</label>
      <input type="password" name="passphrase" id="passphrase_input" placeholder="Enter phrase to activate guard...">
    </div>
    <button type="submit" class="btn primary">Apply</button>
    </form>
    </div>
    <div class="card">
    <h2>Environment</h2>
    <table>
      <tr><td>PGP_SENDER_ID</td><td><code>{app.config['SENDER_IDENTITY']}</code></td></tr>
      <tr><td>PGP_DIR</td><td><code>{app.config['PGP_DIR']}</code></td></tr>
      <tr><td>PGP_CLIPBOARD_CLEAR_SECONDS</td><td><code>{os.environ.get('PGP_CLIPBOARD_CLEAR_SECONDS','30')}</code></td></tr>
      <tr><td>PGP_MAX_ATTEMPTS</td><td><code>{os.environ.get('PGP_MAX_ATTEMPTS','5')}</code></td></tr>
    </table>
    </div>'''
    return render('Settings', 'settings', body, dark)

@app.route('/settings/kill-agent')
def kill_agent():
    subprocess.run(['gpgconf', '--kill', 'gpg-agent'], capture_output=True)
    subprocess.run(['gpgconf', '--launch', 'gpg-agent'], capture_output=True)
    settings.lockout_active = False
    settings.lockout_remaining = int(os.environ.get('PGP_MAX_ATTEMPTS', '5'))
    return redirect(url_for('settings_page'))

@app.route('/toggle-dark', methods=['POST'])
def toggle_dark_mode():
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    resp = app.make_response(redirect(url_for('compose')))
    resp.set_cookie(DARK_MODE_COOKIE, '0' if dark else '1')
    return resp

# ─── Key Management ─────────────────────────────────────────────────────────────

@app.route('/keys', methods=['GET', 'POST'])
def keys_page():
    dark = request.cookies.get(DARK_MODE_COOKIE, '1') == '1'
    msg = ''
    keys_raw = list_public_keys()

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'import':
            key_data = request.form.get('key_data', '').strip()
            if key_data:
                out, code = import_public_key(key_data)
                if code == 0:
                    msg = '<div class="alert success">Key imported successfully!</div>'
                    keys_raw = list_public_keys()  # refresh
                else:
                    msg = f'<div class="alert error">Import failed: {out}</div>'
        elif action == 'delete':
            key_id = request.form.get('key_id', '').strip()
            if key_id:
                out, err, code = run_gpg(['--delete-keys', key_id])
                if code == 0:
                    msg = '<div class="alert success">Key deleted.</div>'
                    keys_raw = list_public_keys()
                else:
                    msg = f'<div class="alert error">Delete failed: {err}</div>'

    # Parse keys into structured display
    keys = []
    current_key = {}
    for line in keys_raw.splitlines():
        if line.startswith('pub'):
            if current_key:
                keys.append(current_key)
            parts = line.split()
            current_key = {'line': line, 'keyid': parts[-1] if parts else '', 'uids': []}
        elif line.startswith('uid'):
            m = re.search(r'<([^>]+)>', line)
            current_key['uids'].append(m.group(1) if m else line.strip())
        elif line.startswith('fpr'):
            current_key['fingerprint'] = line.split()[-1]
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
        <th>Key ID</th><th>Fingerprint</th><th>User IDs</th><th></th>
      </tr>'''
    for k in keys:
        fprint = k.get('fingerprint', '')
        uid_str = '<br>'.join(k['uids'])
        keyid = k.get('keyid', '')
        body += f'''
      <tr style="border-bottom:1px solid #21262d">
        <td style="padding:0.5rem;font-family:monospace">{keyid}</td>
        <td style="padding:0.5rem;font-family:monospace;font-size:0.75rem">{fprint}</td>
        <td style="padding:0.5rem">{uid_str}</td>
        <td style="padding:0.5rem">
          <form method="post" style="display:inline">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="key_id" value="{keyid}">
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
      <input type="hidden" name="action" value="import">
      <div class="form-row">
        <label>Public key block (-----BEGIN PGP PUBLIC KEY BLOCK-----)</label>
        <textarea name="key_data" rows="8" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;&#10;...&#10;-----END PGP PUBLIC KEY BLOCK-----"></textarea>
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

# ─── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PGP_WEBUI_PORT', '8765'))
    sender = app.config['SENDER_IDENTITY']
    print(r"""
   __   __      _____   _   _  ______  _____
   \ \ / /     |_   _| | \ | ||  ____|/ ____|
    \ V / ______| | |   |  \| || |__  | (___
     \   /|______| | |   | . ` ||  __|  \___ \
     | |         | | |   | |\  || |____ ____) |
     |_|        |___|   |_| \_||______|_____/

   echo-pgp-webui  |  Echo Vault <echo@vault.local>
   https://github.com/Echo-Computing/echo-pgp-webui
""")
    print(f"[*] PGP Vault Web UI starting on http://localhost:{port}")
    print(f"[*] PGP_DIR: {app.config['PGP_DIR']}")
    print(f"[*] SENDER_IDENTITY: {sender}")
    print(f"[*] Press Ctrl+C to stop")
    app.run(host='0.0.0.0', port=port, debug=False)
