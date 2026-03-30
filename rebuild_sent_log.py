#!/usr/bin/env python3
"""
Rebuild sent_log.json by rescanning ALL reply*.asc files.
Uses gpg --list-packets to extract metadata without full decryption.
"""
import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

PGP_DIR = Path('D:/pgp')
SENT_LOG = PGP_DIR / 'sent_log.json'
BACKUP_LOG = PGP_DIR / 'sent_log.json.bak'

GPG_BIN = shutil.which('gpg') or shutil.which('gpg2') or 'gpg'

def get_gpg_metadata(asc_path):
    """Extract recipient and timestamp from GPG packet without decrypting."""
    result = subprocess.run(
        [GPG_BIN, '--list-packets', '--verbose', str(asc_path)],
        capture_output=True, text=True
    )
    output = result.stdout + result.stderr

    recipient = None
    timestamp = None

    for line in output.splitlines():
        line = line.strip()
        if ':recipient information:' in line.lower():
            # Next line typically has the key ID
            pass
        elif 'pub' in line and not recipient:
            # Try to extract key ID from pub line
            parts = line.split()
            for p in parts:
                if p.startswith('4') and len(p) == 16:  # Key ID format
                    recipient = f"key_{p}"
                    break
        elif line.startswith('@'):
            timestamp = line[1:]  # Sometimes timestamp appears after @

    return recipient, timestamp

def extract_from_decrypt(asc_path):
    """Do a test decrypt to get recipient info (silent, no passphrase prompt)."""
    result = subprocess.run(
        [GPG_BIN, '--batch', '--decrypt', '--throw-keyids', str(asc_path)],
        capture_output=True, text=True
    )
    # stderr often has useful info even when encryption fails
    return result.stderr

def main():
    print(f"[*] PGP_DIR: {PGP_DIR}")
    print(f"[*] Sent log: {SENT_LOG}")

    # Backup existing log
    if SENT_LOG.exists():
        shutil.copy2(SENT_LOG, BACKUP_LOG)
        print(f"[+] Backed up existing log to {BACKUP_LOG}")

    # Load existing log to get already-logged files
    existing_entries = []
    logged_files = set()
    if SENT_LOG.exists():
        try:
            existing_entries = json.loads(SENT_LOG.read_text())
            logged_files = {Path(e['output']).name for e in existing_entries}
            print(f"[+] Loaded {len(existing_entries)} existing entries")
        except Exception as e:
            print(f"[!] Failed to load existing log: {e}")

    # Find ALL reply*.asc files
    reply_files = sorted(PGP_DIR.glob('reply*.asc'), key=lambda f: f.stat().st_mtime)

    # Filter out files that start with things like reply_confirm, reply_verify, reply_to_
    # Only include numbered reply files (replyNNN.asc)
    import re
    numbered_replies = []
    for f in reply_files:
        if re.match(r'^reply\d+\.asc$', f.name):
            numbered_replies.append(f)

    print(f"[+] Total reply*.asc files: {len(reply_files)}")
    print(f"[+] Numbered reply files: {len(numbered_replies)}")

    # Build new log entries
    new_entries = []
    skipped = 0

    for f in numbered_replies:
        if f.name in logged_files:
            # Already in log, keep existing entry
            for e in existing_entries:
                if Path(e['output']).name == f.name:
                    new_entries.append(e)
                    break
            continue

        # Get file stats for timestamp fallback
        stat = f.stat()
        file_mtime = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%dT%H:%M:%S')

        # Try to get recipient from GPG
        recipient = f"unknown ({f.name})"

        # Use gpg --list-packets to see recipient info
        result = subprocess.run(
            [GPG_BIN, '--list-packets', str(f)],
            capture_output=True, text=True
        )
        output = result.stdout + result.stderr

        # Parse for recipient
        for line in output.split('\n'):
            if ':recipient:' in line.lower():
                # Extract the user ID or key ID
                parts = line.split(':')
                if len(parts) >= 4:
                    recipient = parts[-1].strip() if parts[-1].strip() else recipient
            elif 'keyid:' in line.lower():
                parts = line.split(':')
                if len(parts) >= 2:
                    keyid = parts[-1].strip()
                    if keyid and len(keyid) >= 8:
                        recipient = f"keyid_{keyid}"

        new_entries.append({
            'timestamp': file_mtime,
            'recipient': recipient,
            'output': str(f)
        })
        skipped += 1

    # Sort by timestamp (oldest first)
    new_entries.sort(key=lambda x: x.get('timestamp', ''))

    print(f"[+] Added {skipped} new entries")
    print(f"[+] Total entries: {len(new_entries)}")

    # Write new log
    SENT_LOG.write_text(json.dumps(new_entries, indent=2))
    print(f"[+] Wrote {len(new_entries)} entries to {SENT_LOG}")

    # Also include the non-numbered reply files in a separate list
    # These are special files like reply_confirm, reply_to_coda, etc
    special_files = [f for f in reply_files if not re.match(r'^reply\d+\.asc$', f.name)]
    if special_files:
        print(f"[!] Skipped {len(special_files)} special files: {[f.name for f in special_files]}")

if __name__ == '__main__':
    main()
