#!/usr/bin/env python3
"""
SQLite storage backend for PGP messages.
Keeps metadata in DB, .asc files on disk.
"""
import json
import sqlite3
import hashlib
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional

DEFAULT_DB_PATH = None  # Set at runtime from app config

def get_db_path() -> Path:
    """Get DB path from PGP_DIR / pgp_webui config."""
    return Path('D:/pgp/messages.db')

def get_pgp_dir() -> Path:
    """Get PGP directory path."""
    return Path('D:/pgp')

def init_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Initialize DB and return connection."""
    if db_path is None:
        db_path = get_db_path()

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row

    conn.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            subject TEXT DEFAULT '',
            file_path TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            encrypted_payload TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        )
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient)
    ''')
    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)
    ''')
    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender)
    ''')

    conn.commit()
    return conn

def import_from_sent_log(conn: sqlite3.Connection, pgp_dir: Path) -> int:
    """Import existing sent_log.json entries into the DB. Returns count of imported."""
    sent_log_path = pgp_dir / 'sent_log.json'
    if not sent_log_path.exists():
        return 0

    count = 0
    try:
        entries = json.loads(sent_log_path.read_text())
        for entry in entries:
            file_path = Path(entry.get('output', ''))
            if not file_path.exists():
                continue

            # Read and hash the .asc content
            content = file_path.read_text(errors='replace')
            content_hash = hashlib.sha256(content.encode()).hexdigest()

            # Extract sender from SENDER_IDENTITY
            sender = 'echo@vault.local'

            conn.execute('''
                INSERT OR IGNORE INTO messages
                    (timestamp, sender, recipient, subject, file_path, content_hash, encrypted_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry.get('timestamp', datetime.utcnow().isoformat()),
                sender,
                entry.get('recipient', ''),
                '',
                str(file_path),
                content_hash,
                content
            ))
            count += 1
        conn.commit()
    except Exception as e:
        print(f"[!] Failed to import sent_log: {e}")

    return count

def add_message(
    conn: sqlite3.Connection,
    sender: str,
    recipient: str,
    encrypted_payload: str,
    subject: str = '',
    file_path: Optional[str] = None,
    timestamp: Optional[str] = None
) -> int:
    """Add a new message to the DB. Returns the row ID."""
    content_hash = hashlib.sha256(encrypted_payload.encode()).hexdigest()
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()
    if file_path is None:
        file_path = ''

    cursor = conn.execute('''
        INSERT INTO messages
            (timestamp, sender, recipient, subject, file_path, content_hash, encrypted_payload)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, sender, recipient, subject, file_path, content_hash, encrypted_payload))
    conn.commit()
    return cursor.lastrowid

def get_messages(
    conn: sqlite3.Connection,
    recipient: Optional[str] = None,
    sender: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> list[dict]:
    """Query messages with optional filters."""
    query = 'SELECT * FROM messages WHERE 1=1'
    params = []

    if recipient:
        query += ' AND recipient = ?'
        params.append(recipient)
    if sender:
        query += ' AND sender = ?'
        params.append(sender)
    if since:
        query += ' AND timestamp >= ?'
        params.append(since)

    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]

def get_message_by_id(conn: sqlite3.Connection, msg_id: int) -> Optional[dict]:
    """Get a single message by ID."""
    row = conn.execute('SELECT * FROM messages WHERE id = ?', (msg_id,)).fetchone()
    return dict(row) if row else None

def delete_message(conn: sqlite3.Connection, msg_id: int) -> bool:
    """Delete a message by ID. Returns True if deleted."""
    cursor = conn.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
    conn.commit()
    return cursor.rowcount > 0
