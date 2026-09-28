import os
import aiosqlite
from bot.config import settings

_db_conn = None


async def get_db() -> aiosqlite.Connection:
    global _db_conn
    if _db_conn is None:
        db_dir = os.path.dirname(settings.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        _db_conn = await aiosqlite.connect(settings.db_path)
        _db_conn.row_factory = aiosqlite.Row
        await _db_conn.execute("PRAGMA foreign_keys = ON;")
    return _db_conn


async def init_db():
    db = await get_db()
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            public_key TEXT UNIQUE NOT NULL,
            private_key TEXT NOT NULL,
            ip_address TEXT UNIQUE NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            delta_rx INTEGER NOT NULL DEFAULT 0,
            delta_tx INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS peer_snapshots (
            public_key TEXT PRIMARY KEY,
            last_rx INTEGER NOT NULL DEFAULT 0,
            last_tx INTEGER NOT NULL DEFAULT 0,
            last_handshake INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_traffic_logs_peer_ts ON traffic_logs(peer_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_traffic_logs_ts ON traffic_logs(timestamp);
    """)
    await db.commit()


async def close_db():
    global _db_conn
    if _db_conn:
        await _db_conn.close()
        _db_conn = None
