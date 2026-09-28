import datetime
from typing import Optional, List, Dict, Any
from bot.database.db import get_db


async def add_peer(name: str, public_key: str, private_key: str, ip_address: str) -> int:
    db = await get_db()
    safe_name = await ensure_unique_name(name)
    cursor = await db.execute(
        """
        INSERT INTO peers (name, public_key, private_key, ip_address, is_active)
        VALUES (?, ?, ?, ?, 1)
        """,
        (safe_name, public_key, private_key, ip_address)
    )
    await db.commit()
    return cursor.lastrowid


async def get_peer_by_id(peer_id: int) -> Optional[Dict[str, Any]]:
    db = await get_db()
    cursor = await db.execute(
        """
        SELECT p.*, s.last_handshake, s.last_rx, s.last_tx
        FROM peers p
        LEFT JOIN peer_snapshots s ON p.public_key = s.public_key
        WHERE p.id = ?
        """,
        (peer_id,)
    )
    row = await cursor.fetchone()
    return dict(row) if row else None


async def get_peer_by_name(name: str) -> Optional[Dict[str, Any]]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM peers WHERE name = ?",
        (name,)
    )
    row = await cursor.fetchone()
    return dict(row) if row else None


async def get_peer_by_pubkey(public_key: str) -> Optional[Dict[str, Any]]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM peers WHERE public_key = ?",
        (public_key,)
    )
    row = await cursor.fetchone()
    return dict(row) if row else None


async def get_all_peers() -> List[Dict[str, Any]]:
    db = await get_db()
    cursor = await db.execute(
        """
        SELECT p.*, s.last_handshake, s.last_rx, s.last_tx
        FROM peers p
        LEFT JOIN peer_snapshots s ON p.public_key = s.public_key
        ORDER BY p.id ASC
        """
    )
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def toggle_peer_status(peer_id: int, is_active: bool) -> bool:
    db = await get_db()
    await db.execute(
        "UPDATE peers SET is_active = ? WHERE id = ?",
        (1 if is_active else 0, peer_id)
    )
    await db.commit()
    return True


async def delete_peer(peer_id: int) -> bool:
    db = await get_db()
    # Also remove snapshot
    peer = await get_peer_by_id(peer_id)
    if peer:
        await db.execute("DELETE FROM peer_snapshots WHERE public_key = ?", (peer["public_key"],))
        await db.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
        await db.commit()
        return True
    return False


async def ensure_unique_name(name: str, exclude_peer_id: Optional[int] = None) -> str:
    """Generates a non-conflicting peer name by appending a counter if needed."""
    db = await get_db()
    base_name = name.strip() if (name and name.strip()) else "Client"
    candidate = base_name
    counter = 2
    while True:
        if exclude_peer_id is not None:
            cursor = await db.execute("SELECT id FROM peers WHERE name = ? AND id != ?", (candidate, exclude_peer_id))
        else:
            cursor = await db.execute("SELECT id FROM peers WHERE name = ?", (candidate,))
        row = await cursor.fetchone()
        if not row:
            return candidate
        candidate = f"{base_name}-{counter}"
        counter += 1


async def import_external_peer(name: str, public_key: str, ip_address: str, private_key: str = "") -> int:
    db = await get_db()
    existing = await get_peer_by_pubkey(public_key)
    if existing:
        safe_name = await ensure_unique_name(name, exclude_peer_id=existing["id"])
        await update_peer_info(peer_id=existing["id"], name=safe_name, private_key=private_key or None, ip_address=ip_address)
        return existing["id"]

    safe_name = await ensure_unique_name(name)
    cursor = await db.execute(
        """
        INSERT INTO peers (name, public_key, private_key, ip_address, is_active)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(public_key) DO UPDATE SET
            name = excluded.name,
            private_key = CASE WHEN excluded.private_key != '' THEN excluded.private_key ELSE peers.private_key END,
            ip_address = excluded.ip_address,
            is_active = 1
        """,
        (safe_name, public_key, private_key, ip_address)
    )
    await db.commit()
    return cursor.lastrowid


async def update_peer_info(
    peer_id: int,
    name: Optional[str] = None,
    private_key: Optional[str] = None,
    ip_address: Optional[str] = None
):
    db = await get_db()
    updates = []
    params = []
    if name is not None and name.strip():
        safe_name = await ensure_unique_name(name, exclude_peer_id=peer_id)
        updates.append("name = ?")
        params.append(safe_name)
    if private_key:
        updates.append("private_key = ?")
        params.append(private_key)
    if ip_address:
        updates.append("ip_address = ?")
        params.append(ip_address)
    if updates:
        params.append(peer_id)
        await db.execute(f"UPDATE peers SET {', '.join(updates)} WHERE id = ?", tuple(params))
        await db.commit()


async def get_allocated_ips() -> List[str]:
    db = await get_db()
    cursor = await db.execute("SELECT ip_address FROM peers")
    rows = await cursor.fetchall()
    return [row["ip_address"] for row in rows]


async def record_traffic_snapshot(
    public_key: str,
    current_rx: int,
    current_tx: int,
    latest_handshake: int,
    fallback_ip: str = "unknown"
):
    db = await get_db()
    # Get previous snapshot
    cursor = await db.execute(
        "SELECT last_rx, last_tx FROM peer_snapshots WHERE public_key = ?",
        (public_key,)
    )
    snapshot = await cursor.fetchone()

    delta_rx = 0
    delta_tx = 0

    if snapshot:
        last_rx = snapshot["last_rx"]
        last_tx = snapshot["last_tx"]

        # If counter wrapped or interface restarted, current is the new delta
        delta_rx = (current_rx - last_rx) if current_rx >= last_rx else current_rx
        delta_tx = (current_tx - last_tx) if current_tx >= last_tx else current_tx
    else:
        # First observation of this peer in snapshots
        delta_rx = 0
        delta_tx = 0

    # Save or update snapshot
    await db.execute(
        """
        INSERT INTO peer_snapshots (public_key, last_rx, last_tx, last_handshake, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(public_key) DO UPDATE SET
            last_rx = excluded.last_rx,
            last_tx = excluded.last_tx,
            last_handshake = excluded.last_handshake,
            updated_at = CURRENT_TIMESTAMP
        """,
        (public_key, current_rx, current_tx, latest_handshake)
    )

    # If there is traffic to log, find corresponding peer and log it
    if delta_rx > 0 or delta_tx > 0:
        cursor_peer = await db.execute(
            "SELECT id FROM peers WHERE public_key = ?",
            (public_key,)
        )
        peer = await cursor_peer.fetchone()
        if not peer:
            # Auto-register this peer into peers table
            auto_name = f"Client-{public_key[:8]}"
            await import_external_peer(auto_name, public_key, fallback_ip)
            cursor_peer = await db.execute(
                "SELECT id FROM peers WHERE public_key = ?",
                (public_key,)
            )
            peer = await cursor_peer.fetchone()

        if peer:
            await db.execute(
                """
                INSERT INTO traffic_logs (peer_id, delta_rx, delta_tx, timestamp)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (peer["id"], delta_rx, delta_tx)
            )

    await db.commit()


async def get_peer_traffic_summary(peer_id: int) -> Dict[str, Dict[str, int]]:
    """
    Returns traffic stats for:
    - day (last 24 hours)
    - week (last 7 days)
    - month (last 30 days)
    - year (last 365 days)
    - all (all time)
    """
    db = await get_db()
    periods = {
        "day": "-24 hours",
        "week": "-7 days",
        "month": "-30 days",
        "year": "-365 days"
    }

    result = {}
    for period_name, sql_mod in periods.items():
        cursor = await db.execute(
            f"""
            SELECT COALESCE(SUM(delta_rx), 0) AS rx, COALESCE(SUM(delta_tx), 0) AS tx
            FROM traffic_logs
            WHERE peer_id = ? AND timestamp >= datetime('now', '{sql_mod}')
            """,
            (peer_id,)
        )
        row = await cursor.fetchone()
        result[period_name] = {"rx": row["rx"], "tx": row["tx"]}

    # All time
    cursor_all = await db.execute(
        """
        SELECT COALESCE(SUM(delta_rx), 0) AS rx, COALESCE(SUM(delta_tx), 0) AS tx
        FROM traffic_logs
        WHERE peer_id = ?
        """,
        (peer_id,)
    )
    row_all = await cursor_all.fetchone()
    result["all"] = {"rx": row_all["rx"], "tx": row_all["tx"]}

    return result


async def get_overall_traffic_summary() -> Dict[str, Dict[str, int]]:
    """
    Returns overall traffic stats for the whole server:
    - day (last 24 hours)
    - week (last 7 days)
    - month (last 30 days)
    - year (last 365 days)
    - all (all time)
    """
    db = await get_db()
    periods = {
        "day": "-24 hours",
        "week": "-7 days",
        "month": "-30 days",
        "year": "-365 days"
    }

    result = {}
    for period_name, sql_mod in periods.items():
        cursor = await db.execute(
            f"""
            SELECT COALESCE(SUM(delta_rx), 0) AS rx, COALESCE(SUM(delta_tx), 0) AS tx
            FROM traffic_logs
            WHERE timestamp >= datetime('now', '{sql_mod}')
            """
        )
        row = await cursor.fetchone()
        result[period_name] = {"rx": row["rx"], "tx": row["tx"]}

    cursor_all = await db.execute(
        """
        SELECT COALESCE(SUM(delta_rx), 0) AS rx, COALESCE(SUM(delta_tx), 0) AS tx
        FROM traffic_logs
        """
    )
    row_all = await cursor_all.fetchone()
    result["all"] = {"rx": row_all["rx"], "tx": row_all["tx"]}

    return result


async def get_clients_traffic_ranking(period: str = "day") -> List[Dict[str, Any]]:
    """
    Returns list of all peers with their traffic for the period,
    sorted by total traffic descending.
    """
    db = await get_db()
    sql_mod = {
        "day": "-24 hours",
        "week": "-7 days",
        "month": "-30 days",
        "year": "-365 days",
        "all": None
    }.get(period, "-24 hours")

    if sql_mod:
        query = f"""
            SELECT p.id, p.name, p.ip_address, p.is_active,
                   COALESCE(s.last_handshake, 0) AS last_handshake,
                   COALESCE(SUM(l.delta_rx), 0) AS rx,
                   COALESCE(SUM(l.delta_tx), 0) AS tx,
                   (COALESCE(SUM(l.delta_rx), 0) + COALESCE(SUM(l.delta_tx), 0)) AS total
            FROM peers p
            LEFT JOIN peer_snapshots s ON p.public_key = s.public_key
            LEFT JOIN traffic_logs l ON p.id = l.peer_id AND l.timestamp >= datetime('now', '{sql_mod}')
            GROUP BY p.id
            ORDER BY total DESC, p.id ASC
        """
    else:
        query = """
            SELECT p.id, p.name, p.ip_address, p.is_active,
                   COALESCE(s.last_handshake, 0) AS last_handshake,
                   COALESCE(SUM(l.delta_rx), 0) AS rx,
                   COALESCE(SUM(l.delta_tx), 0) AS tx,
                   (COALESCE(SUM(l.delta_rx), 0) + COALESCE(SUM(l.delta_tx), 0)) AS total
            FROM peers p
            LEFT JOIN peer_snapshots s ON p.public_key = s.public_key
            LEFT JOIN traffic_logs l ON p.id = l.peer_id
            GROUP BY p.id
            ORDER BY total DESC, p.id ASC
        """
    cursor = await db.execute(query)
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]

