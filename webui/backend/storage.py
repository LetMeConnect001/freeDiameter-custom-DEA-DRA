"""
SQLite-backed persistence for rules. Deliberately simple: rules are small, low-volume records
edited by a human through a form, not a high-throughput data path -- a hand-rolled sqlite3 layer
avoids pulling in an ORM for something this size.
"""

import json
import os
import sqlite3
from typing import List, Optional

from models import DeaIdentity, Peer, Rule

DB_PATH_ENV = "RULES_DB_PATH"
DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "rules.db")


def _db_path() -> str:
    return os.environ.get(DB_PATH_ENV, DEFAULT_DB_PATH)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT NOT NULL
        )
        """
    )
    # Single-row table for the DEA's own Identity/Realm. A fixed id=1 row (upserted) is simpler
    # than a one-off settings-key/value scheme for exactly two fields.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS identity (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            data TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def _row_to_rule(row: sqlite3.Row) -> Rule:
    data = json.loads(row["data"])
    data["id"] = row["id"]
    return Rule(**data)


def list_rules() -> List[Rule]:
    conn = get_conn()
    rows = conn.execute("SELECT id, data FROM rules ORDER BY id").fetchall()
    conn.close()
    return [_row_to_rule(r) for r in rows]


def get_rule(rule_id: int) -> Optional[Rule]:
    conn = get_conn()
    row = conn.execute("SELECT id, data FROM rules WHERE id = ?", (rule_id,)).fetchone()
    conn.close()
    return _row_to_rule(row) if row else None


def create_rule(rule: Rule) -> Rule:
    rule.validate_for_type()
    conn = get_conn()
    data = rule.model_dump(exclude={"id"})
    cur = conn.execute("INSERT INTO rules (data) VALUES (?)", (json.dumps(data),))
    conn.commit()
    rule_id = cur.lastrowid
    conn.close()
    rule.id = rule_id
    return rule


def update_rule(rule_id: int, rule: Rule) -> Optional[Rule]:
    rule.validate_for_type()
    conn = get_conn()
    data = rule.model_dump(exclude={"id"})
    cur = conn.execute("UPDATE rules SET data = ? WHERE id = ?", (json.dumps(data), rule_id))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    if not changed:
        return None
    rule.id = rule_id
    return rule


def delete_rule(rule_id: int) -> bool:
    conn = get_conn()
    cur = conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    return bool(changed)


# ---------------------------------------------------------------------------
# Peers
# ---------------------------------------------------------------------------

def _row_to_peer(row: sqlite3.Row) -> Peer:
    data = json.loads(row["data"])
    data["id"] = row["id"]
    return Peer(**data)


def list_peers() -> List[Peer]:
    conn = get_conn()
    rows = conn.execute("SELECT id, data FROM peers ORDER BY id").fetchall()
    conn.close()
    return [_row_to_peer(r) for r in rows]


def get_peer(peer_id: int) -> Optional[Peer]:
    conn = get_conn()
    row = conn.execute("SELECT id, data FROM peers WHERE id = ?", (peer_id,)).fetchone()
    conn.close()
    return _row_to_peer(row) if row else None


def create_peer(peer: Peer) -> Peer:
    conn = get_conn()
    data = peer.model_dump(exclude={"id"})
    cur = conn.execute("INSERT INTO peers (data) VALUES (?)", (json.dumps(data),))
    conn.commit()
    peer_id = cur.lastrowid
    conn.close()
    peer.id = peer_id
    return peer


def update_peer(peer_id: int, peer: Peer) -> Optional[Peer]:
    conn = get_conn()
    data = peer.model_dump(exclude={"id"})
    cur = conn.execute("UPDATE peers SET data = ? WHERE id = ?", (json.dumps(data), peer_id))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    if not changed:
        return None
    peer.id = peer_id
    return peer


def delete_peer(peer_id: int) -> bool:
    conn = get_conn()
    cur = conn.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    return bool(changed)


# ---------------------------------------------------------------------------
# DEA identity (Identity/Realm) -- single row, id fixed to 1
# ---------------------------------------------------------------------------

def get_identity() -> Optional[DeaIdentity]:
    conn = get_conn()
    row = conn.execute("SELECT data FROM identity WHERE id = 1").fetchone()
    conn.close()
    return DeaIdentity(**json.loads(row["data"])) if row else None


def set_identity(identity: DeaIdentity) -> DeaIdentity:
    conn = get_conn()
    data = json.dumps(identity.model_dump())
    conn.execute(
        "INSERT INTO identity (id, data) VALUES (1, ?) "
        "ON CONFLICT(id) DO UPDATE SET data = excluded.data",
        (data,),
    )
    conn.commit()
    conn.close()
    return identity
