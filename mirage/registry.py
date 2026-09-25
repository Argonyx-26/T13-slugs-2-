"""SQLite registry: hosts, decoys, events, incidents.

Decoy values are stored only as HMAC fingerprints, so reading the registry does not
reveal the credentials themselves (flaw #31).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    name TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    owner TEXT NOT NULL,
    team TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'online',
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    lookup_fp TEXT NOT NULL UNIQUE,
    display TEXT NOT NULL,
    identity TEXT NOT NULL DEFAULT '',
    meta TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS placements (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL REFERENCES tokens(id),
    host TEXT NOT NULL REFERENCES hosts(name),
    rel_path TEXT NOT NULL,
    abs_path TEXT NOT NULL,
    norm_path TEXT NOT NULL,
    template TEXT NOT NULL,
    label TEXT NOT NULL,
    scope TEXT NOT NULL,
    technique TEXT NOT NULL,
    mode TEXT NOT NULL,
    created_file INTEGER NOT NULL,
    colocated TEXT NOT NULL DEFAULT '[]',
    meta TEXT NOT NULL DEFAULT '{}',
    deployed_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'deployed'
);
CREATE INDEX IF NOT EXISTS placements_norm_path ON placements(norm_path);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    sensor TEXT NOT NULL,
    kind TEXT NOT NULL,
    token_id TEXT,
    placement_id TEXT,
    incident_id TEXT,
    src_ip TEXT,
    user_agent TEXT,
    classification TEXT,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_placement ON events(placement_id, kind, ts);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    placement_id TEXT NOT NULL,
    host TEXT NOT NULL,
    bucket TEXT NOT NULL,
    opened_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    stage TEXT NOT NULL,
    severity TEXT NOT NULL,
    classification TEXT NOT NULL,
    label TEXT NOT NULL,
    attribution TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    breaker_tripped INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '{}',
    tasks TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS incidents_lookup ON incidents(placement_id, bucket, status);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    host TEXT,
    incident_id TEXT,
    actor TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
"""

JSON_COLUMNS = {"colocated", "meta", "detail", "summary", "tasks"}
INCIDENT_MUTABLE = (
    "updated_at", "stage", "severity", "classification", "label", "attribution",
    "action", "status", "event_count", "breaker_tripped", "summary", "tasks",
)


def _decode(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    out = dict(row)
    for col in JSON_COLUMNS & out.keys():
        out[col] = json.loads(out[col])
    return out


def _encode(value):
    return json.dumps(value) if isinstance(value, (dict, list)) else value


class Registry:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=10)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- low level -----------------------------------------------------------------
    def _rows(self, sql: str, args=()) -> list[dict]:
        with self._lock:
            return [_decode(r) for r in self._db.execute(sql, args).fetchall()]

    def _row(self, sql: str, args=()) -> dict | None:
        with self._lock:
            return _decode(self._db.execute(sql, args).fetchone())

    def _exec(self, sql: str, args=()) -> int:
        with self._lock:
            return self._db.execute(sql, [_encode(a) for a in args]).lastrowid

    def _insert(self, table: str, fields: dict) -> int:
        cols = ", ".join(fields)
        marks = ", ".join("?" for _ in fields)
        return self._exec(f"INSERT INTO {table} ({cols}) VALUES ({marks})", list(fields.values()))

    # -- meta and counters -------------------------------------------------------
    def get_meta(self, key: str, default=None):
        row = self._row("SELECT value FROM meta WHERE key = ?", (key,))
        return default if row is None else json.loads(row["value"])

    def set_meta(self, key: str, value) -> None:
        self._exec("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, json.dumps(value)))

    def del_meta(self, key: str) -> None:
        self._exec("DELETE FROM meta WHERE key = ?", (key,))

    def bump(self, counter: str, n: int = 1) -> None:
        with self._lock:
            self.set_meta(f"stat:{counter}", self.get_meta(f"stat:{counter}", 0) + n)

    def stats(self) -> dict:
        counters = {r["key"][5:]: json.loads(r["value"]) for r in self._rows("SELECT key, value FROM meta WHERE key LIKE 'stat:%'")}
        counters["events"] = self._row("SELECT COUNT(*) AS n FROM events")["n"]
        counters["decoys"] = self._row("SELECT COUNT(*) AS n FROM placements WHERE status = 'deployed'")["n"]
        counters["open_incidents"] = self._row("SELECT COUNT(*) AS n FROM incidents WHERE status != 'closed'")["n"]
        return counters

    # -- hosts ---------------------------------------------------------------------
    def upsert_host(self, name: str, role: str, owner: str, team: str = "", os_name: str = "") -> None:
        self._exec(
            "INSERT INTO hosts (name, role, owner, team, os, status, updated_at) VALUES (?, ?, ?, ?, ?, 'online', ?) "
            "ON CONFLICT(name) DO UPDATE SET role = excluded.role, owner = excluded.owner, team = excluded.team, os = excluded.os",
            (name, role, owner, team, os_name, time.time()),
        )

    def get_host(self, name: str) -> dict | None:
        return self._row("SELECT * FROM hosts WHERE name = ?", (name,))

    def list_hosts(self) -> list[dict]:
        order = "CASE role WHEN 'workstation' THEN 0 WHEN 'server' THEN 1 ELSE 2 END"
        return self._rows(f"SELECT * FROM hosts ORDER BY {order}, name")

    def set_host_status(self, name: str, status: str) -> None:
        self._exec("UPDATE hosts SET status = ?, updated_at = ? WHERE name = ?", (status, time.time(), name))

    # -- tokens --------------------------------------------------------------------
    def add_token(self, token_id: str, kind: str, lookup_fp: str, display: str, identity: str = "", meta: dict | None = None) -> None:
        self._insert("tokens", {
            "id": token_id, "kind": kind, "lookup_fp": lookup_fp, "display": display,
            "identity": identity, "meta": meta or {}, "created_at": time.time(),
        })

    def find_token(self, lookup_fp: str) -> dict | None:
        return self._row("SELECT * FROM tokens WHERE lookup_fp = ? AND status = 'active'", (lookup_fp,))

    def get_token(self, token_id: str) -> dict | None:
        return self._row("SELECT * FROM tokens WHERE id = ?", (token_id,))

    def set_token_status(self, token_id: str, status: str) -> None:
        self._exec("UPDATE tokens SET status = ? WHERE id = ?", (status, token_id))

    # -- placements ----------------------------------------------------------------
    def add_placement(self, fields: dict) -> None:
        self._insert("placements", fields)

    def get_placement(self, placement_id: str) -> dict | None:
        return self._row("SELECT * FROM placements WHERE id = ?", (placement_id,))

    def placement_for_token(self, token_id: str) -> dict | None:
        return self._row("SELECT * FROM placements WHERE token_id = ? ORDER BY deployed_at DESC LIMIT 1", (token_id,))

    def find_placement_by_path(self, norm_path: str) -> dict | None:
        return self._row("SELECT * FROM placements WHERE norm_path = ? AND status = 'deployed'", (norm_path,))

    def find_placement(self, host: str, rel_path: str, template: str) -> dict | None:
        return self._row(
            "SELECT * FROM placements WHERE host = ? AND rel_path = ? AND template = ? AND status = 'deployed'",
            (host, rel_path, template),
        )

    def list_placements(self, status: str | None = "deployed") -> list[dict]:
        if status is None:
            return self._rows("SELECT * FROM placements ORDER BY host, rel_path")
        return self._rows("SELECT * FROM placements WHERE status = ? ORDER BY host, rel_path", (status,))

    def set_placement_status(self, placement_id: str, status: str) -> None:
        self._exec("UPDATE placements SET status = ? WHERE id = ?", (status, placement_id))

    # -- events --------------------------------------------------------------------
    def add_event(self, ts: float, sensor: str, kind: str, *, token_id=None, placement_id=None, src_ip=None,
                  user_agent=None, classification=None, detail: dict | None = None) -> int:
        return self._insert("events", {
            "ts": ts, "sensor": sensor, "kind": kind, "token_id": token_id, "placement_id": placement_id,
            "src_ip": src_ip, "user_agent": user_agent, "classification": classification, "detail": detail or {},
        })

    def set_event_incident(self, event_id: int, incident_id: str) -> None:
        self._exec("UPDATE events SET incident_id = ? WHERE id = ?", (incident_id, event_id))

    def suspicious_reads(self, placement_id: str, since: float) -> list[dict]:
        return self._rows(
            "SELECT * FROM events WHERE placement_id = ? AND kind = 'file_read' AND classification LIKE 'suspicious%' "
            "AND ts >= ? ORDER BY ts DESC",
            (placement_id, since),
        )

    # -- incidents -----------------------------------------------------------------
    def insert_incident(self, inc: dict) -> None:
        self._insert("incidents", {k: inc[k] for k in (
            "id", "placement_id", "host", "bucket", "opened_at", *INCIDENT_MUTABLE)})

    def update_incident(self, inc: dict) -> None:
        sets = ", ".join(f"{c} = ?" for c in INCIDENT_MUTABLE)
        self._exec(f"UPDATE incidents SET {sets} WHERE id = ?", [inc[c] for c in INCIDENT_MUTABLE] + [inc["id"]])

    def get_incident(self, incident_id: str) -> dict | None:
        return self._row("SELECT * FROM incidents WHERE id = ?", (incident_id,))

    def find_open_incident(self, placement_id: str, bucket: str, since: float) -> dict | None:
        return self._row(
            "SELECT * FROM incidents WHERE placement_id = ? AND bucket = ? AND status != 'closed' AND updated_at >= ? "
            "ORDER BY updated_at DESC LIMIT 1",
            (placement_id, bucket, since),
        )

    def open_incidents_for_host(self, host: str) -> list[dict]:
        return self._rows("SELECT * FROM incidents WHERE host = ? AND status != 'closed'", (host,))

    def list_incidents(self, limit: int = 50) -> list[dict]:
        return self._rows("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,))

    # -- response actions ----------------------------------------------------------
    def add_action(self, kind: str, *, host=None, incident_id=None, actor: str, detail: dict | None = None) -> None:
        self._insert("actions", {
            "ts": time.time(), "kind": kind, "host": host, "incident_id": incident_id,
            "actor": actor, "detail": detail or {},
        })

    def count_actions(self, kind: str, since: float) -> int:
        return self._row("SELECT COUNT(*) AS n FROM actions WHERE kind = ? AND ts >= ?", (kind, since))["n"]

    def list_actions(self, limit: int = 50) -> list[dict]:
        return self._rows("SELECT * FROM actions ORDER BY ts DESC LIMIT ?", (limit,))
