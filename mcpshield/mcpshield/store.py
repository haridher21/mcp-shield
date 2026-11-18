"""SQLite persistence: approved definitions, quarantine, decisions, manifests, events."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS approved_tools (
    server_id TEXT NOT NULL,
    name TEXT NOT NULL,
    hash TEXT NOT NULL,
    definition TEXT NOT NULL,
    local_output_schema TEXT,
    approved_at TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    PRIMARY KEY (server_id, name)
);
CREATE TABLE IF NOT EXISTS quarantine (
    server_id TEXT NOT NULL,
    name TEXT NOT NULL,
    hash TEXT NOT NULL,
    definition TEXT NOT NULL,
    reason TEXT NOT NULL,          -- 'added' | 'modified'
    status TEXT NOT NULL,          -- 'pending' | 'rejected'
    first_seen TEXT NOT NULL,
    PRIMARY KEY (server_id, name)
);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    server_id TEXT NOT NULL,
    name TEXT NOT NULL,
    decision TEXT NOT NULL,        -- 'approve' | 'reject' | 'revoke'
    hash TEXT,
    actor TEXT NOT NULL,
    note TEXT
);
CREATE TABLE IF NOT EXISTS manifests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    server_id TEXT NOT NULL,
    hash TEXT NOT NULL,
    tools TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    server_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    tool TEXT,
    severity TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ApprovedTool:
    name: str
    hash: str
    definition: dict[str, Any]
    local_output_schema: dict[str, Any] | None
    approved_at: str
    approved_by: str


@dataclass
class QuarantinedTool:
    name: str
    hash: str
    definition: dict[str, Any]
    reason: str
    status: str
    first_seen: str


class Store:
    def __init__(self, path: str | Path = "mcpshield.db"):
        self.path = str(path)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def data_version(self) -> int:
        """Changes whenever *another* connection commits (e.g. a CLI approval while serving)."""
        return self.db.execute("PRAGMA data_version").fetchone()[0]

    # -- approved ---------------------------------------------------------
    def get_approved(self, server_id: str) -> dict[str, ApprovedTool]:
        rows = self.db.execute("SELECT * FROM approved_tools WHERE server_id=? ORDER BY name", (server_id,))
        return {
            r["name"]: ApprovedTool(
                r["name"],
                r["hash"],
                json.loads(r["definition"]),
                json.loads(r["local_output_schema"]) if r["local_output_schema"] else None,
                r["approved_at"],
                r["approved_by"],
            )
            for r in rows
        }

    def set_approved(
        self,
        server_id: str,
        name: str,
        tool_hash: str,
        definition: dict[str, Any],
        local_output_schema: dict[str, Any] | None,
        actor: str,
    ) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO approved_tools VALUES (?,?,?,?,?,?,?)",
            (
                server_id,
                name,
                tool_hash,
                json.dumps(definition),
                json.dumps(local_output_schema) if local_output_schema is not None else None,
                _now(),
                actor,
            ),
        )
        self.db.commit()

    def set_local_output_schema(self, server_id: str, name: str, schema: dict[str, Any] | None) -> bool:
        cur = self.db.execute(
            "UPDATE approved_tools SET local_output_schema=? WHERE server_id=? AND name=?",
            (json.dumps(schema) if schema is not None else None, server_id, name),
        )
        self.db.commit()
        return cur.rowcount > 0

    def delete_approved(self, server_id: str, name: str) -> bool:
        cur = self.db.execute("DELETE FROM approved_tools WHERE server_id=? AND name=?", (server_id, name))
        self.db.commit()
        return cur.rowcount > 0

    # -- quarantine -------------------------------------------------------
    def get_quarantined(self, server_id: str, name: str | None = None) -> dict[str, QuarantinedTool]:
        sql, args = "SELECT * FROM quarantine WHERE server_id=?", [server_id]
        if name is not None:
            sql += " AND name=?"
            args.append(name)
        rows = self.db.execute(sql + " ORDER BY name", args)
        return {
            r["name"]: QuarantinedTool(
                r["name"], r["hash"], json.loads(r["definition"]), r["reason"], r["status"], r["first_seen"]
            )
            for r in rows
        }

    def quarantine(self, server_id: str, name: str, tool_hash: str, definition: dict[str, Any], reason: str) -> bool:
        """Record a pending definition. Returns False if this exact hash is already recorded."""
        existing = self.get_quarantined(server_id, name).get(name)
        if existing and existing.hash == tool_hash:
            return False
        self.db.execute(
            "INSERT OR REPLACE INTO quarantine VALUES (?,?,?,?,?,?,?)",
            (server_id, name, tool_hash, json.dumps(definition), reason, "pending", _now()),
        )
        self.db.commit()
        return True

    def set_quarantine_status(self, server_id: str, name: str, status: str) -> None:
        self.db.execute("UPDATE quarantine SET status=? WHERE server_id=? AND name=?", (status, server_id, name))
        self.db.commit()

    def release(self, server_id: str, name: str) -> None:
        self.db.execute("DELETE FROM quarantine WHERE server_id=? AND name=?", (server_id, name))
        self.db.commit()

    # -- log tables -------------------------------------------------------
    def record_decision(self, server_id: str, name: str, decision: str, tool_hash: str | None, actor: str, note: str = "") -> None:
        self.db.execute(
            "INSERT INTO decisions (ts, server_id, name, decision, hash, actor, note) VALUES (?,?,?,?,?,?,?)",
            (_now(), server_id, name, decision, tool_hash, actor, note),
        )
        self.db.commit()

    def decisions(self, server_id: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM decisions WHERE server_id=? ORDER BY id DESC LIMIT ?", (server_id, limit)
        )
        return [dict(r) for r in rows]

    def record_manifest(self, server_id: str, manifest_hash: str, tools: list[dict[str, Any]]) -> bool:
        """Snapshot the catalog if it differs from the last snapshot. Returns True if new."""
        last = self.db.execute(
            "SELECT hash FROM manifests WHERE server_id=? ORDER BY id DESC LIMIT 1", (server_id,)
        ).fetchone()
        if last and last["hash"] == manifest_hash:
            return False
        self.db.execute(
            "INSERT INTO manifests (ts, server_id, hash, tools) VALUES (?,?,?,?)",
            (_now(), server_id, manifest_hash, json.dumps(tools)),
        )
        self.db.commit()
        return True

    def log_event(self, server_id: str, kind: str, severity: str, detail: dict[str, Any] | str, tool: str | None = None) -> None:
        if not isinstance(detail, str):
            detail = json.dumps(detail, ensure_ascii=False)
        self.db.execute(
            "INSERT INTO events (ts, server_id, kind, tool, severity, detail) VALUES (?,?,?,?,?,?)",
            (_now(), server_id, kind, tool, severity, detail),
        )
        self.db.commit()

    def events(self, server_id: str, limit: int = 50, kind: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM events WHERE server_id=?", [server_id]
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        rows = self.db.execute(sql + " ORDER BY id DESC LIMIT ?", (*args, limit))
        return [dict(r) for r in rows]
