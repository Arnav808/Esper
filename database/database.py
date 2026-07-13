"""SQLite database layer for Esper — stores scan history, findings, and assets.

Provides a lightweight persistence layer that requires zero external services.
Uses WAL mode for concurrent read/write safety.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

_DB_PATH = os.path.join(os.getcwd(), "esper.db")

# ------------------------------------------------------------------ #
# Connection helpers
# ------------------------------------------------------------------ #


def _connect(db_path: str | None = None) -> sqlite3.Connection:
    """Return a connection to the Esper database."""
    path = db_path or _DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str | None = None) -> None:
    """Create tables if they do not exist."""
    conn = _connect(db_path)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url  TEXT    NOT NULL,
            security_score INTEGER NOT NULL DEFAULT 0,
            confidence  REAL    NOT NULL DEFAULT 0.0,
            report_path TEXT,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            discovery_json  TEXT,
            attack_graph_json   TEXT,
            mitigation_graph_json TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_scans_target
            ON scans(target_url);
        CREATE INDEX IF NOT EXISTS idx_scans_created
            ON scans(created_at);

        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            title       TEXT    NOT NULL,
            severity    TEXT    NOT NULL DEFAULT 'Unknown',
            category    TEXT    NOT NULL DEFAULT '',
            cvss_score  REAL,
            cve_id      TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan
            ON findings(scan_id);

        CREATE TABLE IF NOT EXISTS assets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            asset_type  TEXT    NOT NULL,
            name        TEXT    NOT NULL,
            details_json TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_assets_scan
            ON assets(scan_id);
        """
    )
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ #
# Write operations
# ------------------------------------------------------------------ #


def save_scan(
    target_url: str,
    security_score: int,
    confidence: float,
    report_path: str | None,
    findings: list[dict[str, Any]],
    discovery: dict[str, Any],
    attack_graph: Any = None,
    mitigation_graph: Any = None,
    assets: list[dict[str, Any]] | None = None,
    db_path: str | None = None,
) -> int:
    """Persist a completed scan and return the scan ID."""
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()

        # Serialise graphs for storage
        ag_json = None
        if attack_graph is not None:
            ag_json = json.dumps(
                {"nodes": list(attack_graph.nodes(data=True)),
                 "edges": list(attack_graph.edges(data=True))}
            )

        mg_json = None
        if mitigation_graph is not None:
            mg_json = json.dumps(
                {"nodes": list(mitigation_graph.nodes(data=True)),
                 "edges": list(mitigation_graph.edges(data=True))}
            )

        cur = conn.execute(
            """
            INSERT INTO scans
                (target_url, security_score, confidence, report_path,
                 created_at, discovery_json, attack_graph_json, mitigation_graph_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (target_url, security_score, confidence, report_path,
             now, json.dumps(discovery), ag_json, mg_json),
        )
        scan_id = cur.lastrowid

        # Save findings
        for f in findings:
            conn.execute(
                """
                INSERT INTO findings (scan_id, title, severity, category, cvss_score, cve_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, f.get("title", ""), f.get("severity", "Unknown"),
                 f.get("category", ""), f.get("cvss_score"), f.get("cve_id")),
            )

        # Save assets
        for a in (assets or []):
            conn.execute(
                """
                INSERT INTO assets (scan_id, asset_type, name, details_json)
                VALUES (?, ?, ?, ?)
                """,
                (scan_id, a.get("type", ""), a.get("name", ""),
                 json.dumps(a.get("details", {}))),
            )

        conn.commit()
        return scan_id
    finally:
        conn.close()


# ------------------------------------------------------------------ #
# Read operations
# ------------------------------------------------------------------ #


def get_scan(scan_id: int, db_path: str | None = None) -> dict[str, Any] | None:
    """Retrieve a single scan by ID."""
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return None
        return _row_to_dict(row)
    finally:
        conn.close()


def get_scan_findings(scan_id: int, db_path: str | None = None) -> list[dict[str, Any]]:
    """Retrieve all findings for a scan."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_scan_assets(scan_id: int, db_path: str | None = None) -> list[dict[str, Any]]:
    """Retrieve all assets for a scan."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM assets WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_history(
    target_url: str | None = None,
    limit: int = 20,
    offset: int = 0,
    db_path: str | None = None,
) -> list[dict[str, Any]]:
    """List scans, optionally filtered by target URL."""
    conn = _connect(db_path)
    try:
        if target_url:
            rows = conn.execute(
                "SELECT * FROM scans WHERE target_url = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (target_url, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def get_previous_scan(
    target_url: str,
    before_scan_id: int | None = None,
    db_path: str | None = None,
) -> dict[str, Any] | None:
    """Get the most recent previous scan for a target (for comparison)."""
    conn = _connect(db_path)
    try:
        if before_scan_id:
            row = conn.execute(
                """SELECT * FROM scans
                   WHERE target_url = ? AND id < ?
                   ORDER BY created_at DESC LIMIT 1""",
                (target_url, before_scan_id),
            ).fetchone()
        else:
            row = conn.execute(
                """SELECT * FROM scans
                   WHERE target_url = ?
                   ORDER BY created_at DESC LIMIT 1""",
                (target_url,),
            ).fetchone()
        if row is None:
            return None
        result = _row_to_dict(row)
        result["findings"] = get_scan_findings(row["id"], db_path)
        return result
    finally:
        conn.close()


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert a sqlite3.Row to a plain dict, parsing JSON columns."""
    d = dict(row)
    for key in ("discovery_json", "attack_graph_json", "mitigation_graph_json"):
        if d.get(key):
            try:
                d[key.replace("_json", "")] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
            del d[key]
    return d
