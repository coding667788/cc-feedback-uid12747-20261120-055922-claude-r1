"""SQLite persistence layer.

A single database file is shared by every process; writers serialise through
``BEGIN IMMEDIATE`` plus a busy timeout, so concurrent acquisition segments
from independent processes are safe.  All state needed for crash recovery
(commits in ``alerts_pending`` / ``committed`` state) lives here.
"""

from __future__ import annotations

import contextlib
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS objects(
  oid     TEXT PRIMARY KEY,
  sha256  TEXT NOT NULL,
  size    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS keys(
  key_id  TEXT PRIMARY KEY,
  secret  TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices(
  device_id             TEXT PRIMARY KEY,
  generation            INTEGER NOT NULL,
  current_baseline_cas  TEXT NOT NULL,
  seq                   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS baselines(
  cas          TEXT PRIMARY KEY,
  device_id    TEXT NOT NULL,
  version      INTEGER NOT NULL,
  entries_json TEXT NOT NULL,
  signature    TEXT NOT NULL,
  key_id       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS batches(
  device_id     TEXT NOT NULL,
  batch_id      TEXT NOT NULL,
  generation    INTEGER NOT NULL,
  baseline_cas  TEXT NOT NULL,
  segment_count INTEGER NOT NULL,
  state         TEXT NOT NULL DEFAULT 'open',
  PRIMARY KEY(device_id, batch_id)
);
CREATE TABLE IF NOT EXISTS segments(
  device_id    TEXT NOT NULL,
  batch_id     TEXT NOT NULL,
  seg_index    INTEGER NOT NULL,
  generation   INTEGER NOT NULL,
  baseline_cas TEXT NOT NULL,
  obs_json     TEXT NOT NULL,
  PRIMARY KEY(device_id, batch_id, seg_index)
);
CREATE TABLE IF NOT EXISTS prechecks(
  precheck_id  TEXT PRIMARY KEY,
  device_id    TEXT NOT NULL,
  batch_id     TEXT NOT NULL,
  generation   INTEGER NOT NULL,
  baseline_cas TEXT NOT NULL,
  kind         TEXT NOT NULL,
  release_json TEXT,
  diff_json    TEXT NOT NULL,
  state        TEXT NOT NULL DEFAULT 'staged'
);
CREATE TABLE IF NOT EXISTS commits(
  commit_id   TEXT PRIMARY KEY,
  precheck_id TEXT UNIQUE,
  device_id   TEXT NOT NULL,
  batch_id    TEXT NOT NULL,
  generation  INTEGER NOT NULL,
  base_cas    TEXT NOT NULL,
  new_cas     TEXT NOT NULL,
  version     INTEGER NOT NULL,
  kind        TEXT NOT NULL,
  status      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts(
  commit_id   TEXT NOT NULL,
  version     INTEGER NOT NULL,
  kind        TEXT NOT NULL,
  path        TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  PRIMARY KEY(commit_id, path, kind)
);
CREATE TABLE IF NOT EXISTS receipts(
  commit_id    TEXT PRIMARY KEY,
  receipt_json TEXT NOT NULL
);
"""


class Store:
    """Thin connection wrapper; all domain logic lives in :mod:`engine`."""

    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path, timeout=30.0, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)

    def close(self):
        self.conn.close()

    @contextlib.contextmanager
    def txn(self):
        """Exclusive write transaction (serialises concurrent processes)."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def q(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def q1(self, sql, args=()):
        return self.conn.execute(sql, args).fetchone()
