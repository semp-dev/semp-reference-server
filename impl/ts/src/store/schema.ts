/**
 * SQLite schema loader. Reads shared/schema/0001_init.sql so the TS
 * impl shares one source of truth with the Go impl.
 *
 * @module
 */

import { readFileSync } from "node:fs";

import type Database from "better-sqlite3";

const SCHEMA_REL_URL = new URL(
  "../../../../shared/schema/0001_init.sql",
  import.meta.url,
);

/** Apply pragmas, run the schema DDL, and record migration 1. */
export function applySchema(db: Database.Database): void {
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.pragma("busy_timeout = 5000");

  const sql = readFileSync(SCHEMA_REL_URL, "utf8");
  db.exec(sql);

  // Tracking table for applied migrations. The Go impl creates this
  // alongside the first apply; mirror that here.
  db.exec(
    `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT)`,
  );
  const has = db
    .prepare<[number], { version: number }>(
      `SELECT version FROM schema_migrations WHERE version = ?`,
    )
    .get(1);
  if (has === undefined) {
    db.prepare(
      `INSERT INTO schema_migrations (version, applied_at) VALUES (1, datetime('now'))`,
    ).run();
  }

  // Defensive ALTER for databases pre-dating the device_public_key
  // column. The Go impl swallows the duplicate-column error; mirror
  // that here.
  try {
    db.exec(
      `ALTER TABLE device_certificates ADD COLUMN device_public_key TEXT NOT NULL DEFAULT ''`,
    );
  } catch (err) {
    if (!isDuplicateColumnError(err)) {
      throw err;
    }
  }
}

function isDuplicateColumnError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.includes("duplicate column name") || msg.includes("already exists");
}
