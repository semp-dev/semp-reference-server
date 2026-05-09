/**
 * SQLite-backed BlockListLookup. Mirrors impl/go/internal/store/blocklist.go.
 *
 * @module
 */

import { randomBytes } from "node:crypto";

import type Database from "better-sqlite3";

import type {
  BlockEntry,
  BlockList,
  BlockListLookup,
  BlocklistEntity,
  BlocklistEntityType,
  BlocklistScope,
} from "@sempdev/semp/delivery";

export class SQLiteBlockList implements BlockListLookup {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  async lookup(recipient: string): Promise<BlockList | null> {
    const rows = this.db
      .prepare<
        [string],
        BlockRow
      >(
        `SELECT id, entity_type, entity_value, acknowledgment, reason, scope, created_at, expires_at
           FROM block_entries WHERE user_id = ?`,
      )
      .all(recipient);
    const entries: BlockEntry[] = rows.map((r) => rowToEntry(r));
    return {
      user_id: recipient,
      list_version: 1,
      entries,
    };
  }

  /** Insert a block entry. Returns its id (generated when omitted). */
  addEntry(userId: string, entry: BlockEntry): string {
    const id = entry.id !== "" ? entry.id : randomBytes(16).toString("hex");
    const now = isoNow();
    const expires = entry.expires_at !== undefined && entry.expires_at !== ""
      ? entry.expires_at
      : null;
    const entityValue = entityValueOf(entry.entity);
    this.db
      .prepare(
        `INSERT INTO block_entries (id, user_id, entity_type, entity_value, acknowledgment, reason, scope, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        userId,
        entry.entity.type,
        entityValue,
        entry.acknowledgment,
        entry.reason ?? null,
        entry.scope,
        now,
        expires,
      );
    return id;
  }

  /** Remove a block entry by id. */
  removeEntry(entryId: string): void {
    this.db.prepare(`DELETE FROM block_entries WHERE id = ?`).run(entryId);
  }

  /** Snapshot the entries for a user. */
  async listEntries(userId: string): Promise<BlockEntry[]> {
    const list = await this.lookup(userId);
    return list?.entries ?? [];
  }
}

interface BlockRow {
  id: string;
  entity_type: string;
  entity_value: string;
  acknowledgment: string;
  reason: string | null;
  scope: string;
  created_at: string;
  expires_at: string | null;
}

function rowToEntry(r: BlockRow): BlockEntry {
  const entity: BlocklistEntity = { type: r.entity_type as BlocklistEntityType };
  switch (entity.type) {
    case "user":
      entity.address = r.entity_value;
      break;
    case "domain":
      entity.domain = r.entity_value;
      break;
    case "server":
      entity.hostname = r.entity_value;
      break;
  }
  const entry: BlockEntry = {
    id: r.id,
    entity,
    acknowledgment: (r.acknowledgment === "delivered" ||
    r.acknowledgment === "rejected" ||
    r.acknowledgment === "silent"
      ? r.acknowledgment
      : "rejected") as BlockEntry["acknowledgment"],
    scope: (r.scope === "all" || r.scope === "direct" || r.scope === "group"
      ? r.scope
      : "all") as BlocklistScope,
    created_at: r.created_at,
    created_by_device_id: "",
  };
  if (r.reason !== null) {
    entry.reason = r.reason;
  }
  if (r.expires_at !== null) {
    entry.expires_at = r.expires_at;
  }
  return entry;
}

function entityValueOf(entity: BlocklistEntity): string {
  switch (entity.type) {
    case "user":
      return entity.address ?? "";
    case "domain":
      return entity.domain ?? "";
    case "server":
      return entity.hostname ?? "";
  }
}

function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
