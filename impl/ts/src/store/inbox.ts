/**
 * SQLite-backed inbox with crash-recovery + a 24-hour payload-hash
 * dedup window. Wraps an in-memory delivery.Inbox so the runtime
 * pipeline reads from RAM while persistent state lives in SQLite.
 *
 * Mirrors impl/go/internal/store/inbox.go.
 *
 * @module
 */

import { createHash } from "node:crypto";

import type Database from "better-sqlite3";

import { Inbox as MemInbox } from "@sempdev/semp/delivery";

const DEDUP_WINDOW_MS = 24 * 3600 * 1000;

export class SQLiteInbox {
  private readonly db: Database.Database;
  private readonly mem: MemInbox;

  constructor(db: Database.Database) {
    this.db = db;
    this.mem = new MemInbox();
  }

  /** The in-memory mirror passed to the runtime pipeline. */
  memInbox(): MemInbox {
    return this.mem;
  }

  /**
   * Persist `payload` for `address` and append it to the in-memory
   * queue. Duplicate payloads (by SHA-256) within the 24h dedup
   * window are silently dropped.
   */
  store(address: string, payload: Uint8Array): void {
    const hashHex = createHash("sha256").update(payload).digest("hex");
    if (this.hasEnvelope(address, hashHex)) {
      return;
    }
    this.db
      .prepare(`INSERT INTO inbox (address, payload) VALUES (?, ?)`)
      .run(address, Buffer.from(payload));
    this.mem.store(address, payload);
    this.db
      .prepare(
        `INSERT OR IGNORE INTO delivered_ids (address, envelope_id, delivered_at) VALUES (?, ?, ?)`,
      )
      .run(address, hashHex, isoNow());
  }

  /**
   * Remove and return every queued envelope for `address`. The
   * in-memory queue is drained too.
   */
  drain(address: string): Uint8Array[] {
    const out = this.mem.drain(address);
    this.db.prepare(`DELETE FROM inbox WHERE address = ?`).run(address);
    return out;
  }

  /** Rehydrate the in-memory queue from SQLite. */
  loadPending(): void {
    const rows = this.db
      .prepare<
        [],
        { address: string; payload: Buffer }
      >(`SELECT address, payload FROM inbox ORDER BY id`)
      .all();
    for (const r of rows) {
      this.mem.store(r.address, r.payload);
    }
  }

  /**
   * True when an envelope with `envelopeId` (payload hash) was
   * already delivered to `address` within the dedup window.
   */
  hasEnvelope(address: string, envelopeId: string): boolean {
    const cutoff = new Date(Date.now() - DEDUP_WINDOW_MS)
      .toISOString()
      .replace(/\.\d{3}Z$/, "Z");
    const row = this.db
      .prepare<
        [string, string, string],
        { c: number }
      >(
        `SELECT COUNT(*) AS c FROM delivered_ids WHERE address = ? AND envelope_id = ? AND delivered_at > ?`,
      )
      .get(address, envelopeId, cutoff);
    return row !== undefined && row.c > 0;
  }

  /** Remove dedup entries older than the 24h window. */
  cleanupDeliveredIds(): void {
    const cutoff = new Date(Date.now() - DEDUP_WINDOW_MS)
      .toISOString()
      .replace(/\.\d{3}Z$/, "Z");
    this.db
      .prepare(`DELETE FROM delivered_ids WHERE delivered_at <= ?`)
      .run(cutoff);
  }
}

function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
