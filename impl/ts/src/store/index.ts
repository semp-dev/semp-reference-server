/**
 * Store package surface. Re-exports the SQLite-backed implementations
 * of the @sempdev/semp keys.KeyStore + delivery.BlockListLookup
 * interfaces, plus the durable inbox wrapper and the master-key
 * encryption envelope helpers.
 *
 * @module
 */

import BetterSqlite3 from "better-sqlite3";

import { applySchema } from "./schema.js";

export { SQLiteBlockList } from "./blocklist.js";
export {
  decryptPrivateKey,
  deriveKey,
  encryptPrivateKey,
  type EncryptedPrivate,
} from "./crypto.js";
export { SQLiteInbox } from "./inbox.js";
export {
  SQLiteKeyStore,
  computeFingerprint,
  type DomainEncRecord,
  type DomainKeyFetcher,
} from "./keys.js";
export { applySchema };

/** Open or create the SQLite database, apply pragmas + schema. */
export function initDB(path: string): BetterSqlite3.Database {
  const db = new BetterSqlite3(path);
  applySchema(db);
  return db;
}
