/**
 * SQLite-backed KeyStore. Mirrors impl/go/internal/store/sqlite.go.
 *
 * Implements the @sempdev/semp/keys KeyStore interface (synchronous
 * methods returning per-record JSON objects). Adds server-only
 * helpers for storing local domain key pairs, computing fingerprints,
 * and the auto-fetch path for peer domain signing keys.
 *
 * @module
 */

import { createHash } from "node:crypto";

import type Database from "better-sqlite3";

import type {
  DeviceCertificate,
  KeyStore,
  KeyStoreRecord,
  KeyType,
  Revocation,
} from "@sempdev/semp/keys";

import { decryptPrivateKey, encryptPrivateKey } from "./crypto.js";

/**
 * Returns a peer domain's published Ed25519 signing public key bytes,
 * or null when the lookup fails. Used by the auto-fetch path.
 */
export type DomainKeyFetcher = (domain: string) => Uint8Array | null;

/** Lookup-shaped record for the domain encryption key. */
export interface DomainEncRecord extends KeyStoreRecord {
  key_type: "domain";
}

/**
 * SQLite-backed key store. Public keys are stored as raw bytes;
 * private key material is encrypted at rest with AES-256-GCM keyed
 * by Argon2id over the master key when one is configured.
 */
export class SQLiteKeyStore implements KeyStore {
  private readonly db: Database.Database;
  private masterKey = "";
  private localDomain = "";
  private fetcher: DomainKeyFetcher | null = null;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Enable encrypted-at-rest private key storage. */
  setMasterKey(key: string): void {
    this.masterKey = key;
  }

  /** Wire the auto-fetch callback for domain signing keys on cache miss. */
  setDomainKeyFetcher(localDomain: string, fetcher: DomainKeyFetcher): void {
    this.localDomain = localDomain;
    this.fetcher = fetcher;
  }

  /** Underlying database handle. */
  database(): Database.Database {
    return this.db;
  }

  // ---------------- KeyStore interface ----------------

  lookupDomainKey(domain: string): KeyStoreRecord | null {
    const local = this.lookupDomainSigningRecord(domain);
    if (local !== null) {
      return local;
    }
    if (this.fetcher === null || domain === this.localDomain) {
      return null;
    }
    const pub = this.fetcher(domain);
    if (pub === null) {
      return null;
    }
    const fp = computeFingerprint(pub);
    const now = isoNow();
    const expires = isoNowPlusDays(365);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO domain_keys
           (domain, key_type, algorithm, public_key, key_id, created_at, expires_at)
           VALUES (?, 'signing', 'ed25519', ?, ?, ?, ?)`,
      )
      .run(domain, Buffer.from(pub), fp, now, expires);
    return {
      key_type: "domain",
      algorithm: "ed25519",
      public_key: base64Encode(pub),
      key_id: fp,
      created: now,
      expires,
    };
  }

  lookupUserKeys(address: string, keyTypes?: KeyType[]): KeyStoreRecord[] {
    const params: (string | number | Buffer)[] = [address];
    let sql =
      `SELECT key_type, algorithm, public_key, key_id, created_at, expires_at,
              revoked_at, revocation_reason, replacement_key_id
         FROM user_keys WHERE address = ?`;
    if (keyTypes !== undefined && keyTypes.length > 0) {
      const placeholders = keyTypes.map(() => "?").join(",");
      sql += ` AND key_type IN (${placeholders})`;
      for (const t of keyTypes) {
        params.push(t);
      }
    }
    sql += ` AND revoked_at IS NULL`;
    const rows = this.db.prepare(sql).all(...params) as UserKeyRow[];
    return rows.map((row) => userRowToRecord(address, row));
  }

  putRecord(rec: KeyStoreRecord): void {
    if (rec.key_type === "domain") {
      return; // domain keys are managed separately
    }
    if (rec.address === undefined || rec.address === "") {
      throw new Error("keys: putRecord on user key requires address");
    }
    const pub = base64Decode(rec.public_key);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO user_keys
           (address, key_type, algorithm, public_key, key_id, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        rec.address,
        rec.key_type,
        rec.algorithm,
        Buffer.from(pub),
        rec.key_id,
        rec.created,
        rec.expires ?? "",
      );
  }

  putRevocation(keyId: string, rev: Revocation): void {
    const revokedAt = rev.revoked_at;
    const reason = rev.reason;
    const replacement = rev.replacement_key_id ?? "";
    this.db
      .prepare(
        `UPDATE user_keys SET revoked_at = ?, revocation_reason = ?, replacement_key_id = ? WHERE key_id = ?`,
      )
      .run(revokedAt, reason, replacement, keyId);
    this.db
      .prepare(
        `UPDATE domain_keys SET revoked_at = ?, revocation_reason = ?, replacement_key_id = ? WHERE key_id = ?`,
      )
      .run(revokedAt, reason, replacement, keyId);
  }

  lookupDeviceCertificate(deviceKeyId: string): DeviceCertificate | null {
    const row = this.db
      .prepare<
        [string],
        DeviceCertRow
      >(
        `SELECT user_id, device_id, device_public_key, issuing_device_key_id, scope_json, issued_at, expires_at, signature_json
           FROM device_certificates WHERE device_key_id = ?`,
      )
      .get(deviceKeyId);
    if (row === undefined) {
      return null;
    }
    const scope = JSON.parse(row.scope_json) as DeviceCertificate["scope"];
    const signature = JSON.parse(
      row.signature_json,
    ) as DeviceCertificate["signature"];
    const cert: DeviceCertificate = {
      type: "SEMP_DEVICE_CERTIFICATE",
      version: "1.0.0",
      device_id: row.device_id,
      device_public_key: row.device_public_key,
      account: row.user_id,
      issued_by: row.issuing_device_key_id,
      issued_at: row.issued_at,
      expires_at: row.expires_at ?? "",
      scope,
      signature,
    };
    return cert;
  }

  putDeviceCertificate(cert: DeviceCertificate): void {
    if (cert.device_public_key === "") {
      throw new Error("device_public_key is empty");
    }
    const pub = base64Decode(cert.device_public_key);
    const deviceKeyId = computeFingerprint(pub);
    const scopeJson = JSON.stringify(cert.scope);
    const sigJson = JSON.stringify(cert.signature);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO device_certificates
           (device_key_id, user_id, device_id, device_public_key, issuing_device_key_id, scope_json, issued_at, expires_at, signature_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        deviceKeyId,
        cert.account,
        cert.device_id,
        cert.device_public_key,
        cert.issued_by,
        scopeJson,
        cert.issued_at,
        cert.expires_at,
        sigJson,
      );
  }

  // ---------------- Domain helpers ----------------

  /** Cache a peer domain's signing public key. Returns the fingerprint. */
  putDomainKey(domain: string, pub: Uint8Array): string {
    const fp = computeFingerprint(pub);
    const now = isoNow();
    const expires = isoNowPlusDays(365);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO domain_keys
           (domain, key_type, algorithm, public_key, key_id, created_at, expires_at)
           VALUES (?, 'signing', 'ed25519', ?, ?, ?, ?)`,
      )
      .run(domain, Buffer.from(pub), fp, now, expires);
    return fp;
  }

  /** Return the domain encryption key record, or null when absent. */
  lookupDomainEncryptionKey(domain: string): DomainEncRecord | null {
    const row = this.db
      .prepare<
        [string],
        DomainKeyRow
      >(
        `SELECT algorithm, public_key, key_id, created_at, expires_at,
                revoked_at, revocation_reason, replacement_key_id
           FROM domain_keys WHERE domain = ? AND key_type = 'encryption'`,
      )
      .get(domain);
    if (row === undefined) {
      return null;
    }
    const rec: DomainEncRecord = {
      key_type: "domain",
      algorithm: row.algorithm,
      public_key: base64Encode(row.public_key),
      key_id: row.key_id,
      created: row.created_at,
      expires: row.expires_at,
    };
    if (row.revoked_at !== null && row.revoked_at !== undefined) {
      rec.revocation = {
        reason: (row.revocation_reason ?? "") as Revocation["reason"],
        revoked_at: row.revoked_at,
        ...(row.replacement_key_id !== null &&
        row.replacement_key_id !== undefined
          ? { replacement_key_id: row.replacement_key_id }
          : {}),
      };
    }
    return rec;
  }

  /** Store a domain key pair, encrypting the private key at rest if configured. */
  putDomainKeyPair(
    domain: string,
    keyType: "signing" | "encryption",
    algorithm: string,
    pub: Uint8Array,
    priv: Uint8Array,
  ): string {
    const fp = computeFingerprint(pub);
    const now = isoNow();
    const expires = isoNowPlusDays(2 * 365);
    const enc = this.encryptIfNeeded(priv, fp);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO domain_keys
           (domain, key_type, algorithm, public_key, private_key, key_salt, key_nonce, key_id, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        domain,
        keyType,
        algorithm,
        Buffer.from(pub),
        enc.ciphertext,
        enc.salt,
        enc.nonce,
        fp,
        now,
        expires,
      );
    return fp;
  }

  /** Load a domain private key. Returns null when no row exists. */
  loadDomainPrivateKey(
    domain: string,
    keyType: "signing" | "encryption",
  ): { priv: Uint8Array; keyId: string } | null {
    const row = this.db
      .prepare<
        [string, string],
        PrivKeyRow
      >(
        `SELECT private_key, key_salt, key_nonce, key_id FROM domain_keys WHERE domain = ? AND key_type = ?`,
      )
      .get(domain, keyType);
    if (row === undefined) {
      return null;
    }
    const priv = this.decryptIfNeeded(
      row.private_key,
      row.key_salt,
      row.key_nonce,
      row.key_id,
    );
    return { priv, keyId: row.key_id };
  }

  /** Load a domain public key. Returns null when no row exists. */
  loadDomainPublicKey(
    domain: string,
    keyType: "signing" | "encryption",
  ): { pub: Uint8Array; keyId: string } | null {
    const row = this.db
      .prepare<
        [string, string],
        PubKeyRow
      >(
        `SELECT public_key, key_id FROM domain_keys WHERE domain = ? AND key_type = ?`,
      )
      .get(domain, keyType);
    if (row === undefined) {
      return null;
    }
    return {
      pub: new Uint8Array(row.public_key),
      keyId: row.key_id,
    };
  }

  /** Both signing and encryption keys exist for `domain`. */
  hasDomainKeys(domain: string): boolean {
    const row = this.db
      .prepare<
        [string],
        { c: number }
      >(`SELECT COUNT(*) AS c FROM domain_keys WHERE domain = ?`)
      .get(domain);
    return row !== undefined && row.c >= 2;
  }

  // ---------------- Internals ----------------

  private lookupDomainSigningRecord(domain: string): KeyStoreRecord | null {
    const row = this.db
      .prepare<
        [string],
        DomainKeyRow
      >(
        `SELECT algorithm, public_key, key_id, created_at, expires_at,
                revoked_at, revocation_reason, replacement_key_id
           FROM domain_keys WHERE domain = ? AND key_type = 'signing'`,
      )
      .get(domain);
    if (row === undefined) {
      return null;
    }
    const rec: KeyStoreRecord = {
      key_type: "domain",
      algorithm: row.algorithm,
      public_key: base64Encode(row.public_key),
      key_id: row.key_id,
      created: row.created_at,
      expires: row.expires_at,
    };
    if (row.revoked_at !== null && row.revoked_at !== undefined) {
      rec.revocation = {
        reason: (row.revocation_reason ?? "") as Revocation["reason"],
        revoked_at: row.revoked_at,
        ...(row.replacement_key_id !== null &&
        row.replacement_key_id !== undefined
          ? { replacement_key_id: row.replacement_key_id }
          : {}),
      };
    }
    return rec;
  }

  private encryptIfNeeded(
    priv: Uint8Array,
    keyId: string,
  ): { ciphertext: Buffer | Uint8Array; salt: Buffer | null; nonce: Buffer | null } {
    if (this.masterKey === "" || priv.length === 0) {
      return { ciphertext: Buffer.from(priv), salt: null, nonce: null };
    }
    const result = encryptPrivateKey(
      this.masterKey,
      priv,
      new TextEncoder().encode(keyId),
    );
    return {
      ciphertext: result.ciphertext,
      salt: result.salt,
      nonce: result.nonce,
    };
  }

  private decryptIfNeeded(
    data: Buffer,
    salt: Buffer | null,
    nonce: Buffer | null,
    keyId: string,
  ): Uint8Array {
    if (salt === null || nonce === null || this.masterKey === "") {
      return new Uint8Array(data);
    }
    return decryptPrivateKey(
      this.masterKey,
      data,
      salt,
      nonce,
      new TextEncoder().encode(keyId),
    );
  }
}

/** Lowercase-hex SHA-256 fingerprint of a public key. */
export function computeFingerprint(pub: Uint8Array): string {
  return createHash("sha256").update(pub).digest("hex");
}

interface DomainKeyRow {
  algorithm: string;
  public_key: Buffer;
  key_id: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  replacement_key_id: string | null;
}

interface UserKeyRow {
  key_type: string;
  algorithm: string;
  public_key: Buffer;
  key_id: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  replacement_key_id: string | null;
}

interface DeviceCertRow {
  user_id: string;
  device_id: string;
  device_public_key: string;
  issuing_device_key_id: string;
  scope_json: string;
  issued_at: string;
  expires_at: string | null;
  signature_json: string;
}

interface PrivKeyRow {
  private_key: Buffer;
  key_salt: Buffer | null;
  key_nonce: Buffer | null;
  key_id: string;
}

interface PubKeyRow {
  public_key: Buffer;
  key_id: string;
}

function userRowToRecord(address: string, row: UserKeyRow): KeyStoreRecord {
  const rec: KeyStoreRecord = {
    address,
    key_type: row.key_type as KeyType,
    algorithm: row.algorithm,
    public_key: base64Encode(row.public_key),
    key_id: row.key_id,
    created: row.created_at,
    expires: row.expires_at,
  };
  if (row.revoked_at !== null && row.revoked_at !== undefined) {
    rec.revocation = {
      reason: (row.revocation_reason ?? "") as Revocation["reason"],
      revoked_at: row.revoked_at,
      ...(row.replacement_key_id !== null && row.replacement_key_id !== undefined
        ? { replacement_key_id: row.replacement_key_id }
        : {}),
    };
  }
  return rec;
}

function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function isoNowPlusDays(days: number): string {
  return new Date(Date.now() + days * 24 * 3600 * 1000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
}

function base64Encode(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

function base64Decode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}
