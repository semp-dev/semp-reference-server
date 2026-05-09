/**
 * TOML config loader. Parity with impl/go/internal/config/config.go.
 *
 * @module
 */

import { readFileSync } from "node:fs";
import { parse as parseToml } from "smol-toml";

import type {
  Config,
  CryptoConfig,
  DatabaseConfig,
  FederationConfig,
  LoggingConfig,
  PeerConfig,
  PolicyConfig,
  PoWConfig,
  TLSConfig,
  UserConfig,
} from "./types.js";

/** Read a TOML config file, apply defaults, and validate. */
export function loadConfig(path: string): Config {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(
      `config: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  let parsed: unknown;
  try {
    parsed = parseToml(raw);
  } catch (err) {
    throw new Error(
      `config: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const cfg = normalize(parsed);
  applyDefaults(cfg);
  validate(cfg);
  return cfg;
}

function normalize(parsed: unknown): Config {
  const o = isRecord(parsed) ? parsed : {};
  return {
    domain: stringOr(o.domain, ""),
    listen_addr: stringOr(o.listen_addr, ""),
    tls: normalizeTLS(o.tls),
    crypto: normalizeCrypto(o.crypto),
    database: normalizeDatabase(o.database),
    users: normalizeUsers(o.users),
    federation: normalizeFederation(o.federation),
    policy: normalizePolicy(o.policy),
    logging: normalizeLogging(o.logging),
  };
}

function normalizeTLS(v: unknown): TLSConfig {
  const o = isRecord(v) ? v : {};
  return {
    cert_file: stringOr(o.cert_file, ""),
    key_file: stringOr(o.key_file, ""),
    external_tls: boolOr(o.external_tls, false),
    quic_addr: stringOr(o.quic_addr, ""),
  };
}

function normalizeCrypto(v: unknown): CryptoConfig {
  const o = isRecord(v) ? v : {};
  return {
    suite: stringOr(o.suite, ""),
  };
}

function normalizeDatabase(v: unknown): DatabaseConfig {
  const o = isRecord(v) ? v : {};
  return {
    path: stringOr(o.path, ""),
    master_key: stringOr(o.master_key, ""),
  };
}

function normalizeUsers(v: unknown): UserConfig[] {
  if (!Array.isArray(v)) {
    return [];
  }
  return v.map((entry) => {
    const o = isRecord(entry) ? entry : {};
    return {
      address: stringOr(o.address, ""),
      password: stringOr(o.password, ""),
    };
  });
}

function normalizeFederation(v: unknown): FederationConfig {
  const o = isRecord(v) ? v : {};
  return {
    session_ttl: intOr(o.session_ttl, 0),
    retention: stringOr(o.retention, ""),
    peers: normalizePeers(o.peers),
  };
}

function normalizePeers(v: unknown): PeerConfig[] {
  if (!Array.isArray(v)) {
    return [];
  }
  return v.map((entry) => {
    const o = isRecord(entry) ? entry : {};
    return {
      domain: stringOr(o.domain, ""),
      endpoint: stringOr(o.endpoint, ""),
      domain_signing_key: stringOr(o.domain_signing_key, ""),
    };
  });
}

function normalizePolicy(v: unknown): PolicyConfig {
  const o = isRecord(v) ? v : {};
  return {
    session_ttl: intOr(o.session_ttl, 0),
    blocked_domains: stringArrayOr(o.blocked_domains),
    permissions: stringArrayOr(o.permissions),
    pow: normalizePoW(o.pow),
  };
}

function normalizePoW(v: unknown): PoWConfig {
  const o = isRecord(v) ? v : {};
  return {
    enabled: boolOr(o.enabled, false),
    difficulty: intOr(o.difficulty, 0),
    ttl: intOr(o.ttl, 0),
  };
}

function normalizeLogging(v: unknown): LoggingConfig {
  const o = isRecord(v) ? v : {};
  return {
    level: stringOr(o.level, ""),
    format: stringOr(o.format, ""),
  };
}

function applyDefaults(c: Config): void {
  if (c.listen_addr === "") {
    c.listen_addr = ":8443";
  }
  if (c.database.path === "") {
    c.database.path = "semp.db";
  }
  if (c.policy.session_ttl <= 0) {
    c.policy.session_ttl = 300;
  }
  if (c.policy.permissions.length === 0) {
    c.policy.permissions = ["send", "receive"];
  }
  if (c.federation.session_ttl <= 0) {
    c.federation.session_ttl = 3600;
  }
  if (c.federation.retention === "") {
    c.federation.retention = "7d";
  }
  if (c.logging.level === "") {
    c.logging.level = "info";
  }
  if (c.logging.format === "") {
    c.logging.format = "text";
  }
  if (c.crypto.suite === "") {
    c.crypto.suite = "pq-kyber768-x25519";
  }
}

function validate(c: Config): void {
  if (c.domain === "") {
    throw new Error("config: domain is required");
  }
  if (c.users.length === 0) {
    throw new Error("config: at least one user is required");
  }
  for (const u of c.users) {
    if (u.address === "") {
      throw new Error("config: user address is empty");
    }
    if (u.password === "") {
      throw new Error(`config: user "${u.address}" has no password`);
    }
    const at = u.address.indexOf("@");
    if (at < 0 || u.address.slice(at + 1) !== c.domain) {
      throw new Error(
        `config: user "${u.address}" must be on domain "${c.domain}"`,
      );
    }
  }
  if ((c.tls.cert_file === "") !== (c.tls.key_file === "")) {
    throw new Error(
      "config: tls.cert_file and tls.key_file must both be set or both empty",
    );
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function stringOr(v: unknown, fallback: string): string {
  return typeof v === "string" ? v : fallback;
}

function boolOr(v: unknown, fallback: boolean): boolean {
  return typeof v === "boolean" ? v : fallback;
}

function intOr(v: unknown, fallback: number): number {
  if (typeof v === "number" && Number.isFinite(v)) {
    return Math.trunc(v);
  }
  if (typeof v === "bigint") {
    return Number(v);
  }
  return fallback;
}

function stringArrayOr(v: unknown): string[] {
  if (!Array.isArray(v)) {
    return [];
  }
  const out: string[] = [];
  for (const entry of v) {
    if (typeof entry === "string") {
      out.push(entry);
    }
  }
  return out;
}
