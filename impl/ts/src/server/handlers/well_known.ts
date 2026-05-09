/**
 * Well-known endpoint handlers. Mirrors the corresponding HTTP routes
 * in impl/go/internal/server/handlers.go.
 *
 *  - GET /.well-known/semp/configuration
 *  - GET /.well-known/semp/keys/{address}
 *  - GET /.well-known/semp/domain-keys
 *
 * @module
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import type { Logger } from "pino";

import type { SQLiteKeyStore } from "../../store/keys.js";

const PROTOCOL_VERSION = "1.0.0";
const DEFAULT_MAX_ENVELOPE_SIZE = 25 * 1024 * 1024;

export interface WellKnownDeps {
  store: SQLiteKeyStore;
  domain: string;
  tlsEnabled: boolean;
  externalTLS: boolean;
  quicEnabled: boolean;
  advertisedSuites: () => string[];
  logger: Logger;
}

interface KeyEntry {
  algorithm: string;
  public_key: string;
  key_id: string;
}

export function makeWellKnownConfigHandler(deps: WellKnownDeps) {
  return (req: IncomingMessage, res: ServerResponse): void => {
    const wsScheme = deps.tlsEnabled || deps.externalTLS ? "wss" : "ws";
    const h2Scheme = deps.tlsEnabled || deps.externalTLS ? "https" : "http";
    const host = req.headers.host ?? "";
    const clientEndpoints: Record<string, string> = {
      h2: `${h2Scheme}://${host}/v1/h2`,
      ws: `${wsScheme}://${host}/v1/ws`,
    };
    const fedEndpoints: Record<string, string> = {
      h2: `${h2Scheme}://${host}/v1/h2/federate`,
      ws: `${wsScheme}://${host}/v1/federate`,
    };
    if (deps.quicEnabled) {
      clientEndpoints.quic = `https://${host}/v1/quic`;
      fedEndpoints.quic = `https://${host}/v1/quic/federate`;
    }
    const cfg = {
      type: "SEMP_CONFIGURATION",
      version: PROTOCOL_VERSION,
      domain: deps.domain,
      revision: 1,
      ttl_seconds: 3600,
      endpoints: {
        client: clientEndpoints,
        federation: fedEndpoints,
        register: `${h2Scheme}://${host}/v1/register`,
        device_register: `${h2Scheme}://${host}/v1/device/register`,
        blocklist: `${h2Scheme}://${host}/v1/blocklist`,
        keys: `${h2Scheme}://${host}/.well-known/semp/keys/`,
        domain_keys: `${h2Scheme}://${host}/.well-known/semp/domain-keys`,
      },
      suites: deps.advertisedSuites(),
      limits: {
        max_envelope_size: DEFAULT_MAX_ENVELOPE_SIZE,
      },
      extensions: [],
    };
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.statusCode = 200;
    res.end(JSON.stringify(cfg));
  };
}

export function makeWellKnownKeysHandler(deps: WellKnownDeps) {
  return (req: IncomingMessage, res: ServerResponse): void => {
    const url = req.url ?? "";
    const address = url.startsWith("/.well-known/semp/keys/")
      ? url.slice("/.well-known/semp/keys/".length)
      : "";
    if (address === "") {
      res.statusCode = 400;
      res.end("missing address");
      return;
    }
    let records;
    try {
      records = deps.store.lookupUserKeys(address);
    } catch (err) {
      deps.logger.error(
        { address, err: err instanceof Error ? err.message : String(err) },
        "key lookup failed",
      );
      res.statusCode = 500;
      res.end("internal error");
      return;
    }
    if (records.length === 0) {
      res.statusCode = 404;
      res.end("not found");
      return;
    }
    const out = {
      type: "SEMP_KEYS",
      version: PROTOCOL_VERSION,
      keys: records,
    };
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.statusCode = 200;
    res.end(JSON.stringify(out));
  };
}

export function makeWellKnownDomainKeysHandler(deps: WellKnownDeps) {
  return (_req: IncomingMessage, res: ServerResponse): void => {
    const signRec = deps.store.lookupDomainKey(deps.domain);
    const encRec = deps.store.lookupDomainEncryptionKey(deps.domain);
    const out: {
      type: string;
      version: string;
      domain: string;
      signing_key?: KeyEntry;
      encryption_key?: KeyEntry;
    } = {
      type: "SEMP_DOMAIN_KEYS",
      version: PROTOCOL_VERSION,
      domain: deps.domain,
    };
    if (signRec !== null) {
      out.signing_key = {
        algorithm: signRec.algorithm,
        public_key: signRec.public_key,
        key_id: signRec.key_id,
      };
    }
    if (encRec !== null) {
      out.encryption_key = {
        algorithm: encRec.algorithm,
        public_key: encRec.public_key,
        key_id: encRec.key_id,
      };
    }
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.statusCode = 200;
    res.end(JSON.stringify(out));
  };
}
