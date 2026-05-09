/**
 * POST /v1/register handler. Mirrors handleRegister in
 * impl/go/internal/server/handlers.go.
 *
 * @module
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import type { Logger } from "pino";

import { computeFingerprint, type SQLiteKeyStore } from "../../store/keys.js";
import { clientIP, type IPRateLimiter } from "../ratelimit.js";
import type { Metrics } from "../metrics.js";

const MAX_BODY = 1 << 20; // 1 MiB

interface RegisterKey {
  algorithm: string;
  public_key: string;
}

interface RegisterRequest {
  address?: string;
  password?: string;
  identity_key?: RegisterKey;
  encryption_key?: RegisterKey;
}

interface RegisterKeyEntry {
  algorithm: string;
  public_key: string;
  key_id: string;
}

interface RegisterResponse {
  status: string;
  domain_signing_key?: RegisterKeyEntry;
  domain_encryption_key?: RegisterKeyEntry;
}

export interface RegisterDeps {
  store: SQLiteKeyStore;
  users: Map<string, string>;
  domain: string;
  rateLimiter: IPRateLimiter;
  metrics: Metrics | null;
  logger: Logger;
}

export function makeRegisterHandler(deps: RegisterDeps) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method !== "POST") {
      res.statusCode = 405;
      res.end("method not allowed");
      return;
    }
    if (!deps.rateLimiter.allow(clientIP(req))) {
      res.statusCode = 429;
      res.end("too many requests");
      return;
    }
    let body: Uint8Array;
    try {
      body = await readLimited(req, MAX_BODY);
    } catch {
      res.statusCode = 400;
      res.end("invalid request body");
      return;
    }
    let parsed: RegisterRequest;
    try {
      parsed = JSON.parse(new TextDecoder().decode(body)) as RegisterRequest;
    } catch {
      res.statusCode = 400;
      res.end("invalid request body");
      return;
    }
    const address = parsed.address ?? "";
    const password = parsed.password ?? "";
    const expected = deps.users.get(address);
    if (expected === undefined || password !== expected) {
      deps.logger.warn({ address }, "registration rejected");
      res.statusCode = 401;
      res.end("invalid credentials");
      return;
    }

    const idKey = parsed.identity_key;
    const encKey = parsed.encryption_key;
    if (
      idKey === undefined ||
      typeof idKey.public_key !== "string" ||
      idKey.public_key === ""
    ) {
      res.statusCode = 400;
      res.end("invalid identity key");
      return;
    }
    if (
      encKey === undefined ||
      typeof encKey.public_key !== "string" ||
      encKey.public_key === ""
    ) {
      res.statusCode = 400;
      res.end("invalid encryption key");
      return;
    }

    let idPub: Uint8Array;
    let encPub: Uint8Array;
    try {
      idPub = new Uint8Array(Buffer.from(idKey.public_key, "base64"));
      encPub = new Uint8Array(Buffer.from(encKey.public_key, "base64"));
    } catch {
      res.statusCode = 400;
      res.end("invalid key encoding");
      return;
    }

    const now = isoNow();
    const expires = isoNowPlusDays(365);
    const idFP = computeFingerprint(idPub);
    const encFP = computeFingerprint(encPub);
    try {
      deps.store.putRecord({
        address,
        key_type: "identity",
        algorithm: idKey.algorithm,
        public_key: idKey.public_key,
        key_id: idFP,
        created: now,
        expires,
      });
      deps.store.putRecord({
        address,
        key_type: "encryption",
        algorithm: encKey.algorithm,
        public_key: encKey.public_key,
        key_id: encFP,
        created: now,
        expires,
      });
    } catch (err) {
      deps.logger.error({ err: String(err), address }, "store user keys failed");
      res.statusCode = 500;
      res.end("internal error");
      return;
    }

    deps.metrics?.registrations.inc();
    deps.logger.info(
      { address, identity_fp: idFP, encryption_fp: encFP },
      "user registered",
    );

    const signRec = deps.store.lookupDomainKey(deps.domain);
    const encRec = deps.store.lookupDomainEncryptionKey(deps.domain);
    const out: RegisterResponse = { status: "registered" };
    if (signRec !== null) {
      out.domain_signing_key = {
        algorithm: signRec.algorithm,
        public_key: signRec.public_key,
        key_id: signRec.key_id,
      };
    }
    if (encRec !== null) {
      out.domain_encryption_key = {
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

async function readLimited(
  req: IncomingMessage,
  max: number,
): Promise<Uint8Array> {
  return new Promise<Uint8Array>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > max) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(new Uint8Array(Buffer.concat(chunks))));
    req.on("error", reject);
  });
}

function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function isoNowPlusDays(days: number): string {
  return new Date(Date.now() + days * 24 * 3600 * 1000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
}
