/**
 * POST /v1/device/register handler. Mirrors handleDeviceRegister in
 * impl/go/internal/server/handlers.go.
 *
 * @module
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  validateDeviceCertificate,
  verifyDeviceCertificate,
  type DeviceCertificate,
} from "@sempdev/semp/keys";
import type { Logger } from "pino";

import { computeFingerprint, type SQLiteKeyStore } from "../../store/keys.js";

const MAX_BODY = 1 << 20; // 1 MiB

interface DeviceRegisterRequest {
  certificate?: DeviceCertificate;
  device_identity_key?: { algorithm: string; public_key: string };
  device_encryption_key?: { algorithm: string; public_key: string };
}

export interface DeviceRegisterDeps {
  store: SQLiteKeyStore;
  users: Map<string, string>;
  logger: Logger;
}

export function makeDeviceRegisterHandler(deps: DeviceRegisterDeps) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method !== "POST") {
      res.statusCode = 405;
      res.end("method not allowed");
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
    let parsed: DeviceRegisterRequest;
    try {
      parsed = JSON.parse(
        new TextDecoder().decode(body),
      ) as DeviceRegisterRequest;
    } catch {
      res.statusCode = 400;
      res.end("invalid request body");
      return;
    }
    const cert = parsed.certificate;
    if (
      cert === undefined ||
      cert.account === "" ||
      cert.device_id === "" ||
      cert.device_public_key === ""
    ) {
      res.statusCode = 400;
      res.end(
        "certificate must include account, device_id, and device_public_key",
      );
      return;
    }
    if (!deps.users.has(cert.account)) {
      res.statusCode = 403;
      res.end("unknown user");
      return;
    }
    try {
      validateDeviceCertificate(cert);
      const issuerKeyId = cert.signature.key_id;
      const issuerKeys = deps.store.lookupUserKeys(cert.account);
      const issuer = issuerKeys.find((k) => k.key_id === issuerKeyId);
      if (issuer === undefined) {
        throw new Error(
          `issuer key ${issuerKeyId} is not registered for ${cert.account}`,
        );
      }
      if (issuer.revocation !== undefined) {
        throw new Error(`issuer key ${issuerKeyId} has been revoked`);
      }
      const issuerPub = new Uint8Array(
        Buffer.from(issuer.public_key, "base64"),
      );
      if (!verifyDeviceCertificate(cert, issuerPub)) {
        throw new Error("certificate signature did not verify");
      }
    } catch (err) {
      deps.logger.warn(
        {
          user: cert.account,
          device: cert.device_id,
          err: err instanceof Error ? err.message : String(err),
        },
        "device certificate verification failed",
      );
      res.statusCode = 401;
      res.end("certificate verification failed");
      return;
    }

    try {
      deps.store.putDeviceCertificate(cert);
    } catch (err) {
      deps.logger.error(
        { err: err instanceof Error ? err.message : String(err) },
        "store device certificate failed",
      );
      res.statusCode = 500;
      res.end("internal error");
      return;
    }

    const idKey = parsed.device_identity_key;
    const encKey = parsed.device_encryption_key;
    if (
      idKey === undefined ||
      typeof idKey.public_key !== "string" ||
      idKey.public_key === ""
    ) {
      res.statusCode = 400;
      res.end("invalid device identity key");
      return;
    }
    if (
      encKey === undefined ||
      typeof encKey.public_key !== "string" ||
      encKey.public_key === ""
    ) {
      res.statusCode = 400;
      res.end("invalid device encryption key");
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
        address: cert.account,
        key_type: "device",
        algorithm: idKey.algorithm,
        public_key: idKey.public_key,
        key_id: idFP,
        created: now,
        expires,
      });
      deps.store.putRecord({
        address: cert.account,
        key_type: "encryption",
        algorithm: encKey.algorithm,
        public_key: encKey.public_key,
        key_id: encFP,
        created: now,
        expires,
      });
    } catch (err) {
      deps.logger.error(
        { err: err instanceof Error ? err.message : String(err) },
        "store device keys failed",
      );
      res.statusCode = 500;
      res.end("internal error");
      return;
    }

    let devicePub: Uint8Array;
    try {
      devicePub = new Uint8Array(Buffer.from(cert.device_public_key, "base64"));
    } catch {
      devicePub = new Uint8Array();
    }
    deps.logger.info(
      {
        user: cert.account,
        device: cert.device_id,
        device_key: devicePub.length > 0 ? computeFingerprint(devicePub) : "",
        scope_send: cert.scope.send.mode,
      },
      "device registered",
    );
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.statusCode = 200;
    res.end(
      JSON.stringify({ status: "registered", device_id: cert.device_id }),
    );
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
