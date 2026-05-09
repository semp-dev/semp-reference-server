/**
 * Send-scope enforcement per CLIENT.md §2.4.
 *
 * Mirrors impl/go/internal/runtime/scope.go.
 *
 * @module
 */

import {
  scopeAllowsRecipient,
  validateDeviceCertificate,
  verifyDeviceCertificate,
  type DeviceCertificate,
} from "@sempdev/semp/keys";
import type { SubmissionResult } from "@sempdev/semp/delivery";
import type { Logger } from "pino";

import type { SQLiteKeyStore } from "../store/keys.js";

export interface ScopeDeps {
  store: SQLiteKeyStore | null;
  identity: string;
  deviceKeyId: string;
  logger: Logger | null;
}

export interface ScopeOutcome {
  rejections: SubmissionResult[];
  allBlocked: boolean;
}

/**
 * Apply the device certificate's scope.send to `recipients`. Returns
 * the per-recipient rejections (empty when the device is full-access)
 * and an `allBlocked` flag that lets callers short-circuit delivery.
 */
export async function enforceSendScope(
  deps: ScopeDeps,
  envelopeId: string,
  recipients: string[],
): Promise<ScopeOutcome> {
  if (deps.deviceKeyId === "" || deps.store === null) {
    return { rejections: [], allBlocked: false };
  }
  const cert = deps.store.lookupDeviceCertificate(deps.deviceKeyId);
  if (cert === null) {
    return { rejections: [], allBlocked: false };
  }
  await verifyChain(cert, deps.store);
  if (cert.account !== deps.identity) {
    throw new Error(
      `device certificate account ${cert.account} does not match session identity ${deps.identity}`,
    );
  }
  const scope = cert.scope.send;
  const blocked: SubmissionResult[] = [];
  let allowedCount = 0;
  for (const address of recipients) {
    if (scopeAllowsRecipient(scope, { address })) {
      allowedCount++;
      continue;
    }
    const reason =
      scope.mode === "none"
        ? "device certificate scope.send.mode is 'none'"
        : `recipient ${address} is outside the device's scope.send`;
    blocked.push({
      recipient: address,
      status: "rejected",
      reason_code: "scope_exceeded",
      reason,
    });
    deps.logger?.warn(
      {
        identity: deps.identity,
        envelope: envelopeId,
        recipient: address,
        mode: scope.mode,
      },
      "scope_exceeded",
    );
  }
  const allBlocked = allowedCount === 0 && recipients.length > 0;
  return { rejections: blocked, allBlocked };
}

async function verifyChain(
  cert: DeviceCertificate,
  store: SQLiteKeyStore,
): Promise<void> {
  validateDeviceCertificate(cert);
  // Look up the issuing device's published identity record.
  const issuerKeyId = cert.signature.key_id;
  if (issuerKeyId === "") {
    throw new Error("device certificate signature.key_id is empty");
  }
  // Walk the issuer's user keys to find the matching key_id.
  const issuerKeys = store.lookupUserKeys(cert.account);
  const match = issuerKeys.find((k) => k.key_id === issuerKeyId);
  if (match === undefined) {
    throw new Error(
      `device certificate issuer key ${issuerKeyId} is not registered for ${cert.account}`,
    );
  }
  if (match.revocation !== undefined) {
    throw new Error(
      `device certificate issuer key ${issuerKeyId} has been revoked`,
    );
  }
  const issuerPub = new Uint8Array(Buffer.from(match.public_key, "base64"));
  if (!verifyDeviceCertificate(cert, issuerPub)) {
    throw new Error("device certificate signature did not verify");
  }
}
