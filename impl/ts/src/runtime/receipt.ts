/**
 * Delivery-receipt helpers per DELIVERY.md §1.1.1. Mirrors
 * impl/go/internal/runtime/receipt.go.
 *
 * @module
 */

import type { Envelope } from "@sempdev/semp/envelope";
import { canonicalEnvelopeFor } from "@sempdev/semp/envelope";
import {
  computeEnvelopeHash,
  signDeliveryReceipt,
  verifyDeliveryReceipt,
  verifyEnvelopeBinding,
  type DeliveryReceipt,
  type SubmissionResult,
} from "@sempdev/semp/delivery";
import type { Logger } from "pino";

import type { SQLiteKeyStore } from "../store/keys.js";

export interface IssueReceiptDeps {
  domain: string;
  domainSignFP: string;
  domainSignPriv: Uint8Array;
}

/** Build + sign a SEMP_DELIVERY_RECEIPT for `env`. */
export function issueDeliveryReceipt(
  deps: IssueReceiptDeps,
  env: Envelope,
): DeliveryReceipt {
  if (deps.domainSignFP === "" || deps.domainSignPriv.length === 0) {
    throw new Error(
      "recipient server has no domain signing key configured",
    );
  }
  const canonical = canonicalEnvelopeFor(env);
  const acceptedAt = isoNow();
  const result = signDeliveryReceipt({
    envelopeHashB64: computeEnvelopeHash(canonical),
    recipientDomain: deps.domain,
    acceptedAt,
    domainKeyId: deps.domainSignFP,
    domainSigningSeed: deps.domainSignPriv,
  });
  return result.receipt;
}

export interface VerifyReceiptDeps {
  store: SQLiteKeyStore | null;
  identity: string;
  logger: Logger | null;
}

/**
 * Enforce the DELIVERY.md §1.1.1.6 sender-side obligation. Returns
 * the peer result unchanged on success, or a demoted version
 * (`server_unavailable`) when the receipt is missing, malformed, or
 * unverifiable.
 */
export function verifyDeliveredReceipt(
  deps: VerifyReceiptDeps,
  peerDomain: string,
  env: Envelope,
  peerResult: SubmissionResult,
): SubmissionResult {
  if (peerResult.status !== "delivered") {
    return peerResult;
  }
  const demote = (reason: string): SubmissionResult => {
    deps.logger?.warn(
      { identity: deps.identity, recipient: peerResult.recipient, reason },
      "receipt verification failed; demoting to server_unavailable",
    );
    return {
      recipient: peerResult.recipient,
      status: "rejected",
      reason_code: "server_unavailable",
      reason,
    };
  };
  if (peerResult.receipt === undefined || peerResult.receipt === null) {
    return demote(
      "delivered acknowledgment missing required receipt (DELIVERY.md section 1.1.1.6)",
    );
  }
  const receipt = peerResult.receipt;
  if (receipt.recipient_domain !== peerDomain) {
    return demote(
      `receipt recipient_domain "${receipt.recipient_domain}" does not match peer "${peerDomain}"`,
    );
  }
  let canonical: Uint8Array;
  try {
    canonical = canonicalEnvelopeFor(env);
  } catch (err) {
    return demote(
      `canonical envelope bytes: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!verifyEnvelopeBinding(receipt, canonical)) {
    return demote(
      "receipt envelope_hash.value does not bind to the canonical envelope bytes",
    );
  }
  if (deps.store === null) {
    return demote(
      "no keys.Store configured; cannot resolve recipient domain key",
    );
  }
  const rec = deps.store.lookupDomainKey(peerDomain);
  if (rec === null) {
    return demote("no peer domain key on file");
  }
  if (rec.key_id !== receipt.signature.key_id) {
    return demote(
      `receipt signature.key_id "${receipt.signature.key_id}" does not match cached peer domain key "${rec.key_id}"`,
    );
  }
  let pubBytes: Uint8Array;
  try {
    pubBytes = new Uint8Array(Buffer.from(rec.public_key, "base64"));
  } catch (err) {
    return demote(
      `decode peer domain public key: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!verifyDeliveryReceipt({ receipt, domainPub: pubBytes })) {
    return demote("delivery receipt signature did not verify");
  }
  return peerResult;
}

function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
