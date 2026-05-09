/**
 * Envelope submission handlers. Mirrors impl/go/internal/runtime/envelope.go.
 *
 * @module
 */

import { computeMAC } from "@sempdev/semp/crypto";
import {
  canonicalEnvelopeFor,
  decodeEnvelope,
  encodeEnvelope,
  openBriefAny,
  type Envelope,
  type RecipientCandidate,
} from "@sempdev/semp/envelope";
import { sign as ed25519Sign } from "@sempdev/semp/keys";
import {
  Pipeline,
  newSubmissionResponse,
  type Forwarder,
  type SubmissionResponse,
  type SubmissionResult,
} from "@sempdev/semp/delivery";
import type { Session } from "@sempdev/semp/session";
import type { Logger } from "pino";

import { domainOf, isLocalAddressFor } from "./helpers.js";
import { enforceSendScope } from "./scope.js";
import { issueDeliveryReceipt, verifyDeliveredReceipt } from "./receipt.js";
import type { SQLiteKeyStore } from "../store/keys.js";
import type { SQLiteInbox } from "../store/inbox.js";
import type { SQLiteBlockList } from "../store/blocklist.js";

const EnvelopePrefix = "SEMP-ENVELOPE:";

export interface ClientEnvelopeDeps {
  suite: "x25519-chacha20-poly1305" | "pq-kyber768-x25519";
  store: SQLiteKeyStore;
  inbox: SQLiteInbox;
  forwarder: Forwarder | null;
  blockList: SQLiteBlockList;
  localDomain: string;
  domainSignFP: string;
  domainSignPriv: Uint8Array;
  domainEncFP: string;
  domainEncPriv: Uint8Array;
  domainEncPub: Uint8Array;
  identity: string;
  deviceKeyId: string;
  session: Session;
  logger: Logger | null;
}

export interface FederationEnvelopeDeps {
  suite: "x25519-chacha20-poly1305" | "pq-kyber768-x25519";
  store: SQLiteKeyStore;
  inbox: SQLiteInbox;
  blockList: SQLiteBlockList;
  localDomain: string;
  domainSignFP: string;
  domainSignPriv: Uint8Array;
  domainEncFP: string;
  domainEncPriv: Uint8Array;
  domainEncPub: Uint8Array;
  identity: string;
  session: Session;
  logger: Logger | null;
}

/** Process one client-submitted envelope frame. */
export async function handleClientSubmission(
  raw: Uint8Array,
  deps: ClientEnvelopeDeps,
): Promise<Uint8Array> {
  let env: Envelope;
  try {
    env = decodeEnvelope(raw);
  } catch (err) {
    return encodeJSON(
      newSubmissionResponse("malformed", [
        {
          recipient: deps.identity,
          status: "rejected",
          reason_code: "seal_invalid",
          reason: err instanceof Error ? err.message : String(err),
        },
      ]),
    );
  }
  return handleClientSubmissionEnvelope(env, deps);
}

async function handleClientSubmissionEnvelope(
  env: Envelope,
  deps: ClientEnvelopeDeps,
): Promise<Uint8Array> {
  // Sign + session_mac the envelope on the home server's behalf.
  try {
    signEnvelopeInPlace(env, deps);
  } catch (err) {
    return encodeJSON(
      newSubmissionResponse(env.postmark.id, [
        {
          recipient: deps.identity,
          status: "rejected",
          reason_code: "seal_invalid",
          reason: err instanceof Error ? err.message : String(err),
        },
      ]),
    );
  }

  // Open the brief once for scope enforcement.
  const candidate: RecipientCandidate = {
    keyId: deps.domainEncFP,
    privateKey: deps.domainEncPriv,
    publicKey: deps.domainEncPub,
  };
  let brief: { to?: unknown; cc?: unknown; from?: unknown };
  try {
    const opened = openBriefAny(deps.suite, env, [candidate]);
    brief = opened.brief as typeof brief;
  } catch (err) {
    return encodeJSON(
      newSubmissionResponse(env.postmark.id, [
        {
          recipient: deps.identity,
          status: "rejected",
          reason_code: "seal_invalid",
          reason: `server cannot unwrap brief: ${err instanceof Error ? err.message : String(err)}`,
        },
      ]),
    );
  }
  const briefTo = Array.isArray(brief.to) ? (brief.to as string[]) : [];
  const briefCC = Array.isArray(brief.cc) ? (brief.cc as string[]) : [];
  const allRecipients = [...briefTo, ...briefCC];

  // Scope enforcement.
  let scopeOutcome;
  try {
    scopeOutcome = await enforceSendScope(
      {
        store: deps.store,
        identity: deps.identity,
        deviceKeyId: deps.deviceKeyId,
        logger: deps.logger,
      },
      env.postmark.id,
      allRecipients,
    );
  } catch (err) {
    return encodeJSON(
      newSubmissionResponse(env.postmark.id, [
        {
          recipient: deps.identity,
          status: "rejected",
          reason_code: "policy_forbidden",
          reason: err instanceof Error ? err.message : String(err),
        },
      ]),
    );
  }
  if (scopeOutcome.allBlocked) {
    return encodeJSON(
      newSubmissionResponse(env.postmark.id, scopeOutcome.rejections),
    );
  }

  // Run the delivery pipeline. Skip signature + session_mac because we
  // produced both moments ago.
  const pipe = new Pipeline({
    envMAC: () => deps.session.keys.envMAC,
    briefRecipients: [candidate],
    blockList: deps.blockList,
    isLocal: isLocalAddressFor(deps.localDomain),
    inbox: deps.inbox,
    skipSignatureCheck: true,
    skipSessionMACCheck: true,
    ...(deps.logger !== null
      ? { logger: (line: string) => deps.logger?.info(line) }
      : {}),
  });
  const result = await pipe.process(env);
  if (result.rejection !== undefined) {
    const rej = result.rejection;
    return encodeJSON(
      newSubmissionResponse(env.postmark.id, [
        {
          recipient: deps.identity,
          status: "rejected",
          reason_code: rej.reasonCode,
          reason: rej.reason,
        },
      ]),
    );
  }

  // Merge scope rejections back in (overrides pipeline outcomes for
  // those recipients) and forward non-local recipients via the
  // federation forwarder.
  const blocked = new Map<string, SubmissionResult>();
  for (const r of scopeOutcome.rejections) {
    if (r.status === "rejected") {
      blocked.set(r.recipient, r);
    }
  }

  const wire = encodeEnvelope(env);
  const out: SubmissionResult[] = [];
  for (const row of result.results) {
    const override = blocked.get(row.recipient);
    if (override !== undefined) {
      out.push(override);
      continue;
    }
    if (row.reason_code !== "recipient_not_found") {
      if (row.status === "delivered" && deps.logger !== null) {
        deps.logger.info(
          {
            identity: deps.identity,
            envelope: env.postmark.id,
            recipient: row.recipient,
          },
          "envelope delivered locally",
        );
      }
      out.push(row);
      continue;
    }
    // Cross-domain forwarding.
    const address = row.recipient;
    if (deps.forwarder === null) {
      out.push({
        recipient: address,
        status: "rejected",
        reason_code: "recipient_not_found",
        reason: "cross-domain forwarding is not enabled on this server",
      });
      continue;
    }
    const peerDomain = domainOf(address);
    let forwardEnv: Envelope;
    try {
      forwardEnv = decodeEnvelope(wire);
    } catch (err) {
      out.push({
        recipient: address,
        status: "rejected",
        reason_code: "seal_invalid",
        reason: `forwarding failed: ${err instanceof Error ? err.message : String(err)}`,
      });
      continue;
    }
    let peerResp: SubmissionResponse;
    try {
      peerResp = await deps.forwarder.forward(peerDomain, forwardEnv);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      out.push({
        recipient: address,
        status: "rejected",
        reason_code: "server_unavailable",
        reason: `forwarding to remote domain failed: ${reason}`,
      });
      deps.logger?.warn(
        {
          identity: deps.identity,
          envelope: env.postmark.id,
          recipient: address,
          err: reason,
        },
        "forward failed",
      );
      continue;
    }
    for (const peerResult of peerResp.results) {
      const verified = verifyDeliveredReceipt(
        {
          store: deps.store,
          identity: deps.identity,
          logger: deps.logger,
        },
        peerDomain,
        forwardEnv,
        peerResult,
      );
      out.push(verified);
      deps.logger?.info(
        {
          identity: deps.identity,
          envelope: env.postmark.id,
          recipient: verified.recipient,
          status: verified.status,
        },
        "envelope forwarded",
      );
    }
  }

  return encodeJSON(newSubmissionResponse(env.postmark.id, out));
}

/** Process one envelope arriving on a federation session. */
export async function handleFederationSubmission(
  raw: Uint8Array,
  deps: FederationEnvelopeDeps,
): Promise<Uint8Array> {
  let env: Envelope;
  try {
    env = decodeEnvelope(raw);
  } catch (err) {
    return encodeJSON(
      newSubmissionResponse("malformed", [
        {
          recipient: deps.identity,
          status: "rejected",
          reason_code: "seal_invalid",
          reason: err instanceof Error ? err.message : String(err),
        },
      ]),
    );
  }
  return handleFederationSubmissionEnvelope(env, deps);
}

async function handleFederationSubmissionEnvelope(
  env: Envelope,
  deps: FederationEnvelopeDeps,
): Promise<Uint8Array> {
  const candidate: RecipientCandidate = {
    keyId: deps.domainEncFP,
    privateKey: deps.domainEncPriv,
    publicKey: deps.domainEncPub,
  };
  const pipe = new Pipeline({
    envMAC: () => deps.session.keys.envMAC,
    domainKeys: async (domain: string): Promise<Uint8Array | null> => {
      const rec = deps.store.lookupDomainKey(domain);
      if (rec === null) {
        return null;
      }
      return new Uint8Array(Buffer.from(rec.public_key, "base64"));
    },
    briefRecipients: [candidate],
    blockList: deps.blockList,
    isLocal: isLocalAddressFor(deps.localDomain),
    inbox: deps.inbox,
    ...(deps.logger !== null
      ? { logger: (line: string) => deps.logger?.info(line) }
      : {}),
  });
  const result = await pipe.process(env);
  if (result.rejection !== undefined) {
    const rej = result.rejection;
    return encodeJSON(
      newSubmissionResponse(env.postmark.id, [
        {
          recipient: deps.identity,
          status: "rejected",
          reason_code: rej.reasonCode,
          reason: rej.reason,
        },
      ]),
    );
  }

  // Override the pipeline's generic "recipient is not local" reason
  // text with the federation-specific "endpoint does not multi-hop".
  // Silent outcomes (per-recipient block-list silent or
  // receipt-issuance failure) are dropped from the wire response per
  // DELIVERY.md section 1: there is no `silent` wire value, so the
  // peer sender's per-recipient timeout produces a sender-side
  // `silent` classification.
  const out: SubmissionResult[] = [];
  for (const row of result.results) {
    if (row.status === "silent") {
      // DELIVERY.md section 1.3: withhold any wire response for a
      // silent disposition. The peer's per-recipient timeout
      // synthesizes the silent classification.
      deps.logger?.info(
        {
          peer: deps.identity,
          envelope: env.postmark.id,
          recipient: row.recipient,
        },
        "federated silent block: withholding wire entry",
      );
      continue;
    }
    if (row.reason_code === "recipient_not_found") {
      out.push({
        ...row,
        reason: "federation endpoint does not multi-hop",
      });
      continue;
    }
    if (row.status === "delivered") {
      deps.logger?.info(
        {
          peer: deps.identity,
          envelope: env.postmark.id,
          recipient: row.recipient,
        },
        "federated delivery",
      );
      try {
        const receipt = issueDeliveryReceipt(
          {
            domain: deps.localDomain,
            domainSignFP: deps.domainSignFP,
            domainSignPriv: deps.domainSignPriv,
          },
          env,
        );
        out.push({ ...row, receipt });
      } catch (err) {
        // DELIVERY.md section 1.1.1.5 forbids returning `delivered`
        // without a verifiable receipt, so withhold this recipient's
        // wire entry. The peer's per-recipient timeout produces the
        // sender-side silent classification (DELIVERY.md section 1.5).
        deps.logger?.warn(
          {
            peer: deps.identity,
            envelope: env.postmark.id,
            err: err instanceof Error ? err.message : String(err),
          },
          "issue receipt failed; withholding wire entry",
        );
      }
      continue;
    }
    out.push(row);
  }
  return encodeJSON(newSubmissionResponse(env.postmark.id, out));
}

/**
 * Re-sign + session-MAC `env` in-place under the home server's domain
 * signing key and the current session's K_env_mac.
 */
function signEnvelopeInPlace(
  env: Envelope,
  deps: ClientEnvelopeDeps,
): void {
  env.seal.signature = "";
  env.seal.session_mac = "";
  const canonical = canonicalEnvelopeFor(env);
  const signingInput = concat(
    new TextEncoder().encode(EnvelopePrefix),
    canonical,
  );
  const sig = ed25519Sign(deps.domainSignPriv, signingInput);
  env.seal.signature = Buffer.from(sig).toString("base64");
  const mac = computeMAC(deps.session.keys.envMAC, canonical);
  env.seal.session_mac = Buffer.from(mac).toString("base64");
  // The seal.key_id should reflect the signer.
  env.seal.key_id = deps.domainSignFP;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function encodeJSON(v: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(v));
}
