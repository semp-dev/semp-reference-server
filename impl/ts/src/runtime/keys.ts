/**
 * SEMP_KEYS handlers. Mirrors impl/go/internal/runtime/keys.go.
 *
 * @module
 */

import {
  KeysRequestType,
  newKeysResponse,
  signSignedDoc,
  type KeysRequest,
  type KeysResponse,
  type KeysResponseResult,
  type KeyStoreRecord,
} from "@sempdev/semp/keys";
import type { Forwarder } from "@sempdev/semp/delivery";

import { domainOf } from "./helpers.js";
import type { SQLiteKeyStore } from "../store/keys.js";

const KeysOriginPrefix = "SEMP-KEYS-ORIGIN:";
const KeysRecordPrefix = "SEMP-KEYS-RECORD:";

export interface ClientKeysDeps {
  store: SQLiteKeyStore;
  localDomain: string;
  domainSignFP: string;
  domainSignPriv: Uint8Array;
  forwarder: Forwarder | null;
}

export interface FederationKeysDeps {
  store: SQLiteKeyStore;
  localDomain: string;
  domainSignFP: string;
  domainSignPriv: Uint8Array;
}

/** Process a SEMP_KEYS request from a client session. */
export async function handleClientKeys(
  raw: Uint8Array,
  deps: ClientKeysDeps,
): Promise<Uint8Array> {
  const req = parseKeysRequest(raw);
  const results: KeysResponseResult[] = [];
  for (const addr of req.addresses) {
    const d = domainOf(addr);
    if (d === deps.localDomain) {
      const local = lookupLocalKeys(deps.store, addr, req.include_domain_keys);
      if (local.status === "found") {
        try {
          signLocalResult(deps, local);
        } catch (err) {
          local.status = "error";
          local.error_reason =
            err instanceof Error ? err.message : String(err);
        }
      }
      results.push(local);
      continue;
    }
    // Cross-domain SEMP_KEYS lookup over the federation forwarder is
    // not exposed by semp-ts v0.5.0 (only `forward` for envelopes).
    // The Go impl uses Forwarder.FetchKeys; in TS we report not_found
    // for remote addresses until a parity helper lands upstream.
    void deps.forwarder;
    results.push({
      address: addr,
      status: "not_found",
      domain: d,
      user_keys: [],
    });
  }
  return encodeResponse(newKeysResponse(req.id, results));
}

/** Process a SEMP_KEYS request received over a federation session. */
export function handleFederationKeys(
  raw: Uint8Array,
  deps: FederationKeysDeps,
): Uint8Array {
  const req = parseKeysRequest(raw);
  const results: KeysResponseResult[] = [];
  for (const addr of req.addresses) {
    const d = domainOf(addr);
    if (d === deps.localDomain) {
      const local = lookupLocalKeys(deps.store, addr, req.include_domain_keys);
      if (local.status === "found") {
        try {
          signLocalResult(deps, local);
        } catch (err) {
          local.status = "error";
          local.error_reason =
            err instanceof Error ? err.message : String(err);
        }
      }
      results.push(local);
      continue;
    }
    results.push({
      address: addr,
      status: "not_found",
      domain: d,
      user_keys: [],
    });
  }
  return encodeResponse(newKeysResponse(req.id, results));
}

function parseKeysRequest(raw: Uint8Array): KeysRequest {
  const obj = JSON.parse(new TextDecoder().decode(raw)) as KeysRequest;
  if (obj.type !== KeysRequestType || obj.step !== "request") {
    throw new Error(`unexpected SEMP_KEYS type/step: ${obj.type}/${obj.step}`);
  }
  if (typeof obj.include_domain_keys !== "boolean") {
    obj.include_domain_keys = true;
  }
  return obj;
}

function encodeResponse(resp: KeysResponse): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(resp));
}

function lookupLocalKeys(
  store: SQLiteKeyStore,
  address: string,
  includeDomain: boolean,
): KeysResponseResult {
  const domain = domainOf(address);
  const result: KeysResponseResult = {
    address,
    status: "not_found",
    domain,
    user_keys: [],
  };
  let userKeys: KeyStoreRecord[] = [];
  try {
    userKeys = store.lookupUserKeys(address);
  } catch (err) {
    result.status = "error";
    result.error_reason = err instanceof Error ? err.message : String(err);
    return result;
  }
  if (userKeys.length === 0) {
    return result;
  }
  result.user_keys = userKeys.map((rec) => keyStoreToRecord(rec));
  result.status = "found";
  if (includeDomain) {
    const domRec = store.lookupDomainKey(domain);
    if (domRec !== null) {
      result.domain_key = keyStoreToRecord(domRec);
    }
    const encRec = store.lookupDomainEncryptionKey(domain);
    if (encRec !== null) {
      result.domain_enc_key = keyStoreToRecord(encRec);
    }
  }
  return result;
}

function keyStoreToRecord(rec: KeyStoreRecord): KeysResponseResult["user_keys"][number] {
  const out: KeysResponseResult["user_keys"][number] = {
    algorithm: rec.algorithm,
    public_key: rec.public_key,
    key_id: rec.key_id,
    key_type: rec.key_type,
  };
  if (rec.address !== undefined) {
    out.address = rec.address;
  }
  if (rec.created !== undefined) {
    out.created = rec.created;
  }
  if (rec.expires !== undefined) {
    out.expires = rec.expires;
  }
  if (rec.revocation !== undefined) {
    out.revocation = {
      reason: rec.revocation.reason,
      revoked_at: rec.revocation.revoked_at,
      ...(rec.revocation.replacement_key_id !== undefined
        ? { replacement_key_id: rec.revocation.replacement_key_id }
        : {}),
    };
  }
  return out;
}

interface SignDeps {
  localDomain: string;
  domainSignFP: string;
  domainSignPriv: Uint8Array;
}

/**
 * Apply per-record + response-level domain signatures per CLIENT.md
 * §3.3 / KEY.md §5.1.
 */
function signLocalResult(deps: SignDeps, result: KeysResponseResult): void {
  if (deps.domainSignPriv.length === 0) {
    throw new Error("runtime: no domain signing key");
  }
  // Sign each record. signSignedDoc writes the signature back into a
  // copy of the JSON; we drop it back into a "signatures" array on
  // the typed Record.
  const signedRecords: KeysResponseResult["user_keys"] = [];
  for (const rec of result.user_keys) {
    const cloned: Record<string, unknown> = JSON.parse(JSON.stringify(rec));
    const sig = signSignedDoc({
      preSignJSON: {
        ...cloned,
        signatures: [
          {
            signer: deps.localDomain,
            key_id: deps.domainSignFP,
            value: "",
            timestamp: isoNow(),
          },
        ],
      },
      seed: deps.domainSignPriv,
      signaturePath: "signatures.0.value",
      prefix: KeysRecordPrefix,
    });
    signedRecords.push(sig.signedJSON as unknown as KeysResponseResult["user_keys"][number]);
  }
  result.user_keys = signedRecords;
  // Response-level origin signature.
  const sigBlock = {
    algorithm: "ed25519",
    key_id: deps.domainSignFP,
    value: "",
  };
  const cloned: Record<string, unknown> = JSON.parse(JSON.stringify(result));
  cloned.origin_signature = sigBlock;
  const sig = signSignedDoc({
    preSignJSON: cloned,
    seed: deps.domainSignPriv,
    signaturePath: "origin_signature.value",
    prefix: KeysOriginPrefix,
  });
  const signed = sig.signedJSON as unknown as KeysResponseResult;
  if (signed.origin_signature !== undefined) {
    result.origin_signature = signed.origin_signature;
  }
}

function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
