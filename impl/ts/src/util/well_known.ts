/**
 * HTTPS GET /.well-known/semp/domain-keys for auto-fetch of peer
 * domain signing keys. Mirrors the Go fetchDomainSigningKeyFromWellKnown.
 *
 * @module
 */

import { lookupSempTarget } from "./srv_lookup.js";

interface DomainKeysResponse {
  signing_key?: {
    public_key: string;
  };
}

/**
 * Fetch the published Ed25519 signing public key for `domain`. Returns
 * null on any failure (DNS, HTTP, JSON parse, missing field). Tries
 * the SRV target first, falls back to the bare domain.
 */
export async function fetchDomainSigningKeyFromWellKnown(
  domain: string,
): Promise<Uint8Array | null> {
  const srvTarget = await lookupSempTarget(domain);
  const candidates = srvTarget !== null && srvTarget !== "" ? [srvTarget, domain] : [domain];
  for (const host of candidates) {
    try {
      const url = `https://${host}/.well-known/semp/domain-keys`;
      const resp = await fetch(url, {
        signal: AbortSignal.timeout(10_000),
      });
      if (!resp.ok) {
        continue;
      }
      const body = (await resp.json()) as DomainKeysResponse;
      if (
        body.signing_key === undefined ||
        typeof body.signing_key.public_key !== "string"
      ) {
        continue;
      }
      const bytes = Buffer.from(body.signing_key.public_key, "base64");
      if (bytes.length === 0) {
        continue;
      }
      return new Uint8Array(bytes);
    } catch {
      continue;
    }
  }
  return null;
}
