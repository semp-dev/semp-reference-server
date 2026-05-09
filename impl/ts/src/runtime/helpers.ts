/**
 * Shared runtime helpers. Mirrors impl/go/internal/runtime/helpers.go.
 *
 * @module
 */

import { randomBytes } from "node:crypto";

const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Return everything after the last `@` in `address`, or "". */
export function domainOf(address: string): string {
  const at = address.lastIndexOf("@");
  if (at < 0) {
    return "";
  }
  return address.slice(at + 1);
}

/** Predicate: does `address` belong to `localDomain` (case-insensitive). */
export function isLocalAddressFor(localDomain: string): (address: string) => boolean {
  const lo = localDomain.toLowerCase();
  return (address: string) => {
    const at = address.lastIndexOf("@");
    if (at < 0) {
      return false;
    }
    return address.slice(at + 1).toLowerCase() === lo;
  };
}

/** Mint a 26-character ULID-shaped session id. */
export function generateSessionID(): string {
  const bits = new Uint8Array(16);
  const ms = BigInt(Date.now());
  bits[0] = Number((ms >> 40n) & 0xffn);
  bits[1] = Number((ms >> 32n) & 0xffn);
  bits[2] = Number((ms >> 24n) & 0xffn);
  bits[3] = Number((ms >> 16n) & 0xffn);
  bits[4] = Number((ms >> 8n) & 0xffn);
  bits[5] = Number(ms & 0xffn);
  const r = randomBytes(10);
  for (let i = 0; i < 10; i++) {
    bits[6 + i] = r[i] ?? 0;
  }
  let high = 0n;
  for (let i = 0; i < 8; i++) {
    high = (high << 8n) | BigInt(bits[i] ?? 0);
  }
  let low = 0n;
  for (let i = 8; i < 16; i++) {
    low = (low << 8n) | BigInt(bits[i] ?? 0);
  }
  const out: string[] = new Array(26);
  for (let i = 25; i >= 13; i--) {
    out[i] = ULID_ALPHABET[Number(low & 31n)] ?? "0";
    low >>= 5n;
  }
  for (let i = 12; i >= 0; i--) {
    out[i] = ULID_ALPHABET[Number(high & 31n)] ?? "0";
    high >>= 5n;
  }
  return out.join("");
}
