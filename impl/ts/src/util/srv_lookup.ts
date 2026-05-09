/**
 * DNS SRV resolution for `_semp._tcp.<domain>`.
 *
 * @module
 */

import { Resolver } from "node:dns/promises";

/**
 * Return the SRV target for `domain`, or null when the lookup fails or
 * has no records.
 */
export async function lookupSempTarget(domain: string): Promise<string | null> {
  const resolver = new Resolver();
  try {
    const records = await resolver.resolveSrv(`_semp._tcp.${domain}`);
    if (records.length === 0) {
      return null;
    }
    const first = records[0];
    if (first === undefined || first.name === "") {
      return null;
    }
    let target = first.name;
    if (target.endsWith(".")) {
      target = target.slice(0, -1);
    }
    return target;
  } catch {
    return null;
  }
}
