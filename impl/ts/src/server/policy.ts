/**
 * Operator policy for client handshakes. Mirrors
 * impl/go/internal/server/policy.go.
 *
 * @module
 */

import type { PolicyConfig } from "../config/types.js";
import type { Metrics } from "./metrics.js";

export interface ServerPolicy {
  blockedDomain(domain: string): boolean;
  sessionTTL(): number;
  permissions(): string[];
  powEnabled(): boolean;
  powDifficulty(): number;
  powTTLSeconds(): number;
  recordChallenge(): void;
}

export function newPolicy(
  cfg: PolicyConfig,
  metrics: Metrics | null,
): ServerPolicy {
  const blocked = new Set<string>(cfg.blocked_domains);
  const perms = cfg.permissions.length > 0
    ? cfg.permissions.slice()
    : ["send", "receive"];
  const sessionTTL = cfg.session_ttl > 0 ? cfg.session_ttl : 300;
  const powDiff = cfg.pow.difficulty > 0 ? cfg.pow.difficulty : 20;
  const powTTL = cfg.pow.ttl > 0 ? cfg.pow.ttl : 300;
  return {
    blockedDomain(domain) {
      return blocked.has(domain);
    },
    sessionTTL() {
      return sessionTTL;
    },
    permissions() {
      return perms;
    },
    powEnabled() {
      return cfg.pow.enabled;
    },
    powDifficulty() {
      return powDiff;
    },
    powTTLSeconds() {
      return powTTL;
    },
    recordChallenge() {
      metrics?.challengesIssued.inc();
    },
  };
}
