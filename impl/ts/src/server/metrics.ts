/**
 * Counter-only operational metrics. Mirrors
 * impl/go/internal/server/metrics.go: each counter is a monotonic
 * int64 surfaced as JSON at /debug/metrics.
 *
 * @module
 */

import type { IncomingMessage, ServerResponse } from "node:http";

export class Counter {
  private value = 0n;
  inc(by = 1): void {
    this.value += BigInt(by);
  }
  load(): bigint {
    return this.value;
  }
}

export class Metrics {
  readonly handshakesSuccess = new Counter();
  readonly handshakesFailure = new Counter();
  readonly registrations = new Counter();
  readonly envelopesDelivered = new Counter();
  readonly envelopesRejected = new Counter();
  readonly envelopesFetched = new Counter();
  readonly federationSuccess = new Counter();
  readonly federationFailure = new Counter();
  readonly challengesIssued = new Counter();
  readonly challengesSolved = new Counter();
  readonly scopeViolations = new Counter();

  /** node:http handler that serves the snapshot as JSON. */
  handler(): (req: IncomingMessage, res: ServerResponse) => void {
    return (_req, res) => {
      const stats = {
        handshakes_success: Number(this.handshakesSuccess.load()),
        handshakes_failure: Number(this.handshakesFailure.load()),
        registrations: Number(this.registrations.load()),
        envelopes_delivered: Number(this.envelopesDelivered.load()),
        envelopes_rejected: Number(this.envelopesRejected.load()),
        envelopes_fetched: Number(this.envelopesFetched.load()),
        federation_success: Number(this.federationSuccess.load()),
        federation_failure: Number(this.federationFailure.load()),
        challenges_issued: Number(this.challengesIssued.load()),
        challenges_solved: Number(this.challengesSolved.load()),
        scope_violations: Number(this.scopeViolations.load()),
      };
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.statusCode = 200;
      res.end(JSON.stringify(stats));
    };
  }
}
