/**
 * SEMP_FETCH handler. Mirrors impl/go/internal/runtime/fetch.go.
 *
 * SEMP_FETCH is a demo-only client/home-server inbox pull. The
 * dispatcher routes it through the `onUnknown` hook because the
 * semp-ts session.runDispatcher does not have a dedicated
 * onFetch handler.
 *
 * @module
 */

import {
  newFetchResponse,
  FetchType,
  type Inbox as MemInbox,
  type FetchRequest,
} from "@sempdev/semp/delivery";
import type { Logger } from "pino";

/** Drain the inbox for `identity` and return the wire response. */
export function handleFetch(
  raw: Uint8Array,
  inbox: MemInbox,
  identity: string,
  logger: Logger | null,
): Uint8Array {
  const req = JSON.parse(new TextDecoder().decode(raw)) as FetchRequest;
  if (req.type !== FetchType || req.step !== "request") {
    throw new Error(
      `unexpected fetch type/step: ${req.type}/${req.step}`,
    );
  }
  const queued = inbox.drain(identity);
  const out = queued.map((b) => Buffer.from(b).toString("base64"));
  logger?.info(
    { identity, count: out.length },
    "fetch returned envelopes",
  );
  return new TextEncoder().encode(JSON.stringify(newFetchResponse(out)));
}
