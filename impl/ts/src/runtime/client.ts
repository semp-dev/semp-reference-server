/**
 * Client-side post-handshake dispatch loop. Mirrors
 * impl/go/internal/runtime/client.go.
 *
 * @module
 */

import { runDispatcher, type Session } from "@sempdev/semp/session";
import type { Forwarder } from "@sempdev/semp/delivery";
import type { Logger } from "pino";

import { handleClientSubmission } from "./envelope.js";
import { handleFetch } from "./fetch.js";
import { handleClientKeys } from "./keys.js";
import { handleRekeyFrame } from "./rekey.js";
import type { SQLiteKeyStore } from "../store/keys.js";
import type { SQLiteInbox } from "../store/inbox.js";
import type { SQLiteBlockList } from "../store/blocklist.js";

export interface ClientDeps {
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

/** Run the post-handshake message loop against `session`. */
export async function serveClient(deps: ClientDeps): Promise<void> {
  await runDispatcher(deps.session, {
    onEnvelope: async (frame) => {
      const out = await handleClientSubmission(frame, {
        suite: deps.suite,
        store: deps.store,
        inbox: deps.inbox,
        forwarder: deps.forwarder,
        blockList: deps.blockList,
        localDomain: deps.localDomain,
        domainSignFP: deps.domainSignFP,
        domainSignPriv: deps.domainSignPriv,
        domainEncFP: deps.domainEncFP,
        domainEncPriv: deps.domainEncPriv,
        domainEncPub: deps.domainEncPub,
        identity: deps.identity,
        deviceKeyId: deps.deviceKeyId,
        session: deps.session,
        logger: deps.logger,
      });
      await deps.session.send(out);
    },
    onKeys: async (frame) => {
      const out = await handleClientKeys(frame, {
        store: deps.store,
        localDomain: deps.localDomain,
        domainSignFP: deps.domainSignFP,
        domainSignPriv: deps.domainSignPriv,
        forwarder: deps.forwarder,
      });
      await deps.session.send(out);
    },
    onRekey: async (frame) => {
      const out = await handleRekeyFrame(
        deps.session,
        frame,
        deps.identity,
        deps.logger,
      );
      await deps.session.send(out);
    },
    onFetch: async (frame) => {
      const out = handleFetch(
        frame,
        deps.inbox.memInbox(),
        deps.identity,
        deps.logger,
      );
      await deps.session.send(out);
    },
    onUnknown: async (type) => {
      deps.logger?.warn({ type }, "unknown client message type");
    },
    onHandlerError: (err, type) => {
      deps.logger?.warn(
        { identity: deps.identity, type, err: err.message },
        "client dispatch handler error",
      );
    },
    onFatal: (err) => {
      deps.logger?.warn(
        { identity: deps.identity, err: err.message },
        "client dispatch fatal error",
      );
    },
  });
}
