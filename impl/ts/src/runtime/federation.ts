/**
 * Federation post-handshake dispatch loop. Mirrors
 * impl/go/internal/runtime/federation.go.
 *
 * @module
 */

import { runDispatcher, type Session } from "@sempdev/semp/session";
import type { Logger } from "pino";

import { handleFederationSubmission } from "./envelope.js";
import { handleFederationKeys } from "./keys.js";
import { handleRekeyFrame } from "./rekey.js";
import type { SQLiteKeyStore } from "../store/keys.js";
import type { SQLiteInbox } from "../store/inbox.js";
import type { SQLiteBlockList } from "../store/blocklist.js";

export interface FederationDeps {
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

/** Run the post-handshake message loop against an inbound peer. */
export async function serveFederation(deps: FederationDeps): Promise<void> {
  await runDispatcher(deps.session, {
    onEnvelope: async (frame) => {
      const out = await handleFederationSubmission(frame, {
        suite: deps.suite,
        store: deps.store,
        inbox: deps.inbox,
        blockList: deps.blockList,
        localDomain: deps.localDomain,
        domainSignFP: deps.domainSignFP,
        domainSignPriv: deps.domainSignPriv,
        domainEncFP: deps.domainEncFP,
        domainEncPriv: deps.domainEncPriv,
        domainEncPub: deps.domainEncPub,
        identity: deps.identity,
        session: deps.session,
        logger: deps.logger,
      });
      await deps.session.send(out);
    },
    onKeys: async (frame) => {
      const out = handleFederationKeys(frame, {
        store: deps.store,
        localDomain: deps.localDomain,
        domainSignFP: deps.domainSignFP,
        domainSignPriv: deps.domainSignPriv,
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
    onHandlerError: (err, type) => {
      deps.logger?.warn(
        { peer: deps.identity, type, err: err.message },
        "federation dispatch handler error",
      );
    },
    onFatal: (err) => {
      deps.logger?.warn(
        { peer: deps.identity, err: err.message },
        "federation dispatch fatal error",
      );
    },
  });
}
