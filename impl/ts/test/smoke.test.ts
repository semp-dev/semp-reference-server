/**
 * Vitest smoke test. Mirrors impl/go/internal/runtime/smoke_test.go:
 * the dispatcher returns cleanly when the peer end of the transport
 * pair closes.
 */

import { describe, it, expect } from "vitest";

import { newMemoryPair } from "@sempdev/semp/transport";
import { Session } from "@sempdev/semp/session";
import { newHKDFSHA512, deriveSessionKeysWithResumption } from "@sempdev/semp/crypto";

import { serveClient } from "../src/runtime/client.js";
import { serveFederation } from "../src/runtime/federation.js";
import { initDB, SQLiteBlockList, SQLiteInbox, SQLiteKeyStore } from "../src/store/index.js";

function buildSession(transport: Parameters<typeof newSession>[0]): ReturnType<typeof newSession> {
  return newSession(transport);
}

function newSession(transport: Parameters<typeof Session.prototype.send> extends [unknown] ? never : never): never {
  // placeholder: the real shim is below.
  throw new Error("unreachable");
}

function makeServerSession(transport: ReturnType<typeof newMemoryPair>[0]) {
  // Derive arbitrary session keys for a local-only Session. The keys
  // never travel the wire because the dispatcher closes immediately.
  const shared = new Uint8Array(32);
  const cn = new Uint8Array(32);
  const sn = new Uint8Array(32);
  const keys = deriveSessionKeysWithResumption(newHKDFSHA512(), shared, cn, sn);
  return new Session({
    role: "server",
    sessionId: "TEST-SMOKE-SESSION",
    sessionTTL: 60,
    establishedAt: new Date(),
    permissions: ["send", "receive"],
    keys,
    transport,
    extensions: {},
  });
}

describe("runtime smoke", () => {
  it("serveClient returns when the transport closes", async () => {
    const [server, client] = newMemoryPair();
    const db = initDB(":memory:");
    const store = new SQLiteKeyStore(db);
    const inbox = new SQLiteInbox(db);
    const blockList = new SQLiteBlockList(db);
    const session = makeServerSession(server);

    const completed = serveClient({
      suite: "x25519-chacha20-poly1305",
      store,
      inbox,
      forwarder: null,
      blockList,
      localDomain: "test.example",
      domainSignFP: "",
      domainSignPriv: new Uint8Array(),
      domainEncFP: "",
      domainEncPriv: new Uint8Array(),
      domainEncPub: new Uint8Array(),
      identity: "alice@test.example",
      deviceKeyId: "",
      session,
      logger: null,
    });

    await client.close();
    await completed;
    db.close();
    // assertion: the dispatcher returned cleanly.
    expect(true).toBe(true);
  });

  it("serveFederation returns when the transport closes", async () => {
    const [server, peer] = newMemoryPair();
    const db = initDB(":memory:");
    const store = new SQLiteKeyStore(db);
    const inbox = new SQLiteInbox(db);
    const blockList = new SQLiteBlockList(db);
    const session = makeServerSession(server);

    const completed = serveFederation({
      suite: "x25519-chacha20-poly1305",
      store,
      inbox,
      blockList,
      localDomain: "test.example",
      domainSignFP: "",
      domainSignPriv: new Uint8Array(),
      domainEncFP: "",
      domainEncPriv: new Uint8Array(),
      domainEncPub: new Uint8Array(),
      identity: "peer.example",
      session,
      logger: null,
    });

    await peer.close();
    await completed;
    db.close();
    expect(true).toBe(true);
  });
});

void buildSession;
