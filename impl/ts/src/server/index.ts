/**
 * Server lifecycle. Mirrors impl/go/internal/server/server.go.
 *
 * Composes the SQLite store, the runtime dispatcher, the WS+H2
 * adapters, and the well-known + register HTTP handlers behind one
 * node:http listener.
 *
 * @module
 */

import { createHash } from "node:crypto";
import { createServer, type Server as HttpServer, type IncomingMessage, type ServerResponse } from "node:http";

import { sign as ed25519Sign } from "@sempdev/semp/keys";
import { Forwarder } from "@sempdev/semp/delivery";
import { runServer } from "@sempdev/semp/handshake";
import { dialWS, dialH2Session, type Transport } from "@sempdev/semp/transport";
import type { Logger } from "pino";

import type { Config } from "../config/types.js";
import { ensureDomainKeys, type SuiteId } from "../keygen/index.js";
import { serveClient } from "../runtime/client.js";
import { serveFederation } from "../runtime/federation.js";
import { generateSessionID } from "../runtime/helpers.js";
import {
  initDB,
  SQLiteBlockList,
  SQLiteInbox,
  SQLiteKeyStore,
} from "../store/index.js";
import { fetchDomainSigningKeyFromWellKnown } from "../util/well_known.js";
import { makeBlockListHandler } from "./handlers/blocklist.js";
import { makeDeviceRegisterHandler } from "./handlers/device_register.js";
import { makeRegisterHandler } from "./handlers/register.js";
import {
  makeWellKnownConfigHandler,
  makeWellKnownDomainKeysHandler,
  makeWellKnownKeysHandler,
} from "./handlers/well_known.js";
import { Metrics } from "./metrics.js";
import { newPolicy, type ServerPolicy } from "./policy.js";
import { IPRateLimiter } from "./ratelimit.js";
import { createH2Adapter } from "./transport_h2.js";
import { createWSAdapter } from "./transport_ws.js";

const HandshakePrefix = "SEMP-HANDSHAKE:";
const BASELINE_SUITE = "x25519-chacha20-poly1305" as const;

export interface SempServer {
  start(): Promise<void>;
  close(): Promise<void>;
}

/** Build a SempServer from a parsed config. */
export async function newServer(
  cfg: Config,
  logger: Logger,
): Promise<SempServer> {
  const db = initDB(cfg.database.path);
  const store = new SQLiteKeyStore(db);
  if (cfg.database.master_key !== "") {
    store.setMasterKey(cfg.database.master_key);
    logger.info("private key encryption enabled");
  }

  const suite = cfg.crypto.suite as SuiteId;
  if (suite !== "x25519-chacha20-poly1305" && suite !== "pq-kyber768-x25519") {
    throw new Error(`unknown crypto suite: ${cfg.crypto.suite}`);
  }
  logger.info({ suite: cfg.crypto.suite }, "crypto suite");

  const domainKeys = ensureDomainKeys(store, suite, cfg.domain, logger);

  // Auto-fetch peer signing keys on cache miss.
  store.setDomainKeyFetcher(cfg.domain, (domain) => {
    // Synchronous shim: return null and warn so the runtime falls
    // through to its rejection path. Real fetches need async I/O,
    // which we cannot do in this synchronous callback.
    void domain;
    return null;
  });
  // Async pre-warmer: fetch the signing keys for any peer the
  // operator did not pre-pin and cache them at startup.
  for (const peer of cfg.federation.peers) {
    if (peer.domain_signing_key !== "") {
      try {
        const pub = new Uint8Array(
          Buffer.from(peer.domain_signing_key, "base64"),
        );
        store.putDomainKey(peer.domain, pub);
        logger.info(
          { domain: peer.domain, endpoint: peer.endpoint },
          "registered federation peer (pre-pinned key)",
        );
      } catch (err) {
        throw new Error(
          `decode peer ${peer.domain} signing key: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    } else {
      // Fire-and-forget warm-up; if it fails, runtime will retry.
      void fetchDomainSigningKeyFromWellKnown(peer.domain).then((pub) => {
        if (pub !== null) {
          store.putDomainKey(peer.domain, pub);
          logger.info(
            { domain: peer.domain, fingerprint: hexSha256(pub) },
            "auto-fetched domain signing key",
          );
        } else {
          logger.warn(
            { domain: peer.domain },
            "auto-fetch domain signing key failed",
          );
        }
      });
      logger.info(
        { domain: peer.domain, endpoint: peer.endpoint },
        "registered federation peer",
      );
    }
  }

  const inbox = new SQLiteInbox(db);
  inbox.loadPending();
  const blockList = new SQLiteBlockList(db);
  const metrics = new Metrics();
  const policy = newPolicy(cfg.policy, metrics);

  // Static endpoint map for federation peers.
  const staticEndpoints = new Map<string, string>();
  for (const p of cfg.federation.peers) {
    if (p.endpoint !== "") {
      staticEndpoints.set(p.domain, p.endpoint);
    }
  }
  const endpointResolver = async (peerDomain: string): Promise<string> => {
    const ep = staticEndpoints.get(peerDomain);
    if (ep !== undefined && ep !== "") {
      return ep;
    }
    // Fall back to discovery: assume a well-known endpoint at
    // https://<domain>/v1/h2/federate. Production deployments would
    // hit the discovery resolver here.
    return `https://${peerDomain}/v1/h2/federate`;
  };
  const peerDomainKey = async (peerDomain: string): Promise<Uint8Array> => {
    const local = store.lookupDomainKey(peerDomain);
    if (local !== null) {
      return new Uint8Array(Buffer.from(local.public_key, "base64"));
    }
    const fetched = await fetchDomainSigningKeyFromWellKnown(peerDomain);
    if (fetched !== null) {
      store.putDomainKey(peerDomain, fetched);
      return fetched;
    }
    throw new Error(`no domain key on file for ${peerDomain}`);
  };
  const dial = async (endpoint: string): Promise<Transport> => {
    if (endpoint.startsWith("ws://")) {
      return dialWS(endpoint, { allowInsecure: true });
    }
    if (endpoint.startsWith("wss://")) {
      return dialWS(endpoint);
    }
    return dialH2Session({ sessionUrl: endpoint });
  };
  const forwarder = new Forwarder({
    capabilities: {
      encryption_algorithms: [BASELINE_SUITE],
      extensions: [],
    },
    localDomain: cfg.domain,
    localServerID: cfg.domain,
    localDomainSeed: domainKeys.signPriv,
    endpointResolver,
    peerDomainKey,
    dial,
  });

  // User credentials.
  const users = new Map<string, string>();
  for (const u of cfg.users) {
    users.set(u.address, u.password);
  }
  const registerRL = new IPRateLimiter(10, 60_000);

  const wellKnownDeps = {
    store,
    domain: cfg.domain,
    tlsEnabled: cfg.tls.cert_file !== "" && cfg.tls.key_file !== "",
    externalTLS: cfg.tls.external_tls,
    quicEnabled: cfg.tls.quic_addr !== "",
    advertisedSuites: () => advertisedSuites(cfg.crypto.suite),
    logger,
  };
  const wellKnownConfig = makeWellKnownConfigHandler(wellKnownDeps);
  const wellKnownKeys = makeWellKnownKeysHandler(wellKnownDeps);
  const wellKnownDomainKeys = makeWellKnownDomainKeysHandler(wellKnownDeps);
  const registerHandler = makeRegisterHandler({
    store,
    users,
    domain: cfg.domain,
    rateLimiter: registerRL,
    metrics,
    logger,
  });
  const deviceRegisterHandler = makeDeviceRegisterHandler({
    store,
    users,
    logger,
  });
  const blockListHandler = makeBlockListHandler({
    blockList,
    users,
    logger,
  });
  const metricsHandler = metrics.handler();

  // Per-connection accept callback: hand off to the handshake server,
  // then run the runtime dispatcher.
  const acceptClient = (conn: Transport, peer: string): void => {
    void runClientConnection(conn, peer, {
      domain: cfg.domain,
      domainSignFP: domainKeys.signFP,
      domainSignPriv: domainKeys.signPriv,
      domainEncFP: domainKeys.encFP,
      domainEncPriv: domainKeys.encPriv,
      domainEncPub: domainKeys.encPub,
      suite,
      store,
      inbox,
      blockList,
      forwarder,
      policy,
      logger,
      metrics,
    });
  };
  const acceptFederation = (conn: Transport, peer: string): void => {
    void runFederationConnection(conn, peer, {
      domain: cfg.domain,
      domainSignFP: domainKeys.signFP,
      domainSignPriv: domainKeys.signPriv,
      domainEncFP: domainKeys.encFP,
      domainEncPriv: domainKeys.encPriv,
      domainEncPub: domainKeys.encPub,
      suite,
      store,
      inbox,
      blockList,
      policy,
      logger,
      metrics,
    });
  };

  const ws = createWSAdapter({}, acceptClient);
  const wsFederation = createWSAdapter({}, acceptFederation);
  const h2 = createH2Adapter({}, acceptClient);
  const h2Federation = createH2Adapter({}, acceptFederation);

  let httpServer: HttpServer | null = null;

  const start = async (): Promise<void> => {
    httpServer = createServer((req, res) => {
      const path = (req.url ?? "").split("?")[0] ?? "";
      try {
        switch (path) {
          case "/v1/h2":
            return h2(req, res);
          case "/v1/h2/federate":
            return h2Federation(req, res);
          case "/v1/register":
            return void registerHandler(req, res);
          case "/v1/device/register":
            return void deviceRegisterHandler(req, res);
          case "/.well-known/semp/configuration":
            return wellKnownConfig(req, res);
          case "/.well-known/semp/domain-keys":
            return wellKnownDomainKeys(req, res);
          case "/debug/metrics":
            return metricsHandler(req, res);
        }
        if (path.startsWith("/.well-known/semp/keys/")) {
          return wellKnownKeys(req, res);
        }
        if (path === "/v1/blocklist" || path.startsWith("/v1/blocklist/")) {
          return void blockListHandler(req, res);
        }
        res.statusCode = 404;
        res.end("not found");
      } catch (err) {
        logger.error(
          {
            method: req.method,
            path,
            err: err instanceof Error ? err.message : String(err),
          },
          "panic recovered in HTTP handler",
        );
        if (!res.headersSent) {
          res.statusCode = 500;
          res.end("internal server error");
        }
      }
    });
    httpServer.on("upgrade", (req, socket, head) => {
      const path = (req.url ?? "").split("?")[0] ?? "";
      if (path === "/v1/ws") {
        ws.handleUpgrade(req, socket, head);
        return;
      }
      if (path === "/v1/federate") {
        wsFederation.handleUpgrade(req, socket, head);
        return;
      }
      socket.destroy();
    });

    const { host, port } = parseListenAddr(cfg.listen_addr);
    await new Promise<void>((resolve, reject) => {
      const onListening = (): void => {
        httpServer?.removeListener("error", onError);
        resolve();
      };
      const onError = (err: Error): void => {
        httpServer?.removeListener("listening", onListening);
        reject(err);
      };
      httpServer?.once("listening", onListening);
      httpServer?.once("error", onError);
      httpServer?.listen(port, host);
    });
    logger.info(
      { addr: cfg.listen_addr, domain: cfg.domain },
      "starting HTTP server",
    );
    if (cfg.tls.quic_addr !== "") {
      logger.warn(
        { addr: cfg.tls.quic_addr },
        "quic listener requested but not supported in TS impl",
      );
    }
  };

  const close = async (): Promise<void> => {
    await ws.close();
    await wsFederation.close();
    await forwarder.close();
    if (httpServer !== null) {
      await new Promise<void>((resolve) => {
        httpServer?.close(() => resolve());
      });
    }
    db.close();
  };

  return { start, close };
}

interface ClientConnDeps {
  domain: string;
  domainSignFP: string;
  domainSignPriv: Uint8Array;
  domainEncFP: string;
  domainEncPriv: Uint8Array;
  domainEncPub: Uint8Array;
  suite: SuiteId;
  store: SQLiteKeyStore;
  inbox: SQLiteInbox;
  blockList: SQLiteBlockList;
  forwarder: Forwarder;
  policy: ServerPolicy;
  logger: Logger;
  metrics: Metrics;
}

async function runClientConnection(
  conn: Transport,
  peer: string,
  deps: ClientConnDeps,
): Promise<void> {
  deps.logger.info({ peer }, "client connected");
  try {
    const session = await runServer(conn, {
      serverDomainSigningSeed: deps.domainSignPriv,
      domain: deps.domain,
      supportedSuites: [BASELINE_SUITE],
      identityProofSignature: ({ serverEphemeralKey, clientNonce, serverNonce }) =>
        signIdentityProof(
          deps.domainSignPriv,
          serverEphemeralKey.key,
          clientNonce,
          serverNonce,
        ),
      permissions: deps.policy.permissions(),
      sessionTTL: deps.policy.sessionTTL(),
      generateSessionId: generateSessionID,
    });
    deps.metrics.handshakesSuccess.inc();
    deps.logger.info(
      {
        peer,
        session: session.sessionId,
        ttl: session.sessionTTL,
      },
      "client session established",
    );
    await serveClient({
      suite: deps.suite,
      store: deps.store,
      inbox: deps.inbox,
      forwarder: deps.forwarder,
      blockList: deps.blockList,
      localDomain: deps.domain,
      domainSignFP: deps.domainSignFP,
      domainSignPriv: deps.domainSignPriv,
      domainEncFP: deps.domainEncFP,
      domainEncPriv: deps.domainEncPriv,
      domainEncPub: deps.domainEncPub,
      // The semp-ts driver does not surface the authenticated client
      // identity from the encrypted CONFIRM block; the runtime treats
      // identity-bound features (scope enforcement, fetch routing) as
      // best-effort when this field is empty.
      identity: "",
      deviceKeyId: "",
      session,
      logger: deps.logger,
    });
    deps.logger.info({ peer }, "client disconnected");
  } catch (err) {
    deps.metrics.handshakesFailure.inc();
    deps.logger.error(
      { peer, err: err instanceof Error ? err.message : String(err) },
      "client handshake failed",
    );
  } finally {
    try {
      await conn.close();
    } catch {
      // ignore
    }
  }
}

interface FederationConnDeps {
  domain: string;
  domainSignFP: string;
  domainSignPriv: Uint8Array;
  domainEncFP: string;
  domainEncPriv: Uint8Array;
  domainEncPub: Uint8Array;
  suite: SuiteId;
  store: SQLiteKeyStore;
  inbox: SQLiteInbox;
  blockList: SQLiteBlockList;
  policy: ServerPolicy;
  logger: Logger;
  metrics: Metrics;
}

async function runFederationConnection(
  conn: Transport,
  peer: string,
  deps: FederationConnDeps,
): Promise<void> {
  deps.logger.info({ peer }, "federation peer connected");
  try {
    // The semp-ts FederationResponder fits an "init" → "response" →
    // "confirm" → "accepted" cycle; we can't easily plumb runServer
    // for federation. Use it via the handshake.FederationResponder
    // class. To keep this MVP, we run the same baseline runServer
    // path (the federation inbound side has the same signature
    // interface, since both call into the same domain signing key).
    //
    // For now we treat federation peers as "trusted for development"
    // by running the simpler runServer for federation accept;
    // upgrading to a full federation-handshake path is a follow-up.
    const session = await runServer(conn, {
      serverDomainSigningSeed: deps.domainSignPriv,
      domain: deps.domain,
      supportedSuites: [BASELINE_SUITE],
      identityProofSignature: ({ serverEphemeralKey, clientNonce, serverNonce }) =>
        signIdentityProof(
          deps.domainSignPriv,
          serverEphemeralKey.key,
          clientNonce,
          serverNonce,
        ),
      permissions: ["receive"],
      sessionTTL: 3600,
      generateSessionId: generateSessionID,
    });
    deps.logger.info(
      {
        peer,
        session: session.sessionId,
        ttl: session.sessionTTL,
      },
      "federation session established",
    );
    await serveFederation({
      suite: deps.suite,
      store: deps.store,
      inbox: deps.inbox,
      blockList: deps.blockList,
      localDomain: deps.domain,
      domainSignFP: deps.domainSignFP,
      domainSignPriv: deps.domainSignPriv,
      domainEncFP: deps.domainEncFP,
      domainEncPriv: deps.domainEncPriv,
      domainEncPub: deps.domainEncPub,
      identity: peer,
      session,
      logger: deps.logger,
    });
    deps.logger.info({ peer }, "federation peer disconnected");
  } catch (err) {
    deps.metrics.federationFailure.inc();
    deps.logger.error(
      { peer, err: err instanceof Error ? err.message : String(err) },
      "federation handshake failed",
    );
  } finally {
    try {
      await conn.close();
    } catch {
      // ignore
    }
  }
}

const BASELINE_SUITE_PROTOCOL = "semp.v1";

function signIdentityProof(
  seed: Uint8Array,
  serverEphPubB64: string,
  clientNonceB64: string,
  serverNonceB64: string,
): string {
  const serverEphPub = Buffer.from(serverEphPubB64, "base64");
  const clientNonce = Buffer.from(clientNonceB64, "base64");
  const serverNonce = Buffer.from(serverNonceB64, "base64");
  const prefix = new TextEncoder().encode("SEMP-IDENTITY:");
  const total = prefix.length + serverEphPub.length + serverNonce.length + clientNonce.length;
  const buf = new Uint8Array(total);
  let off = 0;
  buf.set(prefix, off);
  off += prefix.length;
  buf.set(serverEphPub, off);
  off += serverEphPub.length;
  buf.set(serverNonce, off);
  off += serverNonce.length;
  buf.set(clientNonce, off);
  const sig = ed25519Sign(seed, buf);
  return Buffer.from(sig).toString("base64");
}

function advertisedSuites(suite: string): string[] {
  if (suite === BASELINE_SUITE) {
    return [BASELINE_SUITE];
  }
  return [suite, BASELINE_SUITE];
}

function hexSha256(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

function parseListenAddr(addr: string): { host: string; port: number } {
  // Accept ":port", "host:port", or "[::]:port" forms.
  if (addr.startsWith(":")) {
    return { host: "0.0.0.0", port: Number(addr.slice(1)) };
  }
  const lastColon = addr.lastIndexOf(":");
  if (lastColon < 0) {
    return { host: "0.0.0.0", port: Number(addr) };
  }
  return {
    host: addr.slice(0, lastColon),
    port: Number(addr.slice(lastColon + 1)),
  };
}

void HandshakePrefix;
