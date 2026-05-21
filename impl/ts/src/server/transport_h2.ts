/**
 * HTTP/1.1+ POST adapter that emulates the SEMP turn-based H2
 * transport. Each POST is one Recv -> Send cycle on the per-session
 * virtual transport identified by `Semp-Session-Id`.
 *
 * Mirrors impl/go/internal/server/transport_h2.go.
 *
 * @module
 */

import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import type { Transport } from "@sempdev/semp/transport";

/** Header name used to thread the per-session id across POSTs. */
export const SempSessionIdHeader = "semp-session-id";

/** Content-Type header value the server emits. */
export const H2ContentType = "application/json";

/** Default cap for inbound POST body size (25 MiB per spec). */
export const DefaultMaxBodyBytes = 25 * 1024 * 1024;

/** Default idle timeout: close virtual sessions after 60s with no POST. */
export const DefaultIdleTimeoutMs = 60 * 1000;

export interface H2AdapterConfig {
  maxBodyBytes?: number;
  idleTimeoutMs?: number;
}

/**
 * Create a request handler + a registry of in-flight virtual sessions.
 * The handler returned satisfies node:http's `(req, res)` shape.
 */
export function createH2Adapter(
  config: H2AdapterConfig,
  accept: (transport: Transport, peer: string) => void,
): (req: IncomingMessage, res: ServerResponse) => void {
  const maxBody = config.maxBodyBytes ?? DefaultMaxBodyBytes;
  const idleTimeout = config.idleTimeoutMs ?? DefaultIdleTimeoutMs;
  const sessions = new Map<string, H2VirtualConn>();

  return (req, res) => {
    if (req.method !== "POST") {
      res.statusCode = 405;
      res.end("method not allowed");
      return;
    }
    const contentLength = req.headers["content-length"];
    if (contentLength !== undefined) {
      const len = Number(contentLength);
      if (Number.isFinite(len) && len > maxBody) {
        res.statusCode = 413;
        res.end("payload too large");
        return;
      }
    }
    readLimited(req, maxBody)
      .then(async (body) => {
        const sidHeader = req.headers[SempSessionIdHeader];
        const sid = typeof sidHeader === "string" ? sidHeader : "";
        let vc: H2VirtualConn | undefined;
        let usedSid = sid;
        if (sid === "") {
          usedSid = newSessionId();
          vc = new H2VirtualConn(
            usedSid,
            req.socket.remoteAddress ?? "",
            idleTimeout,
            (id) => sessions.delete(id),
          );
          sessions.set(usedSid, vc);
          accept(vc, vc.peer());
        } else {
          vc = sessions.get(sid);
          if (vc === undefined) {
            res.statusCode = 404;
            res.end("unknown session");
            return;
          }
        }
        vc.touch();

        const turn = vc.enqueue(body);
        try {
          const reply = await turn;
          res.setHeader("Content-Type", H2ContentType);
          res.setHeader(SempSessionIdHeader, usedSid);
          res.statusCode = 200;
          res.end(Buffer.from(reply));
        } catch (err) {
          res.statusCode = 500;
          res.end(err instanceof Error ? err.message : String(err));
        }
      })
      .catch((err) => {
        res.statusCode = 400;
        res.end(`read body: ${err instanceof Error ? err.message : String(err)}`);
      });
  };
}

interface H2Turn {
  body: Uint8Array;
  resolve: (reply: Uint8Array) => void;
  reject: (err: Error) => void;
}

/**
 * Server-side per-session virtual {@link Transport}. Each POST adds one
 * turn; the accept callback drives Recv/Send and the HTTP handler
 * waits for the matching reply.
 */
class H2VirtualConn implements Transport {
  private readonly sessionId: string;
  private readonly peerAddr: string;
  private readonly idleTimeoutMs: number;
  private readonly onClose: (sid: string) => void;
  private idleTimer: NodeJS.Timeout | null = null;
  private closed = false;
  private terminalError: Error | null = null;

  private turnQueue: H2Turn[] = [];
  private receiveWaiters: Array<{
    resolve: (v: Uint8Array | null) => void;
    reject: (err: Error) => void;
  }> = [];
  private pending: H2Turn | null = null;

  constructor(
    sessionId: string,
    peer: string,
    idleTimeoutMs: number,
    onClose: (sid: string) => void,
  ) {
    this.sessionId = sessionId;
    this.peerAddr = peer;
    this.idleTimeoutMs = idleTimeoutMs;
    this.onClose = onClose;
    this.resetIdleTimer();
  }

  /** Add a new POST body to the queue. Returns a promise for the reply. */
  enqueue(body: Uint8Array): Promise<Uint8Array> {
    return new Promise<Uint8Array>((resolve, reject) => {
      const turn: H2Turn = { body, resolve, reject };
      if (this.receiveWaiters.length > 0) {
        const w = this.receiveWaiters.shift();
        this.pending = turn;
        w?.resolve(turn.body);
        return;
      }
      this.turnQueue.push(turn);
    });
  }

  /** Update the idle timer. */
  touch(): void {
    this.resetIdleTimer();
  }

  send(message: Uint8Array): Promise<void> {
    if (this.closed) {
      return Promise.reject(new Error("h2: virtual conn closed"));
    }
    if (this.pending === null) {
      return Promise.reject(
        new Error("h2: Send called without a pending POST"),
      );
    }
    const t = this.pending;
    this.pending = null;
    t.resolve(message);
    return Promise.resolve();
  }

  receive(): Promise<Uint8Array | null> {
    if (this.terminalError !== null) {
      return Promise.reject(this.terminalError);
    }
    // Abandon any prior pending turn whose Send was never called.
    if (this.pending !== null) {
      this.pending.reject(
        new Error("h2: accept callback abandoned previous turn"),
      );
      this.pending = null;
    }
    if (this.turnQueue.length > 0) {
      const t = this.turnQueue.shift() as H2Turn;
      this.pending = t;
      return Promise.resolve(t.body);
    }
    if (this.closed) {
      return Promise.resolve(null);
    }
    return new Promise<Uint8Array | null>((resolve, reject) => {
      this.receiveWaiters.push({ resolve, reject });
    });
  }

  close(): Promise<void> {
    if (this.closed) {
      return Promise.resolve();
    }
    this.closed = true;
    if (this.idleTimer !== null) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
    const closedErr = new Error("h2: virtual conn closed");
    if (this.pending !== null) {
      this.pending.reject(closedErr);
      this.pending = null;
    }
    for (const t of this.turnQueue) {
      t.reject(closedErr);
    }
    this.turnQueue = [];
    const drained = this.receiveWaiters;
    this.receiveWaiters = [];
    for (const w of drained) {
      w.resolve(null);
    }
    this.onClose(this.sessionId);
    return Promise.resolve();
  }

  /** Peer address. */
  peer(): string {
    return this.peerAddr;
  }

  private resetIdleTimer(): void {
    if (this.idleTimeoutMs <= 0) {
      return;
    }
    if (this.idleTimer !== null) {
      clearTimeout(this.idleTimer);
    }
    this.idleTimer = setTimeout(() => {
      void this.close();
    }, this.idleTimeoutMs);
  }
}

async function readLimited(
  req: IncomingMessage,
  max: number,
): Promise<Uint8Array> {
  return new Promise<Uint8Array>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > max) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      resolve(new Uint8Array(Buffer.concat(chunks)));
    });
    req.on("error", reject);
  });
}

const SESSION_ID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function newSessionId(): string {
  // ULID-shaped 26-char Crockford base32 string.
  const raw = randomBytes(16);
  const ms = BigInt(Date.now());
  raw[0] = Number((ms >> 40n) & 0xffn);
  raw[1] = Number((ms >> 32n) & 0xffn);
  raw[2] = Number((ms >> 24n) & 0xffn);
  raw[3] = Number((ms >> 16n) & 0xffn);
  raw[4] = Number((ms >> 8n) & 0xffn);
  raw[5] = Number(ms & 0xffn);
  let high = 0n;
  for (let i = 0; i < 8; i++) {
    high = (high << 8n) | BigInt(raw[i] ?? 0);
  }
  let low = 0n;
  for (let i = 8; i < 16; i++) {
    low = (low << 8n) | BigInt(raw[i] ?? 0);
  }
  const out: string[] = new Array(26);
  for (let i = 25; i >= 13; i--) {
    out[i] = SESSION_ID_ALPHABET[Number(low & 31n)] ?? "0";
    low >>= 5n;
  }
  for (let i = 12; i >= 0; i--) {
    out[i] = SESSION_ID_ALPHABET[Number(high & 31n)] ?? "0";
    high >>= 5n;
  }
  return out.join("");
}
