/**
 * WebSocket transport adapter. Wraps the `ws` library's WebSocketServer
 * upgrade flow and exposes each accepted connection as a SEMP
 * Transport.
 *
 * Mirrors impl/go/internal/server/transport_ws.go.
 *
 * @module
 */

import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";

import { WebSocketServer, type WebSocket } from "ws";

import type { Transport } from "@sempdev/semp/transport";

const SempSubprotocol = "semp.v1";

/** Default cap for inbound message size (25 MiB per spec). */
export const DefaultMaxEnvelopeSize = 25 * 1024 * 1024;

export interface WSAdapterConfig {
  maxPayload?: number;
}

/**
 * Create a noServer WebSocketServer plus an upgrade handler. The
 * returned `handleUpgrade` is meant to be wired to a path-routing
 * dispatch on the HTTP server (see server/index.ts).
 */
export function createWSAdapter(
  config: WSAdapterConfig,
  accept: (transport: Transport, peer: string) => void,
): {
  handleUpgrade: (req: IncomingMessage, socket: Duplex, head: Buffer) => void;
  close: () => Promise<void>;
} {
  const wss = new WebSocketServer({
    noServer: true,
    handleProtocols: (protocols) => {
      if (protocols.has(SempSubprotocol)) {
        return SempSubprotocol;
      }
      return false;
    },
    maxPayload: config.maxPayload ?? DefaultMaxEnvelopeSize,
  });

  const handleUpgrade = (
    req: IncomingMessage,
    socket: Duplex,
    head: Buffer,
  ): void => {
    wss.handleUpgrade(req, socket, head, (ws) => {
      if (ws.protocol !== SempSubprotocol) {
        ws.close(1008, "subprotocol not confirmed");
        return;
      }
      const peer = req.socket.remoteAddress ?? "";
      const transport = new WSConn(ws, peer);
      accept(transport, peer);
    });
  };

  const close = async (): Promise<void> => {
    await new Promise<void>((resolve) => {
      wss.close(() => resolve());
    });
  };

  return { handleUpgrade, close };
}

/**
 * Server-side {@link Transport} backed by a single WebSocket connection.
 * Text frames only; binary frames are rejected.
 */
class WSConn implements Transport {
  private readonly ws: WebSocket;
  private readonly peerAddr: string;
  private inboxQueue: (Uint8Array | null)[] = [];
  private waiters: Array<{
    resolve: (v: Uint8Array | null) => void;
    reject: (err: Error) => void;
  }> = [];
  private closed = false;
  private terminalError: Error | null = null;

  constructor(ws: WebSocket, peerAddr: string) {
    this.ws = ws;
    this.peerAddr = peerAddr;
    ws.on("message", (data, isBinary) => {
      if (isBinary) {
        this.fail(new Error("ws: unexpected binary frame"));
        ws.close(1003, "SEMP requires text frames");
        return;
      }
      const buf = Buffer.isBuffer(data)
        ? new Uint8Array(data)
        : new Uint8Array(Buffer.from(String(data), "utf8"));
      this.deliver(buf);
    });
    ws.on("close", () => {
      this.closed = true;
      this.deliver(null);
    });
    ws.on("error", (err) => {
      this.fail(err);
    });
  }

  send(message: Uint8Array): Promise<void> {
    if (this.closed) {
      return Promise.reject(new Error("ws: send after close"));
    }
    return new Promise<void>((resolve, reject) => {
      this.ws.send(Buffer.from(message), { binary: false }, (err) => {
        // The `ws` library calls back with null on success and an
        // Error on failure. Earlier code used `err !== undefined`,
        // which rejected on null too.
        if (err !== undefined && err !== null) {
          reject(err);
          return;
        }
        resolve();
      });
    });
  }

  receive(): Promise<Uint8Array | null> {
    if (this.terminalError !== null) {
      return Promise.reject(this.terminalError);
    }
    if (this.inboxQueue.length > 0) {
      const next = this.inboxQueue.shift() as Uint8Array | null;
      return Promise.resolve(next);
    }
    if (this.closed) {
      return Promise.resolve(null);
    }
    return new Promise<Uint8Array | null>((resolve, reject) => {
      this.waiters.push({ resolve, reject });
    });
  }

  close(): Promise<void> {
    if (!this.closed) {
      this.closed = true;
      try {
        this.ws.close(1000, "");
      } catch {
        // already closing
      }
    }
    this.deliver(null);
    return Promise.resolve();
  }

  /** Peer address (the client's RemoteAddr). */
  peer(): string {
    return this.peerAddr;
  }

  private deliver(msg: Uint8Array | null): void {
    if (this.waiters.length > 0) {
      const w = this.waiters.shift();
      w?.resolve(msg);
      return;
    }
    this.inboxQueue.push(msg);
  }

  private fail(err: Error): void {
    this.terminalError = err;
    const drained = this.waiters;
    this.waiters = [];
    for (const w of drained) {
      w.reject(err);
    }
  }
}
