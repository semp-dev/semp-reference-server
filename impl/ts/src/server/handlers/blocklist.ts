/**
 * GET/POST/DELETE /v1/blocklist[/...] handlers. Mirrors handleBlockList
 * in impl/go/internal/server/handlers.go.
 *
 * @module
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import type {
  BlockEntry,
  BlocklistEntity,
  BlocklistEntityType,
  BlocklistScope,
} from "@sempdev/semp/delivery";
import type { Logger } from "pino";

import type { SQLiteBlockList } from "../../store/blocklist.js";

const MAX_BODY = 1 << 20;

interface AddRequest {
  user_id?: string;
  entity_type?: string;
  entity_value?: string;
  acknowledgment?: string;
  reason?: string;
  scope?: string;
}

export interface BlockListDeps {
  blockList: SQLiteBlockList;
  users: Map<string, string>;
  logger: Logger;
}

export function makeBlockListHandler(deps: BlockListDeps) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(
      req.url ?? "/",
      `http://${req.headers.host ?? "localhost"}`,
    );
    switch (req.method) {
      case "GET":
        return getBlockList(req, res, url, deps);
      case "POST":
        return postBlockList(req, res, deps);
      case "DELETE":
        return deleteBlockList(req, res, url, deps);
      default:
        res.statusCode = 405;
        res.end("method not allowed");
    }
  };
}

async function getBlockList(
  _req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  deps: BlockListDeps,
): Promise<void> {
  const address = url.searchParams.get("address") ?? "";
  if (address === "") {
    res.statusCode = 400;
    res.end("missing address parameter");
    return;
  }
  const password = url.searchParams.get("password") ?? "";
  const expected = deps.users.get(address);
  if (expected === undefined || password !== expected) {
    res.statusCode = 401;
    res.end("unauthorized");
    return;
  }
  try {
    const entries = await deps.blockList.listEntries(address);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.statusCode = 200;
    res.end(JSON.stringify(entries));
  } catch {
    res.statusCode = 500;
    res.end("internal error");
  }
}

async function postBlockList(
  req: IncomingMessage,
  res: ServerResponse,
  deps: BlockListDeps,
): Promise<void> {
  let body: Uint8Array;
  try {
    body = await readLimited(req, MAX_BODY);
  } catch {
    res.statusCode = 400;
    res.end("invalid request");
    return;
  }
  let parsed: AddRequest;
  try {
    parsed = JSON.parse(new TextDecoder().decode(body)) as AddRequest;
  } catch {
    res.statusCode = 400;
    res.end("invalid request");
    return;
  }
  if (
    parsed.user_id === undefined ||
    parsed.user_id === "" ||
    parsed.entity_type === undefined ||
    parsed.entity_type === "" ||
    parsed.entity_value === undefined ||
    parsed.entity_value === ""
  ) {
    res.statusCode = 400;
    res.end("user_id, entity_type, and entity_value are required");
    return;
  }
  const ack =
    parsed.acknowledgment === "delivered" ||
    parsed.acknowledgment === "rejected" ||
    parsed.acknowledgment === "silent"
      ? parsed.acknowledgment
      : "rejected";
  const scope: BlocklistScope =
    parsed.scope === "all" ||
    parsed.scope === "direct" ||
    parsed.scope === "group"
      ? parsed.scope
      : "all";
  const entity: BlocklistEntity = {
    type: parsed.entity_type as BlocklistEntityType,
  };
  switch (entity.type) {
    case "user":
      entity.address = parsed.entity_value;
      break;
    case "domain":
      entity.domain = parsed.entity_value;
      break;
    case "server":
      entity.hostname = parsed.entity_value;
      break;
  }
  const entry: BlockEntry = {
    id: "",
    entity,
    acknowledgment: ack,
    ...(parsed.reason !== undefined && parsed.reason !== ""
      ? { reason: parsed.reason }
      : {}),
    scope,
    created_at: isoNow(),
    created_by_device_id: "",
  };
  try {
    const id = deps.blockList.addEntry(parsed.user_id, entry);
    deps.logger.info(
      { user: parsed.user_id, entity: parsed.entity_value, id },
      "block entry added",
    );
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.statusCode = 200;
    res.end(JSON.stringify({ id, status: "added" }));
  } catch {
    res.statusCode = 500;
    res.end("internal error");
  }
}

async function deleteBlockList(
  _req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  deps: BlockListDeps,
): Promise<void> {
  const id = url.pathname.replace(/^\/v1\/blocklist\/?/, "");
  if (id === "" || id === url.pathname) {
    res.statusCode = 400;
    res.end("missing entry ID");
    return;
  }
  try {
    deps.blockList.removeEntry(id);
    deps.logger.info({ id }, "block entry removed");
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.statusCode = 200;
    res.end(JSON.stringify({ status: "removed" }));
  } catch {
    res.statusCode = 500;
    res.end("internal error");
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
    req.on("end", () => resolve(new Uint8Array(Buffer.concat(chunks))));
    req.on("error", reject);
  });
}

function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
