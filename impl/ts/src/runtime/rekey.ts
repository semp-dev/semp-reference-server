/**
 * Inline rekey responder for the dispatcher loop. The semp-ts
 * `rekeyServer` driver reads its own bytes off the transport, which
 * doesn't fit the dispatcher's "frame in, frame out" shape. This
 * helper runs the rekey responder against a frame the dispatcher has
 * already pulled.
 *
 * @module
 */

import { randomBytes } from "node:crypto";

import {
  deriveRekeyKeys,
  newHKDFSHA512,
  x25519Agree,
  x25519PublicKey,
} from "@sempdev/semp/crypto";
import { fingerprint } from "@sempdev/semp/keys";
import {
  openRekeyMessage,
  sealRekeyMessage,
  type Session,
  type SealedRekey,
} from "@sempdev/semp/session";
import { marshal as canonicalMarshal } from "@sempdev/semp/canonical";
import type { Logger } from "pino";

import { generateSessionID } from "./helpers.js";

interface RekeyInit {
  type: "SEMP_REKEY";
  step: "rekey-init";
  version: "1.0.0";
  session_id: string;
  new_ephemeral_key: { algorithm: string; key: string; key_id: string };
  rekey_nonce: string;
}

interface RekeyAccepted {
  type: "SEMP_REKEY";
  step: "rekey-accepted";
  version: "1.0.0";
  session_id: string;
  new_session_id: string;
  new_ephemeral_key: { algorithm: string; key: string; key_id: string };
  rekey_nonce: string;
  responder_nonce: string;
}

/**
 * Process one inbound SEMP_REKEY frame and return the bytes to send
 * back. Updates the session in-place via {@link Session.applyRekey}.
 */
export async function handleRekeyFrame(
  session: Session,
  frame: Uint8Array,
  identity: string,
  logger: Logger | null,
): Promise<Uint8Array> {
  const wrapper = JSON.parse(new TextDecoder().decode(frame)) as SealedRekey;
  if (wrapper.type !== "SEMP_REKEY") {
    throw new Error(`rekey: expected SEMP_REKEY, got ${wrapper.type}`);
  }
  const initDir = directionFromRole(otherRole(session.role));
  const respDir = otherDirection(initDir);
  if (wrapper.direction !== initDir) {
    throw new Error(
      `rekey: expected init direction=${initDir}, got ${wrapper.direction}`,
    );
  }
  const initPlain = openRekeyMessage(session, wrapper);
  const init = JSON.parse(new TextDecoder().decode(initPlain)) as RekeyInit;
  if (init.step !== "rekey-init") {
    throw new Error(`rekey: expected step=rekey-init, got ${init.step}`);
  }

  const ephPriv = randomBytes(32);
  const ephPub = x25519PublicKey(ephPriv);
  const responderNonce = randomBytes(32);
  const newSessionId = generateSessionID();
  const initiatorPub = base64Decode(init.new_ephemeral_key.key);
  const rekeyNonce = base64Decode(init.rekey_nonce);
  const sharedSecret = x25519Agree(ephPriv, initiatorPub);
  const kdf = newHKDFSHA512();
  const newKeys = deriveRekeyKeys(kdf, sharedSecret, rekeyNonce, responderNonce);

  const accepted: RekeyAccepted = {
    type: "SEMP_REKEY",
    step: "rekey-accepted",
    version: "1.0.0",
    session_id: session.sessionId,
    new_session_id: newSessionId,
    new_ephemeral_key: {
      algorithm: "x25519-chacha20-poly1305",
      key: base64Encode(ephPub),
      key_id: fingerprint(ephPub),
    },
    rekey_nonce: init.rekey_nonce,
    responder_nonce: base64Encode(responderNonce),
  };
  const sealed = sealRekeyMessage(
    session,
    respDir,
    canonicalMarshal(accepted as unknown as Record<string, unknown>),
  );
  const out = new TextEncoder().encode(JSON.stringify(sealed));

  session.applyRekey({ newSessionId, newKeys });
  logger?.info(
    { identity, session: session.sessionId },
    "rekey ok",
  );
  return out;
}

function directionFromRole(role: "client" | "server"): "c2s" | "s2c" {
  return role === "client" ? "c2s" : "s2c";
}

function otherDirection(d: "c2s" | "s2c"): "c2s" | "s2c" {
  return d === "c2s" ? "s2c" : "c2s";
}

function otherRole(r: "client" | "server"): "client" | "server" {
  return r === "client" ? "server" : "client";
}

function base64Encode(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

function base64Decode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}
