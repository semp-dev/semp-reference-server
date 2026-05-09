/**
 * Domain key bootstrap. Mirrors impl/go/internal/keygen/keygen.go.
 *
 * The first time the server starts, it generates a domain signing
 * (Ed25519) keypair and a domain encryption keypair (X25519 for the
 * baseline suite, Kyber768+X25519 hybrid for the PQ suite). The
 * private keys are persisted via {@link SQLiteKeyStore}; if a master
 * key is configured they are encrypted at rest.
 *
 * @module
 */

import { randomBytes } from "node:crypto";

import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import {
  Kyber768PrivateKeySize,
  Kyber768PublicKeySize,
  X25519Size,
  x25519PublicKey,
} from "@sempdev/semp/crypto";
import type { Logger } from "pino";

import { SQLiteKeyStore } from "../store/keys.js";

export type SuiteId = "x25519-chacha20-poly1305" | "pq-kyber768-x25519";

export interface DomainKeyMaterial {
  signFP: string;
  signPriv: Uint8Array;
  encFP: string;
  encPriv: Uint8Array;
  encPub: Uint8Array;
}

/**
 * Load existing domain keys for `domain`, or generate + persist a new
 * pair when the store has none. The returned bytes are plaintext;
 * encryption at rest is handled inside the store.
 */
export function ensureDomainKeys(
  store: SQLiteKeyStore,
  suite: SuiteId,
  domain: string,
  logger: Logger,
): DomainKeyMaterial {
  if (store.hasDomainKeys(domain)) {
    const sign = store.loadDomainPrivateKey(domain, "signing");
    if (sign === null) {
      throw new Error(`keygen: signing private key missing for ${domain}`);
    }
    const enc = store.loadDomainPrivateKey(domain, "encryption");
    if (enc === null) {
      throw new Error(`keygen: encryption private key missing for ${domain}`);
    }
    const encPub = store.loadDomainPublicKey(domain, "encryption");
    if (encPub === null) {
      throw new Error(`keygen: encryption public key missing for ${domain}`);
    }
    logger.info(
      { domain, sign_fp: sign.keyId, enc_fp: enc.keyId },
      "loaded existing domain keys",
    );
    return {
      signFP: sign.keyId,
      signPriv: sign.priv,
      encFP: enc.keyId,
      encPriv: enc.priv,
      encPub: encPub.pub,
    };
  }

  // Generate signing key (Ed25519). semp-go publishes the 32-byte
  // SECRET seed as the "private key"; @noble/curves/ed25519 follows
  // the same convention.
  const signSeed = randomBytes(32);
  const signPub = ed25519.getPublicKey(signSeed);
  const signFP = store.putDomainKeyPair(
    domain,
    "signing",
    "ed25519",
    signPub,
    signSeed,
  );

  // Generate encryption key per suite.
  const enc = generateKEMKeyPair(suite);
  const encFP = store.putDomainKeyPair(
    domain,
    "encryption",
    suite,
    enc.publicKey,
    enc.privateKey,
  );

  logger.info(
    { domain, sign_fp: signFP, enc_fp: encFP },
    "generated new domain keys",
  );
  return {
    signFP,
    signPriv: signSeed,
    encFP,
    encPriv: enc.privateKey,
    encPub: enc.publicKey,
  };
}

interface KEMKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

function generateKEMKeyPair(suite: SuiteId): KEMKeyPair {
  switch (suite) {
    case "x25519-chacha20-poly1305": {
      const priv = randomBytes(X25519Size);
      const pub = x25519PublicKey(priv);
      return { privateKey: priv, publicKey: pub };
    }
    case "pq-kyber768-x25519": {
      // ML-KEM-768 keygen takes a 64-byte seed (d || z).
      const seed = randomBytes(64);
      const k = ml_kem768.keygen(seed);
      const xPriv = randomBytes(X25519Size);
      const xPub = x25519PublicKey(xPriv);
      // Wire layout per ENVELOPE.md §4.4.1: kyberPriv || x25519Priv.
      const priv = new Uint8Array(Kyber768PrivateKeySize + X25519Size);
      priv.set(k.secretKey, 0);
      priv.set(xPriv, Kyber768PrivateKeySize);
      const pub = new Uint8Array(Kyber768PublicKeySize + X25519Size);
      pub.set(k.publicKey, 0);
      pub.set(xPub, Kyber768PublicKeySize);
      return { privateKey: priv, publicKey: pub };
    }
  }
}
