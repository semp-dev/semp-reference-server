/**
 * Master-key encryption envelope for at-rest private key material.
 *
 * Parameters MUST be byte-identical to impl/go/internal/store/encrypt.go
 * so a database written by one impl is readable by the other:
 *
 *  - KDF: Argon2id, m=131072 KiB (128 MiB), t=4, p=4, dkLen=32.
 *  - Salt: 16 random bytes per record.
 *  - AEAD: AES-256-GCM with a fresh 12-byte nonce per record.
 *  - AAD: the row's `key_id` value as UTF-8 bytes.
 *
 * @module
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { argon2id } from "@noble/hashes/argon2.js";

const ARGON_MEMORY_KB = 131072; // 128 MiB
const ARGON_ITERATIONS = 4;
const ARGON_PARALLELISM = 4;
const ARGON_KEY_LEN = 32; // AES-256
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;

/** Derive a 256-bit key from a master string + salt via Argon2id. */
export function deriveKey(masterKey: string, salt: Uint8Array): Uint8Array {
  return argon2id(new TextEncoder().encode(masterKey), salt, {
    m: ARGON_MEMORY_KB,
    t: ARGON_ITERATIONS,
    p: ARGON_PARALLELISM,
    dkLen: ARGON_KEY_LEN,
  });
}

/** Output of {@link encryptPrivateKey}. */
export interface EncryptedPrivate {
  ciphertext: Buffer;
  salt: Buffer;
  nonce: Buffer;
}

/**
 * AES-256-GCM seal of `plaintext` under a key derived from the master
 * string. The `aad` is the bytes of the row's `key_id`.
 *
 * The returned `ciphertext` carries the GCM tag appended (16 bytes),
 * matching the wire form Go's `cipher.GCM.Seal(nil, nonce, pt, aad)`
 * produces: SQLite stores `ciphertext = ct || tag`.
 */
export function encryptPrivateKey(
  masterKey: string,
  plaintext: Uint8Array,
  aad: Uint8Array,
): EncryptedPrivate {
  if (masterKey === "") {
    throw new Error("encrypt: empty master key");
  }
  const salt = randomBytes(SALT_LEN);
  const key = deriveKey(masterKey, salt);
  try {
    const nonce = randomBytes(NONCE_LEN);
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      ciphertext: Buffer.concat([ct, tag]),
      salt,
      nonce,
    };
  } finally {
    zeroize(key);
  }
}

/**
 * AES-256-GCM open of ciphertext stored as `ct || tag`. The aad MUST
 * match the value used during seal (the row's `key_id`).
 */
export function decryptPrivateKey(
  masterKey: string,
  ciphertext: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (masterKey === "") {
    throw new Error("decrypt: empty master key");
  }
  if (ciphertext.length < TAG_LEN) {
    throw new Error("decrypt: ciphertext too short for GCM tag");
  }
  const ctOnly = ciphertext.slice(0, ciphertext.length - TAG_LEN);
  const tag = ciphertext.slice(ciphertext.length - TAG_LEN);
  const key = deriveKey(masterKey, salt);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ctOnly), decipher.final()]);
  } finally {
    zeroize(key);
  }
}

function zeroize(b: Uint8Array): void {
  for (let i = 0; i < b.length; i++) {
    b[i] = 0;
  }
}
