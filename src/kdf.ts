/**
 * Primitives for RFC 9807 OPAQUE on the P256-SHA256 ciphersuite.
 *
 *   Suite parameters (RFC 9807 §6.4):
 *     Nh   = 32  SHA-256 output length
 *     Nm   = 32  HMAC-SHA-256 tag length
 *     Nn   = 32  nonce length
 *     Nsk  = 32  P-256 scalar length
 *     Npk  = 33  P-256 compressed point length (SEC1)
 *     Nseed = 32 seed length for DeriveAuthKeyPair
 *
 * All bit twiddling lives here so that envelope.ts and ake.ts read like the spec.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf.js';
import { scrypt } from '@noble/hashes/scrypt.js';
import { p256, p256_hasher } from '@noble/curves/nist.js';

export const Nh = 32;
export const Nm = 32;
export const Nn = 32;
export const Nsk = 32;
export const Npk = 33;
export const Nseed = 32;
export const Noe = 33; // OPRF element length (P-256 compressed)

/** Big-endian integer → fixed-length octet string. */
export function i2osp(n: number, len: number): Uint8Array {
  if (n < 0 || n >= Math.pow(2, 8 * len)) {
    throw new Error(`i2osp: value ${n} out of range for ${len} bytes`);
  }
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  return out;
}

/** Concatenate byte arrays. */
export function concat(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((s, a) => s + a.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.byteLength;
  }
  return out;
}

/** SHA-256. */
export function hash(msg: Uint8Array): Uint8Array {
  return sha256(msg);
}

/** HMAC-SHA-256. */
export function mac(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return hmac(sha256, key, msg);
}

/** Constant-time byte equality. */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let r = 0;
  for (let i = 0; i < a.byteLength; i++) r |= a[i] ^ b[i];
  return r === 0;
}

/** XOR two equal-length byte arrays. */
export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.byteLength !== b.byteLength) throw new Error('xor: length mismatch');
  const out = new Uint8Array(a.byteLength);
  for (let i = 0; i < a.byteLength; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** HKDF-Extract(salt, ikm) per RFC 5869. */
export function extract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hkdfExtract(sha256, ikm, salt);
}

/** HKDF-Expand(prk, info, length) per RFC 5869. */
export function expand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return hkdfExpand(sha256, prk, info, length);
}

/**
 * Expand-Label per RFC 9807 §6.4.2.
 *
 *   CustomLabel = I2OSP(Length, 2) ||
 *                 I2OSP(7 + len(Label), 1) || "OPAQUE-" || Label ||
 *                 I2OSP(len(Context), 1) || Context
 *   return HKDF-Expand(Secret, CustomLabel, Length)
 */
export function expandLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number
): Uint8Array {
  const labelBytes = new TextEncoder().encode('OPAQUE-' + label);
  const customLabel = concat(
    i2osp(length, 2),
    i2osp(labelBytes.byteLength, 1),
    labelBytes,
    i2osp(context.byteLength, 1),
    context
  );
  return expand(secret, customLabel, length);
}

/** Derive-Secret per RFC 9807 §6.4.2: Expand-Label with length = Nh. */
export function deriveSecret(
  secret: Uint8Array,
  label: string,
  transcriptHash: Uint8Array
): Uint8Array {
  return expandLabel(secret, label, transcriptHash, Nh);
}

/**
 * Key-stretching function applied to the OPRF output before deriving credentials.
 * RFC 9807 §4.1 says implementers should pick a memory-hard KSF.
 *
 * The library demos run with `stretchScrypt` (memory-hard, snappy at N=2^15).
 * The `Identity` stretch is the no-op KSF — used in RFC 9807 §C test vectors
 * and in protocol-debugging contexts. Production deployments should bump scrypt
 * N to 2^17 (OWASP 2023) or swap in Argon2id.
 */
export type StretchFn = (input: Uint8Array) => Uint8Array;

export const stretchIdentity: StretchFn = input => input;

export const stretchScrypt: StretchFn = input =>
  scrypt(input, new Uint8Array(0), { N: 1 << 15, r: 8, p: 1, dkLen: Nh });

/** Default stretch (kept exported under the old name for callers). */
export const stretch: StretchFn = stretchScrypt;

/**
 * RFC 9807 §4.1 `randomized_password` derivation. The stretch output and
 * the raw OPRF output are *both* fed into HKDF-Extract — running stretch
 * alone isn't enough.
 *
 *   randomized_password = HKDF-Extract("", oprf_output || stretch(oprf_output))
 */
export function deriveRandomizedPassword(
  oprfOutput: Uint8Array,
  stretchFn: StretchFn = stretchScrypt
): Uint8Array {
  const stretched = stretchFn(oprfOutput);
  return extract(new Uint8Array(0), concat(oprfOutput, stretched));
}

/** bigint → big-endian 32-byte scalar. */
function scalarToBytes(s: bigint): Uint8Array {
  const out = new Uint8Array(Nsk);
  for (let i = Nsk - 1; i >= 0; i--) {
    out[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  return out;
}

/**
 * RFC 9497 §3.2.1 DeriveKeyPair, parameterized by `info`.
 *
 *   deriveInput = seed || I2OSP(len(info), 2) || info
 *   contextString = "OPRFV1-" || I2OSP(mode, 1) || "-" || suite
 *   DST = "DeriveKeyPair" || contextString
 *   for counter in 0..255:
 *     sk = HashToScalar(deriveInput || I2OSP(counter, 1), DST)
 *     if sk != 0: break
 *   pk = sk * G   (compressed)
 *
 * Mode is fixed to 0x00 (base OPRF) and the OPRF suite is P256-SHA256 — both
 * match the RFC 9807 P256-SHA256 configuration.
 */
export function deriveKeyPair(seed: Uint8Array, info: Uint8Array): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
} {
  const contextString = new TextEncoder().encode('OPRFV1-\x00-P256-SHA256');
  const dst = concat(new TextEncoder().encode('DeriveKeyPair'), contextString);

  for (let counter = 0; counter < 256; counter++) {
    const input = concat(seed, i2osp(info.byteLength, 2), info, i2osp(counter, 1));
    const scalar = p256_hasher.hashToScalar(input, { DST: dst });
    if (scalar !== 0n) {
      const skBytes = scalarToBytes(scalar);
      const publicKey = p256.getPublicKey(skBytes, true);
      return { secretKey: skBytes, publicKey };
    }
  }
  throw new Error('DeriveKeyPair: rejection-sampled past counter 255');
}

const DH_INFO = new TextEncoder().encode('OPAQUE-DeriveDiffieHellmanKeyPair');
const OPRF_INFO = new TextEncoder().encode('OPAQUE-DeriveKeyPair');

/**
 * DeriveKeyPair for any OPAQUE Diffie-Hellman keypair: the client's static
 * key (in Store / Recover), the client ephemeral, and the server ephemeral.
 */
export function deriveDiffieHellmanKeyPair(seed: Uint8Array): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
} {
  return deriveKeyPair(seed, DH_INFO);
}

/**
 * DeriveKeyPair for the server's per-user OPRF secret. The seed itself
 * comes from `HKDF-Expand(oprf_seed, credential_identifier || "OprfKey", Nok)`.
 */
export function deriveOprfKeyPair(seed: Uint8Array): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
} {
  return deriveKeyPair(seed, OPRF_INFO);
}

/**
 * Diffie-Hellman: scalar * peer_point, serialized as a 33-byte compressed
 * SEC1 point per RFC 9807 §6.4 "Group elements are serialized using SEC1
 * compressed encoding".
 */
export function dh(scalar: Uint8Array, peerPoint: Uint8Array): Uint8Array {
  return p256.getSharedSecret(scalar, peerPoint, true);
}

/** Generate a fresh ephemeral P-256 keypair (compressed public). */
export function generateKeyPair(): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
} {
  const secretKey = p256.utils.randomSecretKey();
  const publicKey = p256.getPublicKey(secretKey, true);
  return { secretKey, publicKey };
}
