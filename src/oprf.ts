/**
 * OPRF — RFC 9497 over NIST P-256 (suite P256-SHA256), via @noble/curves.
 *
 * Lower-level API (used by envelope.ts and ake.ts):
 *   oprfBlind(input)                      -> { blind, blinded }
 *   oprfBlindEvaluate(secret, blinded)    -> evaluated
 *   oprfFinalize(input, blind, evaluated) -> oprfOutput (32 bytes)
 *
 * Step-by-step wrappers (used by the demo exhibits, kept for compatibility):
 *   generateOprfKey()                     -> { oprfPrivate, oprfPublic }
 *   oprfClientBlind(password)             -> { blind, blindingFactor }
 *   oprfServerEvaluate(secret, blind)     -> evaluated
 *   oprfClientUnblind(password, evaluated, blindingFactor) -> oprfOutput
 *
 * RFC 9807 then stretches `oprfOutput` and fans it out into credential keys
 * (envelope.ts handles that).
 */

import { p256_oprf, p256_hasher } from '@noble/curves/nist.js';

/** Server keypair for the OPRF. Public key is 33-byte compressed P-256. */
export function generateOprfKey(): {
  oprfPrivate: Uint8Array;
  oprfPublic: Uint8Array;
} {
  const { secretKey, publicKey } = p256_oprf.oprf.generateKeyPair();
  return { oprfPrivate: secretKey, oprfPublic: publicKey };
}

const OPRF_HASH_TO_GROUP_DST = new TextEncoder().encode(
  'HashToGroup-OPRFV1-\x00-P256-SHA256'
);

function bytesToScalar(b: Uint8Array): bigint {
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  return n;
}

/**
 * Client blind step.
 *
 * Pass `preChosenBlind` to skip random scalar selection and use the exact
 * scalar bytes provided — needed because noble's blind() samples through
 * hash_to_field (48+ bytes of entropy), and the RFC 9807 vectors specify
 * the scalar directly. The resulting blinded point is computed manually:
 *   M = HashToGroup(input);  blinded = M.multiply(blindScalar)
 */
export function oprfBlind(
  input: Uint8Array,
  preChosenBlind?: Uint8Array
): { blind: Uint8Array; blinded: Uint8Array } {
  if (preChosenBlind) {
    const M = p256_hasher.hashToCurve(input, { DST: OPRF_HASH_TO_GROUP_DST });
    const r = bytesToScalar(preChosenBlind);
    const blinded = M.multiply(r).toBytes(true);
    return { blind: preChosenBlind, blinded };
  }
  const { blind, blinded } = p256_oprf.oprf.blind(input);
  return { blind, blinded };
}

/** Server evaluate step. */
export function oprfBlindEvaluate(
  secretKey: Uint8Array,
  blinded: Uint8Array
): Uint8Array {
  return p256_oprf.oprf.blindEvaluate(secretKey, blinded);
}

/** Client finalize step → 32-byte OPRF output. */
export function oprfFinalize(
  input: Uint8Array,
  blind: Uint8Array,
  evaluated: Uint8Array
): Uint8Array {
  return p256_oprf.oprf.finalize(input, blind, evaluated);
}

// ============================================================
// Demo-facing wrappers (preserve the names the exhibits know)
// ============================================================

export async function oprfClientBlind(password: string): Promise<{
  blind: Uint8Array;
  blindingFactor: Uint8Array;
}> {
  const input = new TextEncoder().encode(password);
  const { blind, blinded } = oprfBlind(input);
  return { blind: blinded, blindingFactor: blind };
}

export async function oprfServerEvaluate(
  oprfPrivate: Uint8Array,
  blind: Uint8Array
): Promise<Uint8Array> {
  return oprfBlindEvaluate(oprfPrivate, blind);
}

export async function oprfClientUnblind(
  password: string,
  evaluated: Uint8Array,
  blindingFactor: Uint8Array
): Promise<Uint8Array> {
  const input = new TextEncoder().encode(password);
  return oprfFinalize(input, blindingFactor, evaluated);
}
