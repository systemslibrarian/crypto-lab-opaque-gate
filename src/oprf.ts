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

import { p256_oprf } from '@noble/curves/nist.js';

/** Server keypair for the OPRF. Public key is 33-byte compressed P-256. */
export function generateOprfKey(): {
  oprfPrivate: Uint8Array;
  oprfPublic: Uint8Array;
} {
  const { secretKey, publicKey } = p256_oprf.oprf.generateKeyPair();
  return { oprfPrivate: secretKey, oprfPublic: publicKey };
}

/** Client blind step. */
export function oprfBlind(input: Uint8Array): {
  blind: Uint8Array;
  blinded: Uint8Array;
} {
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
