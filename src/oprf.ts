/**
 * OPRF — RFC 9497 over NIST P-256 (suite P256-SHA256), via @noble/curves.
 *
 * Protocol:
 *   blind(input)            -> { blinded, blind }            // client
 *   blindEvaluate(sk, blinded) -> evaluated                  // server
 *   finalize(input, blind, evaluated) -> output (32 bytes)   // client
 *
 * The exported names below are kept as `oprfClient*` / `oprfServer*` for
 * compatibility with the rest of the codebase (envelope.ts, ake.ts, etc.).
 *
 * Security properties this gives us (and the previous HKDF chain did NOT):
 *  - Determinism: same password + same server key → same output, every run.
 *  - Server-side secrecy: server sees only the blinded point, never the input.
 *  - Offline-attack cost: each guess requires one full curve evaluation.
 *
 * Randomness comes from noble's RNG (crypto.getRandomValues under the hood).
 */

import { p256_oprf } from '@noble/curves/nist.js';

/** Server keypair. `oprfPrivate` is a 32-byte scalar; `oprfPublic` is a 33-byte compressed P-256 point. */
export async function generateOprfKey(): Promise<{
  oprfPrivate: Uint8Array;
  oprfPublic: Uint8Array;
}> {
  const keys = p256_oprf.oprf.generateKeyPair();
  return {
    oprfPrivate: keys.secretKey,
    oprfPublic: keys.publicKey
  };
}

/**
 * Client blind step. Returns the blinded element (sent to server) and the
 * secret blinding scalar (kept by client and used during unblind).
 */
export async function oprfClientBlind(password: string): Promise<{
  blind: Uint8Array;
  blindingFactor: Uint8Array;
}> {
  const input = new TextEncoder().encode(password);
  const { blind, blinded } = p256_oprf.oprf.blind(input);
  return {
    blind: blinded,
    blindingFactor: blind
  };
}

/** Server evaluate step. Returns the evaluated element (sent back to client). */
export async function oprfServerEvaluate(
  oprfPrivate: Uint8Array,
  blind: Uint8Array
): Promise<Uint8Array> {
  return p256_oprf.oprf.blindEvaluate(oprfPrivate, blind);
}

/**
 * Client unblind + finalize. Returns the 32-byte OPRF output (`rwd`).
 * Same (password, oprfPrivate) pair ⇒ same output across runs, regardless of
 * the fresh blinding factor used per session.
 */
export async function oprfClientUnblind(
  password: string,
  evaluated: Uint8Array,
  blindingFactor: Uint8Array
): Promise<Uint8Array> {
  const input = new TextEncoder().encode(password);
  return p256_oprf.oprf.finalize(input, blindingFactor, evaluated);
}
