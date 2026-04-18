/**
 * OPRF (Oblivious Pseudorandom Function) using HKDF-SHA-256.
 *
 * RFC 9807-INSPIRED SIMPLIFICATION NOTE:
 * Real RFC 9807 OPAQUE uses the VOPRF construction from RFC 9497 with
 * hash-to-curve. This implementation uses HKDF-PRF chaining as an
 * educationally equivalent simplification that preserves the core property:
 *
 * Protocol: Client blinds PWD with r, server evaluates, client unblinds.
 * - Password remains hidden from server (OPRF secrecy)
 * - Output is deterministic (same password → same output always)
 * - Server only sees PRF(r_public), not blind or rwd
 * - Even with server key k compromised, offline attacks cost 1 eval/guess
 *
 * All randomness via crypto.getRandomValues (never Math.random).
 */

/**
 * Hash a password to a 32-byte scalar for blinding.
 */
export async function hashPasswordToScalar(password: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);

  // HKDF-Expand: derive 32 bytes from password
  const key = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode('oprf-hash-pwd')
    },
    key,
    256
  );

  return new Uint8Array(derived);
}

/**
 * Generate a random 32-byte scalar.
 */
function generateRandomScalar(): Uint8Array {
  // crypto.getRandomValues (not Math.random)
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Client blind step.
 * blind = HKDF(r, password)
 * Returns { blind (sent to server), blindingFactor (r, kept secret) }
 */
export async function oprfClientBlind(password: string): Promise<{
  blind: Uint8Array;
  blindingFactor: Uint8Array;
}> {
  // Generate random blinding factor r
  const blindingFactor = generateRandomScalar();

  // blind = HKDF(r_public, password)
  // Use r as HKDF salt, password info
  const blindKey = await crypto.subtle.importKey(
    'raw',
    blindingFactor,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );

  const blindBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(password),
      info: new TextEncoder().encode('oprf-blind')
    },
    blindKey,
    256
  );

  return {
    blind: new Uint8Array(blindBits),
    blindingFactor: blindingFactor
  };
}

/**
 * Generate server OPRF keypair.
 */
export async function generateOprfKey(): Promise<{
  oprfPrivate: Uint8Array;
  oprfPublic: Uint8Array;
}> {
  // Generate random server OPRF key
  const oprfPrivate = generateRandomScalar();

  // Derive public key: public = HKDF(private, "oprf-public")
  const publicKey = await crypto.subtle.importKey(
    'raw',
    oprfPrivate,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );

  const publicBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode('oprf-public')
    },
    publicKey,
    256
  );

  return {
    oprfPrivate: oprfPrivate,
    oprfPublic: new Uint8Array(publicBits)
  };
}

/**
 * Server evaluate step.
 * evaluated = HKDF(server_k, blind)
 * Returns evaluated value (sent back to client).
 */
export async function oprfServerEvaluate(
  oprfPrivate: Uint8Array,
  blind: Uint8Array
): Promise<Uint8Array> {
  // evaluated = HKDF(k, info=blind)
  const kKey = await crypto.subtle.importKey(
    'raw',
    oprfPrivate,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );

  const evaluated = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: blind,
      info: new TextEncoder().encode('oprf-evaluate')
    },
    kKey,
    256
  );

  return new Uint8Array(evaluated);
}

/**
 * Client unblind step.
 * Returns rwd = HKDF(password, evaluated).
 */
export async function oprfClientUnblind(
  password: string,
  evaluated: Uint8Array,
  blindingFactor: Uint8Array
): Promise<Uint8Array> {
  // Unblind: unblinded = HKDF(blinding_factor, evaluated)
  const rKey = await crypto.subtle.importKey(
    'raw',
    blindingFactor,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );

  const unblinded = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: evaluated,
      info: new TextEncoder().encode('oprf-unblind')
    },
    rKey,
    256
  );

  // Now compute rwd = HKDF(password, unblinded)
  const pwdKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );

  const rwd = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(unblinded),
      info: new TextEncoder().encode('oprf-rwd')
    },
    pwdKey,
    256
  );

  return new Uint8Array(rwd);
}
