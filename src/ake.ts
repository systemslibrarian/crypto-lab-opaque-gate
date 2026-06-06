/**
 * OPAQUE 3DH Authenticated Key Exchange (AKE).
 *
 * Three Diffie-Hellman operations on NIST P-256, via @noble/curves:
 * - DH1: static-static     (mutual knowledge of long-term keys)
 * - DH2: ephemeral-static  (forward secrecy)
 * - DH3: static-ephemeral  (forward secrecy)
 *
 * Messages: Client KE1 → Server KE2 → Client KE3 → Server Finalize.
 *
 * Note: this AKE is intentionally simplified for the demo; it does not
 * split MAC keys per direction the way RFC 9807 mandates. See PHASE_SUMMARY.md.
 */

import { p256 } from '@noble/curves/nist.js';
import { openEnvelope } from './envelope';
import {
  oprfClientBlind,
  oprfServerEvaluate,
  oprfClientUnblind
} from './oprf';

export interface AKEMessage1 {
  clientIdentity: string;
  blindedPassword: Uint8Array;
  clientEphemeralPublic: Uint8Array; // 65-byte uncompressed P-256 point
}

export interface AKEMessage2 {
  oprfEvaluated: Uint8Array;
  envelope: Uint8Array;
  serverEphemeralPublic: Uint8Array; // 65-byte uncompressed P-256 point
  serverStaticPublic: Uint8Array; // 65-byte uncompressed P-256 point
  serverMAC: Uint8Array;
}

export interface AKEMessage3 {
  clientMAC: Uint8Array;
}

/**
 * ECDH over P-256 returning the 32-byte x-coordinate as the shared secret.
 * Matches what WebCrypto's `deriveBits` would have produced.
 */
function ecdhX(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const shared = p256.getSharedSecret(privateKey, publicKey, false);
  return shared.slice(1, 33);
}

/** session_key = HKDF(DH1 || DH2 || DH3, salt=transcript, info="opaque-3dh-key") */
async function compute3DHKey(
  dh1: Uint8Array,
  dh2: Uint8Array,
  dh3: Uint8Array,
  transcript: Uint8Array
): Promise<Uint8Array> {
  const combined = new Uint8Array(96);
  combined.set(dh1, 0);
  combined.set(dh2, 32);
  combined.set(dh3, 64);

  const key = await crypto.subtle.importKey(
    'raw',
    combined,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );

  const sessionKeyBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: transcript,
      info: new TextEncoder().encode('opaque-3dh-key')
    },
    key,
    256
  );

  return new Uint8Array(sessionKeyBits);
}

async function computeMAC(
  key: Uint8Array,
  transcript: Uint8Array
): Promise<Uint8Array> {
  const macKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const mac = await crypto.subtle.sign('HMAC', macKey, transcript);
  return new Uint8Array(mac).slice(0, 32);
}

/**
 * Build the 3DH transcript. Both client and server must produce identical bytes,
 * so this helper is the single source of truth for layout.
 *
 * Layout: clientIdentity || blindedPassword || clientEphemeralPublic ||
 *         evaluated || envelope || serverEphemeralPublic || serverStaticPublic
 */
function buildTranscript(parts: {
  clientIdentity: string;
  blindedPassword: Uint8Array;
  clientEphemeralPublic: Uint8Array;
  evaluated: Uint8Array;
  envelope: Uint8Array;
  serverEphemeralPublic: Uint8Array;
  serverStaticPublic: Uint8Array;
}): Uint8Array {
  const encoder = new TextEncoder();
  const identityBytes = encoder.encode(parts.clientIdentity);

  const total =
    identityBytes.byteLength +
    parts.blindedPassword.byteLength +
    parts.clientEphemeralPublic.byteLength +
    parts.evaluated.byteLength +
    parts.envelope.byteLength +
    parts.serverEphemeralPublic.byteLength +
    parts.serverStaticPublic.byteLength;

  const out = new Uint8Array(total);
  let off = 0;
  out.set(identityBytes, off);
  off += identityBytes.byteLength;
  out.set(parts.blindedPassword, off);
  off += parts.blindedPassword.byteLength;
  out.set(parts.clientEphemeralPublic, off);
  off += parts.clientEphemeralPublic.byteLength;
  out.set(parts.evaluated, off);
  off += parts.evaluated.byteLength;
  out.set(parts.envelope, off);
  off += parts.envelope.byteLength;
  out.set(parts.serverEphemeralPublic, off);
  off += parts.serverEphemeralPublic.byteLength;
  out.set(parts.serverStaticPublic, off);

  return out;
}

/** Client step 1: blind password, generate ephemeral keypair, build KE1. */
export async function clientLoginStep1(
  password: string,
  clientIdentity: string
): Promise<{
  ke1: AKEMessage1;
  clientState: {
    clientIdentity: string;
    blindedPassword: Uint8Array;
    blindingFactor: Uint8Array;
    clientEphemeralPrivate: Uint8Array;
    clientEphemeralPublic: Uint8Array;
    password: string;
  };
}> {
  const { blind, blindingFactor } = await oprfClientBlind(password);

  const clientEphemeralPrivate = p256.utils.randomSecretKey();
  const clientEphemeralPublic = p256.getPublicKey(clientEphemeralPrivate, false);

  return {
    ke1: {
      clientIdentity,
      blindedPassword: blind,
      clientEphemeralPublic
    },
    clientState: {
      clientIdentity,
      blindedPassword: blind,
      blindingFactor,
      clientEphemeralPrivate,
      clientEphemeralPublic,
      password
    }
  };
}

/** Server step 2: evaluate OPRF, generate ephemeral, run 3DH, emit KE2. */
export async function serverLoginStep2(
  ke1: AKEMessage1,
  record: {
    credentialIdentifier: string;
    clientPublicKey: Uint8Array;
    envelope: Uint8Array;
    oprfKey: Uint8Array;
  },
  serverPrivateKey: Uint8Array,
  serverPublicKey: Uint8Array
): Promise<{
  ke2: AKEMessage2;
  serverState: {
    sessionKey: Uint8Array;
    transcript: Uint8Array;
  };
}> {
  const evaluated = await oprfServerEvaluate(record.oprfKey, ke1.blindedPassword);

  const serverEphemeralPrivate = p256.utils.randomSecretKey();
  const serverEphemeralPublic = p256.getPublicKey(serverEphemeralPrivate, false);

  // DH1 = DH(server_static_priv, client_static_pub)
  const dh1 = ecdhX(serverPrivateKey, record.clientPublicKey);
  // DH2 = DH(server_static_priv, client_ephemeral_pub)
  const dh2 = ecdhX(serverPrivateKey, ke1.clientEphemeralPublic);
  // DH3 = DH(server_ephemeral_priv, client_static_pub)
  const dh3 = ecdhX(serverEphemeralPrivate, record.clientPublicKey);

  const transcript = buildTranscript({
    clientIdentity: ke1.clientIdentity,
    blindedPassword: ke1.blindedPassword,
    clientEphemeralPublic: ke1.clientEphemeralPublic,
    evaluated,
    envelope: record.envelope,
    serverEphemeralPublic,
    serverStaticPublic: serverPublicKey
  });

  const sessionKey = await compute3DHKey(dh1, dh2, dh3, transcript);
  const serverMAC = await computeMAC(sessionKey, transcript);

  return {
    ke2: {
      oprfEvaluated: evaluated,
      envelope: record.envelope,
      serverEphemeralPublic,
      serverStaticPublic: serverPublicKey,
      serverMAC
    },
    serverState: {
      sessionKey,
      transcript
    }
  };
}

/** Client step 3: unblind OPRF, open envelope, run 3DH, verify server MAC. */
export async function clientLoginStep3(
  ke2: AKEMessage2,
  clientState: {
    clientIdentity: string;
    blindedPassword: Uint8Array;
    blindingFactor: Uint8Array;
    clientEphemeralPrivate: Uint8Array;
    clientEphemeralPublic: Uint8Array;
    password: string;
  }
): Promise<{
  ke3: AKEMessage3;
  sessionKey: Uint8Array;
  exportKey: Uint8Array;
}> {
  const rwd = await oprfClientUnblind(
    clientState.password,
    ke2.oprfEvaluated,
    clientState.blindingFactor
  );

  // Throws if rwd is wrong (AES-GCM auth tag mismatch).
  const credentials = await openEnvelope(ke2.envelope, rwd);

  // DH1 = DH(client_static_priv, server_static_pub)
  const dh1 = ecdhX(credentials.clientPrivateKey, ke2.serverStaticPublic);
  // DH2 = DH(client_ephemeral_priv, server_static_pub)
  const dh2 = ecdhX(clientState.clientEphemeralPrivate, ke2.serverStaticPublic);
  // DH3 = DH(client_static_priv, server_ephemeral_pub)
  const dh3 = ecdhX(credentials.clientPrivateKey, ke2.serverEphemeralPublic);

  const transcript = buildTranscript({
    clientIdentity: clientState.clientIdentity,
    blindedPassword: clientState.blindedPassword,
    clientEphemeralPublic: clientState.clientEphemeralPublic,
    evaluated: ke2.oprfEvaluated,
    envelope: ke2.envelope,
    serverEphemeralPublic: ke2.serverEphemeralPublic,
    serverStaticPublic: ke2.serverStaticPublic
  });

  const sessionKey = await compute3DHKey(dh1, dh2, dh3, transcript);

  const expectedServerMAC = await computeMAC(sessionKey, transcript);
  if (!constantTimeEqual(ke2.serverMAC, expectedServerMAC)) {
    throw new Error('Server authentication failed: MAC mismatch');
  }

  const clientMAC = await computeMAC(sessionKey, transcript);

  const exportKeyMaterial = await crypto.subtle.importKey(
    'raw',
    rwd,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );

  const exportKeyBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode('opaque-exportkey')
    },
    exportKeyMaterial,
    256
  );

  return {
    ke3: { clientMAC },
    sessionKey,
    exportKey: new Uint8Array(exportKeyBits)
  };
}

/** Server step 4: verify client MAC, return session key. */
export async function serverFinalize(
  ke3: AKEMessage3,
  serverState: {
    sessionKey: Uint8Array;
    transcript: Uint8Array;
  }
): Promise<Uint8Array> {
  const expectedClientMAC = await computeMAC(
    serverState.sessionKey,
    serverState.transcript
  );

  if (!constantTimeEqual(ke3.clientMAC, expectedClientMAC)) {
    throw new Error('Client authentication failed: MAC mismatch');
  }

  return serverState.sessionKey;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let result = 0;
  for (let i = 0; i < a.byteLength; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
