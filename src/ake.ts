/**
 * OPAQUE-3DH AKE (RFC 9807 §6, internal mode, P256-SHA256).
 *
 * Preamble (RFC 9807 §6.4.2.1):
 *
 *   preamble = "OPAQUEv1-" ||
 *              I2OSP(len(context), 2)        || context ||
 *              I2OSP(len(client_identity), 2)|| client_identity ||
 *              serialize(ke1) ||
 *              I2OSP(len(server_identity), 2)|| server_identity ||
 *              serialize(credential_response) ||
 *              server_nonce ||
 *              server_keyshare
 *
 * Field order matters and is easy to write backwards: server_identity comes
 * BEFORE credential_response. buildPreamble() below has always had it right —
 * the Appendix C known-answer tests would not pass otherwise — but this comment
 * had the two swapped, so it described a protocol the file does not implement.
 *
 * Key schedule (RFC 9807 §6.4.2, Key Schedule Functions):
 *
 *   ikm  = dh1 || dh2 || dh3
 *           dh1 = DH(client_eph_sk, server_eph_pk)    // eph × eph
 *           dh2 = DH(client_eph_sk, server_static_pk) // eph × static
 *           dh3 = DH(client_static_sk, server_eph_pk) // static × eph
 *   prk              = HKDF-Extract("", ikm)
 *   handshake_secret = Expand-Label(prk, "HandshakeSecret", H(preamble), Nh)
 *   session_key      = Expand-Label(prk, "SessionKey",      H(preamble), Nh)
 *   km2 = Expand-Label(handshake_secret, "ServerMAC", "", Nh)
 *   km3 = Expand-Label(handshake_secret, "ClientMAC", "", Nh)
 *   server_mac = MAC(km2, H(preamble))
 *   client_mac = MAC(km3, H(preamble || server_mac))
 */

import { p256 } from '@noble/curves/nist.js';
import {
  Nh,
  Nn,
  Npk,
  concat,
  hash,
  mac,
  ctEqual,
  xor,
  extract,
  expand,
  expandLabel,
  deriveSecret,
  StretchFn,
  stretchScrypt,
  deriveRandomizedPassword,
  dh,
  generateKeyPair,
  deriveDiffieHellmanKeyPair
} from './kdf';
import {
  oprfBlind,
  oprfBlindEvaluate,
  oprfFinalize
} from './oprf';
import {
  ENVELOPE_LENGTH,
  MASKED_RESPONSE_LENGTH,
  RegistrationRecord,
  recover
} from './envelope';

/** Application context, mixed into the preamble for domain separation. */
const DEFAULT_CONTEXT = new TextEncoder().encode('opaque-gate-demo');

export interface AKEMessage1 {
  blindedMessage: Uint8Array; // 33
  clientNonce: Uint8Array; // 32
  clientKeyshare: Uint8Array; // 33
}

export interface CredentialResponse {
  evaluatedMessage: Uint8Array; // 33
  maskingNonce: Uint8Array; // 32
  maskedResponse: Uint8Array; // 97
}

export interface AKEMessage2 {
  credentialResponse: CredentialResponse;
  serverNonce: Uint8Array; // 32
  serverKeyshare: Uint8Array; // 33
  serverMac: Uint8Array; // 32
}

export interface AKEMessage3 {
  clientMac: Uint8Array; // 32
}

export interface ClientState {
  password: string;
  blind: Uint8Array;
  clientNonce: Uint8Array;
  clientEphemeralPrivate: Uint8Array;
  clientEphemeralPublic: Uint8Array;
  ke1Bytes: Uint8Array;
  clientIdentity: Uint8Array;
  serverIdentity: Uint8Array;
  context: Uint8Array;
  stretchFn: StretchFn;
}

export interface ServerState {
  sessionKey: Uint8Array;
  expectedClientMac: Uint8Array;
}

// ============================================================
// Serialization
// ============================================================

export function serializeKE1(ke1: AKEMessage1): Uint8Array {
  return concat(ke1.blindedMessage, ke1.clientNonce, ke1.clientKeyshare);
}

export function serializeCredentialResponse(cr: CredentialResponse): Uint8Array {
  return concat(cr.evaluatedMessage, cr.maskingNonce, cr.maskedResponse);
}

/** Parse 98-byte wire KE1 into the structured form serverLoginStep2 takes. */
export function deserializeKE1(bytes: Uint8Array): AKEMessage1 {
  if (bytes.byteLength !== Npk + Nn + Npk) {
    throw new Error(`deserializeKE1: wrong length ${bytes.byteLength}`);
  }
  return {
    blindedMessage: bytes.slice(0, Npk),
    clientNonce: bytes.slice(Npk, Npk + Nn),
    clientKeyshare: bytes.slice(Npk + Nn)
  };
}

const PREAMBLE_PREFIX = new TextEncoder().encode('OPAQUEv1-');

function vec2(b: Uint8Array): Uint8Array {
  return new Uint8Array([(b.byteLength >> 8) & 0xff, b.byteLength & 0xff]);
}

function buildPreamble(args: {
  context: Uint8Array;
  clientIdentity: Uint8Array;
  clientPublicKey: Uint8Array;
  ke1Bytes: Uint8Array;
  credentialResponseBytes: Uint8Array;
  serverIdentity: Uint8Array;
  serverPublicKey: Uint8Array;
  serverNonce: Uint8Array;
  serverKeyshare: Uint8Array;
}): Uint8Array {
  const cid =
    args.clientIdentity.byteLength === 0
      ? args.clientPublicKey
      : args.clientIdentity;
  const sid =
    args.serverIdentity.byteLength === 0
      ? args.serverPublicKey
      : args.serverIdentity;

  return concat(
    PREAMBLE_PREFIX,
    vec2(args.context),
    args.context,
    vec2(cid),
    cid,
    args.ke1Bytes,
    vec2(sid),
    sid,
    args.credentialResponseBytes,
    args.serverNonce,
    args.serverKeyshare
  );
}

// ============================================================
// Credential response masking (RFC 9807 §6.3.2.2, CreateCredentialResponse)
// ============================================================

function maskResponse(
  maskingKey: Uint8Array,
  maskingNonce: Uint8Array,
  serverPublicKey: Uint8Array,
  envelope: Uint8Array
): Uint8Array {
  const info = concat(
    maskingNonce,
    new TextEncoder().encode('CredentialResponsePad')
  );
  const pad = expand(maskingKey, info, MASKED_RESPONSE_LENGTH);
  return xor(pad, concat(serverPublicKey, envelope));
}

function unmaskResponse(
  maskingKey: Uint8Array,
  maskingNonce: Uint8Array,
  maskedResponse: Uint8Array
): { serverPublicKey: Uint8Array; envelope: Uint8Array } {
  const info = concat(
    maskingNonce,
    new TextEncoder().encode('CredentialResponsePad')
  );
  const pad = expand(maskingKey, info, MASKED_RESPONSE_LENGTH);
  const plain = xor(pad, maskedResponse);
  return {
    serverPublicKey: plain.slice(0, Npk),
    envelope: plain.slice(Npk, Npk + ENVELOPE_LENGTH)
  };
}

// ============================================================
// Key schedule (RFC 9807 §6.4.2)
// ============================================================

export interface KeySchedule {
  prk: Uint8Array;
  handshakeSecret: Uint8Array;
  sessionKey: Uint8Array;
}

/**
 * The RFC 9807 §6.4.2 key schedule, factored out of the client and server so
 * there is exactly one implementation of it.
 *
 * Exporting it is what lets the forward-secrecy exhibit *measure* rather than
 * assert: the exhibit re-runs this same schedule over an attacker's own
 * reconstruction of the ikm and compares the result, byte for byte, against
 * the key the real handshake produced.
 */
export function keySchedule(ikm: Uint8Array, preambleHash: Uint8Array): KeySchedule {
  const prk = extract(new Uint8Array(0), ikm);
  return {
    prk,
    handshakeSecret: deriveSecret(prk, 'HandshakeSecret', preambleHash),
    sessionKey: deriveSecret(prk, 'SessionKey', preambleHash)
  };
}

// ============================================================
// Helper for deterministic-key injection
// ============================================================

// ============================================================
// Client step 1
// ============================================================

export async function clientLoginStep1(
  password: string,
  clientIdentityStr: string,
  options: {
    serverIdentity?: Uint8Array;
    context?: Uint8Array;
    stretchFn?: StretchFn;
    blind?: Uint8Array;
    clientNonce?: Uint8Array;
    clientKeyshareSeed?: Uint8Array;
    clientEphemeralPrivate?: Uint8Array;
  } = {}
): Promise<{ ke1: AKEMessage1; clientState: ClientState }> {
  const passwordBytes = new TextEncoder().encode(password);

  const { blind, blinded } = oprfBlind(passwordBytes, options.blind);

  const clientNonce =
    options.clientNonce ?? crypto.getRandomValues(new Uint8Array(Nn));

  let clientEphemeralPrivate: Uint8Array;
  let clientEphemeralPublic: Uint8Array;
  if (options.clientEphemeralPrivate) {
    clientEphemeralPrivate = options.clientEphemeralPrivate;
    // Derive public from the supplied private (sec1 compressed).
    // We re-use noble via generateKeyPair? No — that randomises.
    // Use deriveDiffieHellmanKeyPair? No — that takes a seed and runs the
    // DeriveKeyPair counter loop. Caller supplied the actual private bytes,
    // so just compute G * sk.
clientEphemeralPublic = p256.getPublicKey(clientEphemeralPrivate, true);
  } else if (options.clientKeyshareSeed) {
    const kp = deriveDiffieHellmanKeyPair(options.clientKeyshareSeed);
    clientEphemeralPrivate = kp.secretKey;
    clientEphemeralPublic = kp.publicKey;
  } else {
    const kp = generateKeyPair();
    clientEphemeralPrivate = kp.secretKey;
    clientEphemeralPublic = kp.publicKey;
  }

  const ke1: AKEMessage1 = {
    blindedMessage: blinded,
    clientNonce,
    clientKeyshare: clientEphemeralPublic
  };

  const clientIdentity = new TextEncoder().encode(clientIdentityStr);
  const serverIdentity = options.serverIdentity ?? new Uint8Array(0);
  const context = options.context ?? DEFAULT_CONTEXT;
  const stretchFn = options.stretchFn ?? stretchScrypt;

  return {
    ke1,
    clientState: {
      password,
      blind,
      clientNonce,
      clientEphemeralPrivate,
      clientEphemeralPublic,
      ke1Bytes: serializeKE1(ke1),
      clientIdentity,
      serverIdentity,
      context,
      stretchFn
    }
  };
}

// ============================================================
// Server step 2
// ============================================================

export async function serverLoginStep2(
  ke1: AKEMessage1,
  record: RegistrationRecord,
  serverPrivateKey: Uint8Array,
  serverPublicKey: Uint8Array,
  options: {
    serverIdentity?: Uint8Array;
    clientIdentity?: Uint8Array;
    context?: Uint8Array;
    maskingNonce?: Uint8Array;
    serverNonce?: Uint8Array;
    serverKeyshareSeed?: Uint8Array;
    serverEphemeralPrivate?: Uint8Array;
  } = {}
): Promise<{ ke2: AKEMessage2; serverState: ServerState }> {
  const serverIdentity = options.serverIdentity ?? new Uint8Array(0);
  const clientIdentity =
    options.clientIdentity ??
    new TextEncoder().encode(record.credentialIdentifier);
  const context = options.context ?? DEFAULT_CONTEXT;

  // 1. OPRF evaluate.
  const evaluatedMessage = oprfBlindEvaluate(
    record.oprfKey,
    ke1.blindedMessage
  );

  // 2. Mask (server_pub || envelope) under per-user masking_key.
  const maskingNonce =
    options.maskingNonce ?? crypto.getRandomValues(new Uint8Array(Nn));
  const maskedResponse = maskResponse(
    record.maskingKey,
    maskingNonce,
    serverPublicKey,
    record.envelope
  );

  const credentialResponse: CredentialResponse = {
    evaluatedMessage,
    maskingNonce,
    maskedResponse
  };

  // 3. Server ephemeral keypair + nonce.
  const serverNonce =
    options.serverNonce ?? crypto.getRandomValues(new Uint8Array(Nn));

  let serverEphemeralPrivate: Uint8Array;
  let serverKeyshare: Uint8Array;
  if (options.serverEphemeralPrivate) {
    serverEphemeralPrivate = options.serverEphemeralPrivate;
serverKeyshare = p256.getPublicKey(serverEphemeralPrivate, true);
  } else if (options.serverKeyshareSeed) {
    const kp = deriveDiffieHellmanKeyPair(options.serverKeyshareSeed);
    serverEphemeralPrivate = kp.secretKey;
    serverKeyshare = kp.publicKey;
  } else {
    const kp = generateKeyPair();
    serverEphemeralPrivate = kp.secretKey;
    serverKeyshare = kp.publicKey;
  }

  // 4. 3DH per RFC 9807 §6.4.4 (3DH Server Functions).
  const dh1 = dh(serverEphemeralPrivate, ke1.clientKeyshare);
  const dh2 = dh(serverPrivateKey, ke1.clientKeyshare);
  const dh3 = dh(serverEphemeralPrivate, record.clientPublicKey);
  const ikm = concat(dh1, dh2, dh3);

  // 5. Preamble and key schedule.
  const ke1Bytes = serializeKE1(ke1);
  const credentialResponseBytes = serializeCredentialResponse(credentialResponse);
  const preamble = buildPreamble({
    context,
    clientIdentity,
    clientPublicKey: record.clientPublicKey,
    ke1Bytes,
    credentialResponseBytes,
    serverIdentity,
    serverPublicKey,
    serverNonce,
    serverKeyshare
  });
  const preambleHash = hash(preamble);

  const { handshakeSecret, sessionKey } = keySchedule(ikm, preambleHash);

  const km2 = expandLabel(handshakeSecret, 'ServerMAC', new Uint8Array(0), Nh);
  const km3 = expandLabel(handshakeSecret, 'ClientMAC', new Uint8Array(0), Nh);

  const serverMac = mac(km2, preambleHash);
  const expectedClientMac = mac(km3, hash(concat(preamble, serverMac)));

  return {
    ke2: {
      credentialResponse,
      serverNonce,
      serverKeyshare,
      serverMac
    },
    serverState: {
      sessionKey,
      expectedClientMac
    }
  };
}

// ============================================================
// Client step 3
// ============================================================

/**
 * The three Diffie-Hellman shared secrets and the four public keys that feed
 * them, surfaced for visualization. These are the *real* values computed during
 * the client's 3DH (§6.4.3) — nothing here is faked; the exhibit only draws
 * what login already produced.
 */
export interface ThreeDHTrace {
  clientEphemeralPublic: Uint8Array;
  clientStaticPublic: Uint8Array;
  serverEphemeralPublic: Uint8Array;
  serverStaticPublic: Uint8Array;
  dh1: Uint8Array; // client_eph × server_eph  → forward secrecy
  dh2: Uint8Array; // client_eph × server_static → authenticates the server
  dh3: Uint8Array; // client_static × server_eph → authenticates the client
  /**
   * H(preamble). The preamble is built entirely from values that travel on the
   * wire, so a passive recorder of the login can compute this hash too — which
   * is exactly why the forward-secrecy exhibit is allowed to hand it to the
   * simulated attacker.
   */
  preambleHash: Uint8Array;
  /**
   * The client's recovered *long-term* secret key.
   *
   * Surfaced only so the forward-secrecy exhibit can simulate a full long-term
   * compromise — attacker steals both static secret keys — and then compute,
   * rather than assert, what such an attacker can and cannot derive. Real
   * client code has no reason to export this.
   */
  clientStaticPrivate: Uint8Array;
}

export async function clientLoginStep3(
  ke2: AKEMessage2,
  clientState: ClientState
): Promise<{
  ke3: AKEMessage3;
  sessionKey: Uint8Array;
  exportKey: Uint8Array;
  threeDH: ThreeDHTrace;
}> {
  const passwordBytes = new TextEncoder().encode(clientState.password);

  const oprfOutput = oprfFinalize(
    passwordBytes,
    clientState.blind,
    ke2.credentialResponse.evaluatedMessage
  );
  const randomizedPwd = deriveRandomizedPassword(oprfOutput, clientState.stretchFn);

  const maskingKey = expand(
    randomizedPwd,
    new TextEncoder().encode('MaskingKey'),
    Nh
  );
  const { serverPublicKey, envelope } = unmaskResponse(
    maskingKey,
    ke2.credentialResponse.maskingNonce,
    ke2.credentialResponse.maskedResponse
  );

  const { clientPrivateKey, clientPublicKey, exportKey } = recover(
    randomizedPwd,
    serverPublicKey,
    envelope,
    clientState.serverIdentity,
    clientState.clientIdentity
  );

  // 3DH — mirror of server.
  const dh1 = dh(clientState.clientEphemeralPrivate, ke2.serverKeyshare);
  const dh2 = dh(clientState.clientEphemeralPrivate, serverPublicKey);
  const dh3 = dh(clientPrivateKey, ke2.serverKeyshare);
  const ikm = concat(dh1, dh2, dh3);

  const credentialResponseBytes = serializeCredentialResponse(ke2.credentialResponse);
  const preamble = buildPreamble({
    context: clientState.context,
    clientIdentity: clientState.clientIdentity,
    clientPublicKey,
    ke1Bytes: clientState.ke1Bytes,
    credentialResponseBytes,
    serverIdentity: clientState.serverIdentity,
    serverPublicKey,
    serverNonce: ke2.serverNonce,
    serverKeyshare: ke2.serverKeyshare
  });
  const preambleHash = hash(preamble);

  const { handshakeSecret, sessionKey } = keySchedule(ikm, preambleHash);

  const km2 = expandLabel(handshakeSecret, 'ServerMAC', new Uint8Array(0), Nh);
  const km3 = expandLabel(handshakeSecret, 'ClientMAC', new Uint8Array(0), Nh);

  const expectedServerMac = mac(km2, preambleHash);
  if (!ctEqual(expectedServerMac, ke2.serverMac)) {
    throw new Error('Server MAC verification failed');
  }

  const clientMac = mac(km3, hash(concat(preamble, ke2.serverMac)));

  return {
    ke3: { clientMac },
    sessionKey,
    exportKey,
    threeDH: {
      clientEphemeralPublic: clientState.clientEphemeralPublic,
      clientStaticPublic: clientPublicKey,
      serverEphemeralPublic: ke2.serverKeyshare,
      serverStaticPublic: serverPublicKey,
      dh1,
      dh2,
      dh3,
      preambleHash,
      clientStaticPrivate: clientPrivateKey
    }
  };
}

// ============================================================
// Server step 4
// ============================================================

export async function serverFinalize(
  ke3: AKEMessage3,
  serverState: ServerState
): Promise<Uint8Array> {
  if (!ctEqual(ke3.clientMac, serverState.expectedClientMac)) {
    throw new Error('Client MAC verification failed');
  }
  return serverState.sessionKey;
}
