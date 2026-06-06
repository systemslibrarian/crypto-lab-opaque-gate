/**
 * OPAQUE-3DH AKE (RFC 9807 §6, internal mode, P256-SHA256).
 *
 * Three messages — KE1 (client→server), KE2 (server→client), KE3 (client→server).
 *
 *   ┌─ Client ─────────────────────┐                  ┌─ Server ──────────┐
 *   │ blind, oprf_blinded =        │   KE1            │                   │
 *   │   OPRF.Blind(password)       │   ─────────────▶ │                   │
 *   │ ephemeral keypair, nonce     │                  │                   │
 *   │                              │                  │ OPRF.BlindEvaluate│
 *   │                              │                  │ mask envelope     │
 *   │                              │                  │ ephemeral keypair │
 *   │                              │   KE2            │ 3DH, key sched    │
 *   │                              │ ◀───────────────  │ server_mac        │
 *   │ unmask, finalize OPRF        │                  │                   │
 *   │ stretch + Recover envelope   │                  │                   │
 *   │ 3DH (mirrors server)         │                  │                   │
 *   │ verify server_mac            │                  │                   │
 *   │ client_mac                   │   KE3            │ verify client_mac │
 *   │                              │   ─────────────▶ │ session_key       │
 *   └──────────────────────────────┘                  └───────────────────┘
 *
 * Key schedule (RFC 9807 §6.4.4):
 *
 *   ikm = dh1 || dh2 || dh3
 *       where:
 *         dh1 = DH(client_eph_sk, server_eph_pk)    // ephemeral × ephemeral
 *         dh2 = DH(client_eph_sk, server_static_pk) // ephemeral × static
 *         dh3 = DH(client_static_sk, server_eph_pk) // static × ephemeral
 *   prk              = HKDF-Extract("", ikm)
 *   handshake_secret = Derive-Secret(prk, "HandshakeSecret", H(preamble))
 *   session_key      = Derive-Secret(prk, "SessionKey",     H(preamble))
 *   km2              = Expand-Label(handshake_secret, "ServerMAC", "", Nh)
 *   km3              = Expand-Label(handshake_secret, "ClientMAC", "", Nh)
 *   server_mac       = MAC(km2, H(preamble))
 *   client_mac       = MAC(km3, H(preamble || server_mac))
 */

import {
  Nh,
  Nn,
  Nm,
  Npk,
  Noe,
  concat,
  i2osp,
  hash,
  mac,
  ctEqual,
  xor,
  extract,
  expand,
  expandLabel,
  deriveSecret,
  stretch,
  dh,
  generateKeyPair
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
  blindedMessage: Uint8Array; // Noe = 33
  clientNonce: Uint8Array; // Nn = 32
  clientKeyshare: Uint8Array; // Npk = 33
}

export interface CredentialResponse {
  evaluatedMessage: Uint8Array; // Noe = 33
  maskingNonce: Uint8Array; // Nn = 32
  maskedResponse: Uint8Array; // Npk + ENVELOPE_LENGTH = 97
}

export interface AKEMessage2 {
  credentialResponse: CredentialResponse;
  serverNonce: Uint8Array; // Nn = 32
  serverKeyshare: Uint8Array; // Npk = 33
  serverMac: Uint8Array; // Nm = 32
}

export interface AKEMessage3 {
  clientMac: Uint8Array; // Nm = 32
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
}

export interface ServerState {
  sessionKey: Uint8Array;
  expectedClientMac: Uint8Array;
}

// ============================================================
// Serialization (used both as wire format and as transcript bytes)
// ============================================================

function serializeKE1(ke1: AKEMessage1): Uint8Array {
  return concat(ke1.blindedMessage, ke1.clientNonce, ke1.clientKeyshare);
}

function serializeCredentialResponse(cr: CredentialResponse): Uint8Array {
  return concat(cr.evaluatedMessage, cr.maskingNonce, cr.maskedResponse);
}

/**
 * Preamble per RFC 9807 §6.3 — the bytes fed to Hash() before deriving
 * handshake_secret / session_key, and what each MAC commits to.
 *
 *   preamble = context_string ||
 *              I2OSP(len(client_identity), 2) || client_identity ||
 *              ke1 ||
 *              credential_response ||
 *              I2OSP(len(server_identity), 2) || server_identity ||
 *              server_nonce || server_keyshare
 *
 * Empty identities are replaced with the corresponding public keys
 * (matches CreateCleartextCredentials, so MAC verification on both
 * sides resolves the same identity bytes).
 */
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
    args.context,
    i2osp(cid.byteLength, 2),
    cid,
    args.ke1Bytes,
    args.credentialResponseBytes,
    i2osp(sid.byteLength, 2),
    sid,
    args.serverNonce,
    args.serverKeyshare
  );
}

// ============================================================
// Credential response masking (RFC 9807 §6.2)
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
// Client step 1
// ============================================================

export async function clientLoginStep1(
  password: string,
  clientIdentityStr: string,
  options: {
    serverIdentity?: Uint8Array;
    context?: Uint8Array;
  } = {}
): Promise<{ ke1: AKEMessage1; clientState: ClientState }> {
  const passwordBytes = new TextEncoder().encode(password);
  const { blind, blinded } = oprfBlind(passwordBytes);

  const clientNonce = crypto.getRandomValues(new Uint8Array(Nn));
  const { secretKey: clientEphemeralPrivate, publicKey: clientEphemeralPublic } =
    generateKeyPair();

  const ke1: AKEMessage1 = {
    blindedMessage: blinded,
    clientNonce,
    clientKeyshare: clientEphemeralPublic
  };

  const clientIdentity = new TextEncoder().encode(clientIdentityStr);
  const serverIdentity = options.serverIdentity ?? new Uint8Array(0);
  const context = options.context ?? DEFAULT_CONTEXT;

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
      context
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
  } = {}
): Promise<{ ke2: AKEMessage2; serverState: ServerState }> {
  const serverIdentity = options.serverIdentity ?? new Uint8Array(0);
  // Mirror register()'s default of using the credential_identifier as the
  // client_identity. Callers can override for application-defined identities.
  const clientIdentity =
    options.clientIdentity ??
    new TextEncoder().encode(record.credentialIdentifier);
  const context = options.context ?? DEFAULT_CONTEXT;

  // 1. OPRF evaluate.
  const evaluatedMessage = oprfBlindEvaluate(
    record.oprfKey,
    ke1.blindedMessage
  );

  // 2. Mask the server's static public key + envelope under the per-user
  //    masking_key. A wrong-password client decrypts garbage and the MAC
  //    check in Recover catches it.
  const maskingNonce = crypto.getRandomValues(new Uint8Array(Nn));
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
  const serverNonce = crypto.getRandomValues(new Uint8Array(Nn));
  const { secretKey: serverEphemeralPrivate, publicKey: serverKeyshare } =
    generateKeyPair();

  // 4. 3DH per RFC 9807 §6.4.4.
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

  const prk = extract(new Uint8Array(0), ikm);
  const handshakeSecret = deriveSecret(prk, 'HandshakeSecret', preambleHash);
  const sessionKey = deriveSecret(prk, 'SessionKey', preambleHash);

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

export async function clientLoginStep3(
  ke2: AKEMessage2,
  clientState: ClientState
): Promise<{
  ke3: AKEMessage3;
  sessionKey: Uint8Array;
  exportKey: Uint8Array;
}> {
  const passwordBytes = new TextEncoder().encode(clientState.password);

  // 1. Finalize OPRF → stretch → randomized_pwd.
  const oprfOutput = oprfFinalize(
    passwordBytes,
    clientState.blind,
    ke2.credentialResponse.evaluatedMessage
  );
  const randomizedPwd = stretch(oprfOutput);

  // 2. Unmask credential response with the masking_key derived from rwd.
  const maskingKey = expandLabel(
    randomizedPwd,
    'MaskingKey',
    new Uint8Array(0),
    Nh
  );
  const { serverPublicKey, envelope } = unmaskResponse(
    maskingKey,
    ke2.credentialResponse.maskingNonce,
    ke2.credentialResponse.maskedResponse
  );

  // 3. Open the envelope → client static keypair + export key.
  const {
    clientPrivateKey,
    clientPublicKey,
    exportKey
  } = recover(
    randomizedPwd,
    serverPublicKey,
    envelope,
    clientState.serverIdentity,
    clientState.clientIdentity
  );

  // 4. 3DH — mirror of server's computation.
  const dh1 = dh(clientState.clientEphemeralPrivate, ke2.serverKeyshare);
  const dh2 = dh(clientState.clientEphemeralPrivate, serverPublicKey);
  const dh3 = dh(clientPrivateKey, ke2.serverKeyshare);
  const ikm = concat(dh1, dh2, dh3);

  // 5. Rebuild preamble — clientState carries every input.
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

  const prk = extract(new Uint8Array(0), ikm);
  const handshakeSecret = deriveSecret(prk, 'HandshakeSecret', preambleHash);
  const sessionKey = deriveSecret(prk, 'SessionKey', preambleHash);

  const km2 = expandLabel(handshakeSecret, 'ServerMAC', new Uint8Array(0), Nh);
  const km3 = expandLabel(handshakeSecret, 'ClientMAC', new Uint8Array(0), Nh);

  // 6. Verify server's MAC, then emit ours over (preamble || server_mac).
  const expectedServerMac = mac(km2, preambleHash);
  if (!ctEqual(expectedServerMac, ke2.serverMac)) {
    throw new Error('Server MAC verification failed');
  }

  const clientMac = mac(km3, hash(concat(preamble, ke2.serverMac)));

  return {
    ke3: { clientMac },
    sessionKey,
    exportKey
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
