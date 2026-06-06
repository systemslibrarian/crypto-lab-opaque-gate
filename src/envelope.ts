/**
 * Credential envelope (RFC 9807 §4, internal mode).
 *
 * Unlike a naive design, OPAQUE does NOT encrypt the client's static
 * private key. Instead:
 *
 *   - The OPRF output is stretched into `randomized_pwd`.
 *   - `Expand-Label(randomized_pwd, "PrivateKey", envelope_nonce, Nseed)`
 *     produces the seed for DeriveAuthKeyPair, which gives the client's
 *     static keypair. Same password ⇒ same seed ⇒ same keypair.
 *   - The envelope itself is just `envelope_nonce || HMAC(auth_key,
 *     envelope_nonce || cleartext_credentials)`. The MAC tag lets the
 *     client detect tampering by the server.
 *
 * This is what makes server-side offline attack cost = 1 OPRF + 1 stretch
 * per guess: an attacker who breaches the server only learns the OPRF
 * key, the masking_key, and the envelope. None of those reveal anything
 * useful without first running the OPRF on a candidate password.
 */

import {
  Nh,
  Nn,
  Nm,
  Nseed,
  Npk,
  concat,
  i2osp,
  expandLabel,
  mac,
  ctEqual,
  stretch,
  deriveAuthKeyPair
} from './kdf';
import { oprfBlind, oprfBlindEvaluate, oprfFinalize } from './oprf';

export const ENVELOPE_LENGTH = Nn + Nm; // 64 bytes
export const MASKED_RESPONSE_LENGTH = Npk + ENVELOPE_LENGTH; // 97 bytes

/**
 * Server's per-user record after registration. Contains NO password material;
 * an attacker who steals this database still has to brute-force the OPRF.
 */
export interface RegistrationRecord {
  credentialIdentifier: string;
  clientPublicKey: Uint8Array; // 33 bytes (compressed)
  maskingKey: Uint8Array; // Nh bytes
  envelope: Uint8Array; // envelope_nonce || auth_tag = 64 bytes
  /**
   * The per-user OPRF key. In RFC 9807 the server derives this on demand
   * from `oprf_seed + credential_identifier`; we stash it on the record for
   * demo simplicity (one less piece of global state to thread through).
   */
  oprfKey: Uint8Array;
}

/** Output of `Store` — what the client keeps after registration. */
export interface StoreResult {
  envelope: Uint8Array;
  clientPublicKey: Uint8Array;
  maskingKey: Uint8Array;
  exportKey: Uint8Array;
}

/**
 * CleartextCredentials per RFC 9807 §4.1.4.
 *
 *   server_public_key            (Npk bytes, compressed)
 *   I2OSP(len(server_identity), 2) || server_identity
 *   I2OSP(len(client_identity), 2) || client_identity
 *
 * If an identity is empty, the corresponding public key is substituted.
 */
export function createCleartextCredentials(
  serverPublicKey: Uint8Array,
  serverIdentity: Uint8Array,
  clientIdentity: Uint8Array,
  clientPublicKey: Uint8Array
): Uint8Array {
  const sid = serverIdentity.byteLength === 0 ? serverPublicKey : serverIdentity;
  const cid = clientIdentity.byteLength === 0 ? clientPublicKey : clientIdentity;
  return concat(
    serverPublicKey,
    i2osp(sid.byteLength, 2),
    sid,
    i2osp(cid.byteLength, 2),
    cid
  );
}

/**
 * Store — client-side envelope construction during registration.
 * RFC 9807 §4.3 (CreateRegistrationResponse → FinalizeRegistrationRequest).
 */
export function store(
  randomizedPwd: Uint8Array,
  serverPublicKey: Uint8Array,
  serverIdentity: Uint8Array,
  clientIdentity: Uint8Array
): StoreResult {
  const envelopeNonce = crypto.getRandomValues(new Uint8Array(Nn));

  const maskingKey = expandLabel(
    randomizedPwd,
    'MaskingKey',
    new Uint8Array(0),
    Nh
  );
  const authKey = expandLabel(randomizedPwd, 'AuthKey', envelopeNonce, Nh);
  const exportKey = expandLabel(
    randomizedPwd,
    'ExportKey',
    envelopeNonce,
    Nh
  );
  const seed = expandLabel(
    randomizedPwd,
    'PrivateKey',
    envelopeNonce,
    Nseed
  );

  const { publicKey: clientPublicKey } = deriveAuthKeyPair(seed);

  const cleartextCreds = createCleartextCredentials(
    serverPublicKey,
    serverIdentity,
    clientIdentity,
    clientPublicKey
  );

  const authTag = mac(authKey, concat(envelopeNonce, cleartextCreds));
  const envelope = concat(envelopeNonce, authTag);

  return { envelope, clientPublicKey, maskingKey, exportKey };
}

/**
 * Recover — client-side envelope opening during login.
 * RFC 9807 §4.4. Throws `EnvelopeRecoveryError` if the MAC fails (wrong
 * password, tampered envelope, or wrong server identity).
 */
export function recover(
  randomizedPwd: Uint8Array,
  serverPublicKey: Uint8Array,
  envelope: Uint8Array,
  serverIdentity: Uint8Array,
  clientIdentity: Uint8Array
): {
  clientPrivateKey: Uint8Array;
  clientPublicKey: Uint8Array;
  exportKey: Uint8Array;
} {
  if (envelope.byteLength !== ENVELOPE_LENGTH) {
    throw new Error('Recover: envelope length mismatch');
  }
  const envelopeNonce = envelope.slice(0, Nn);
  const expectedTag = envelope.slice(Nn, Nn + Nm);

  const authKey = expandLabel(randomizedPwd, 'AuthKey', envelopeNonce, Nh);
  const exportKey = expandLabel(
    randomizedPwd,
    'ExportKey',
    envelopeNonce,
    Nh
  );
  const seed = expandLabel(
    randomizedPwd,
    'PrivateKey',
    envelopeNonce,
    Nseed
  );

  const { secretKey: clientPrivateKey, publicKey: clientPublicKey } =
    deriveAuthKeyPair(seed);

  const cleartextCreds = createCleartextCredentials(
    serverPublicKey,
    serverIdentity,
    clientIdentity,
    clientPublicKey
  );

  const actualTag = mac(authKey, concat(envelopeNonce, cleartextCreds));
  if (!ctEqual(actualTag, expectedTag)) {
    throw new Error('EnvelopeRecoveryError: auth tag mismatch');
  }

  return { clientPrivateKey, clientPublicKey, exportKey };
}

/**
 * Full registration (client side, end-to-end).
 *
 *   1. Client blinds password → blinded.
 *   2. Server evaluates blinded under its per-user OPRF key → evaluated.
 *      (Demo: we pass the oprf key in directly; in deployment the server
 *      derives it from oprf_seed + credential_identifier.)
 *   3. Client finalizes → oprf_output.
 *   4. Client stretches → randomized_pwd, then Stores → envelope, masking_key.
 *   5. Record = { client_public_key, masking_key, envelope }.
 */
export async function register(
  password: string,
  username: string,
  oprfKey: Uint8Array,
  serverPublicKey: Uint8Array,
  options: {
    serverIdentity?: Uint8Array;
    clientIdentity?: Uint8Array;
  } = {}
): Promise<{ record: RegistrationRecord; exportKey: Uint8Array }> {
  const passwordBytes = new TextEncoder().encode(password);

  const { blind, blinded } = oprfBlind(passwordBytes);
  const evaluated = oprfBlindEvaluate(oprfKey, blinded);
  const oprfOutput = oprfFinalize(passwordBytes, blind, evaluated);

  const randomizedPwd = stretch(oprfOutput);

  // Default client_identity to the username string, matching what
  // clientLoginStep1 uses by default. Pass `options.clientIdentity` to
  // override (e.g., for a UUID-based application identity).
  const serverIdentity = options.serverIdentity ?? new Uint8Array(0);
  const clientIdentity =
    options.clientIdentity ?? new TextEncoder().encode(username);

  const { envelope, clientPublicKey, maskingKey, exportKey } = store(
    randomizedPwd,
    serverPublicKey,
    serverIdentity,
    clientIdentity
  );

  return {
    record: {
      credentialIdentifier: username,
      clientPublicKey,
      maskingKey,
      envelope,
      oprfKey
    },
    exportKey
  };
}
