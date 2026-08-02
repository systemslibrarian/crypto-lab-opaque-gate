/**
 * Credential envelope (RFC 9807 §4, internal mode).
 *
 * The envelope's credential-key derivations use *raw* HKDF-Expand with
 * label bytes appended to a per-envelope nonce — NOT the Expand-Label
 * construction used elsewhere in the spec. The AKE side uses Expand-Label.
 *
 *   auth_key    = HKDF-Expand(rwd, envelope_nonce || "AuthKey",    Nh)
 *   export_key  = HKDF-Expand(rwd, envelope_nonce || "ExportKey",  Nh)
 *   seed        = HKDF-Expand(rwd, envelope_nonce || "PrivateKey", Nseed)
 *   masking_key = HKDF-Expand(rwd, "MaskingKey",                    Nh)
 *
 *   (sk, pk) = DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
 *   envelope = envelope_nonce || HMAC(auth_key, envelope_nonce || cleartext_creds)
 *
 * Same password ⇒ same `randomized_pwd` ⇒ same envelope-derived keypair.
 */

import {
  Nh,
  Nn,
  Nm,
  Nseed,
  Npk,
  concat,
  expand,
  mac,
  ctEqual,
  StretchFn,
  stretchScrypt,
  deriveRandomizedPassword,
  deriveDiffieHellmanKeyPair,
  deriveOprfKeyPair
} from './kdf';
import {
  oprfBlind,
  oprfBlindEvaluate,
  oprfFinalize
} from './oprf';

export const ENVELOPE_LENGTH = Nn + Nm; // 64 bytes
export const MASKED_RESPONSE_LENGTH = Npk + ENVELOPE_LENGTH; // 97 bytes
/** Internal-mode envelope contents, exported so learner-facing copy cannot drift. */
export const ENVELOPE_FORMAT = 'nonce + HMAC authentication tag (no ciphertext)';

const LABEL_AUTH_KEY = new TextEncoder().encode('AuthKey');
const LABEL_EXPORT_KEY = new TextEncoder().encode('ExportKey');
const LABEL_PRIVATE_KEY = new TextEncoder().encode('PrivateKey');
const LABEL_MASKING_KEY = new TextEncoder().encode('MaskingKey');
const LABEL_OPRF_KEY = new TextEncoder().encode('OprfKey');

/** Server's per-user record. RFC 9807 stores no password-related material here. */
export interface RegistrationRecord {
  credentialIdentifier: string;
  clientPublicKey: Uint8Array; // 33 bytes (compressed)
  maskingKey: Uint8Array; // Nh bytes
  envelope: Uint8Array; // envelope_nonce || auth_tag = 64 bytes
  /**
   * Per-user OPRF secret. In the spec the server derives this on demand
   * from `oprf_seed + credential_identifier`; we stash it on the record so
   * the demo doesn't need to thread `oprf_seed` everywhere. The vector
   * helpers can still derive it on the fly via `deriveOprfKey()`.
   */
  oprfKey: Uint8Array;
}

export interface StoreResult {
  envelope: Uint8Array;
  clientPublicKey: Uint8Array;
  maskingKey: Uint8Array;
  exportKey: Uint8Array;
}

/**
 * CleartextCredentials per RFC 9807 §4.
 *
 *   server_public_key                       (Npk bytes, compressed)
 *   I2OSP(len(server_identity), 2) || server_identity
 *   I2OSP(len(client_identity), 2) || client_identity
 *
 * Empty identities substitute the corresponding public key.
 */
export function createCleartextCredentials(
  serverPublicKey: Uint8Array,
  serverIdentity: Uint8Array,
  clientIdentity: Uint8Array,
  clientPublicKey: Uint8Array
): Uint8Array {
  const sid = serverIdentity.byteLength === 0 ? serverPublicKey : serverIdentity;
  const cid = clientIdentity.byteLength === 0 ? clientPublicKey : clientIdentity;
  const sidLen = new Uint8Array([(sid.byteLength >> 8) & 0xff, sid.byteLength & 0xff]);
  const cidLen = new Uint8Array([(cid.byteLength >> 8) & 0xff, cid.byteLength & 0xff]);
  return concat(serverPublicKey, sidLen, sid, cidLen, cid);
}

/**
 * Server-side OPRF key derivation per RFC 9807 §5.2.2 (CreateRegistrationResponse).
 *
 *   ikm     = HKDF-Expand(oprf_seed, credential_identifier || "OprfKey", Nok)
 *   oprfKey = DeriveKeyPair(ikm, "OPAQUE-DeriveKeyPair").secretKey
 */
export function deriveOprfKey(
  oprfSeed: Uint8Array,
  credentialIdentifier: Uint8Array
): Uint8Array {
  const ikm = expand(
    oprfSeed,
    concat(credentialIdentifier, LABEL_OPRF_KEY),
    Nseed
  );
  return deriveOprfKeyPair(ikm).secretKey;
}

/**
 * Store — RFC 9807 §4.1.2 (Envelope Creation). Builds the envelope and returns everything the
 * client needs to keep (export_key) plus what the server gets (masking_key,
 * envelope, client_public_key).
 *
 * Pass `options.envelopeNonce` to make the derivation deterministic for
 * testing against published vectors.
 */
export function store(
  randomizedPwd: Uint8Array,
  serverPublicKey: Uint8Array,
  serverIdentity: Uint8Array,
  clientIdentity: Uint8Array,
  options: { envelopeNonce?: Uint8Array } = {}
): StoreResult {
  const envelopeNonce =
    options.envelopeNonce ?? crypto.getRandomValues(new Uint8Array(Nn));

  const maskingKey = expand(randomizedPwd, LABEL_MASKING_KEY, Nh);
  const authKey = expand(
    randomizedPwd,
    concat(envelopeNonce, LABEL_AUTH_KEY),
    Nh
  );
  const exportKey = expand(
    randomizedPwd,
    concat(envelopeNonce, LABEL_EXPORT_KEY),
    Nh
  );
  const seed = expand(
    randomizedPwd,
    concat(envelopeNonce, LABEL_PRIVATE_KEY),
    Nseed
  );

  const { publicKey: clientPublicKey } = deriveDiffieHellmanKeyPair(seed);

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
 * Recover — RFC 9807 §4.1.3 (Envelope Recovery). Throws `EnvelopeRecoveryError` on MAC mismatch.
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

  const authKey = expand(
    randomizedPwd,
    concat(envelopeNonce, LABEL_AUTH_KEY),
    Nh
  );
  const exportKey = expand(
    randomizedPwd,
    concat(envelopeNonce, LABEL_EXPORT_KEY),
    Nh
  );
  const seed = expand(
    randomizedPwd,
    concat(envelopeNonce, LABEL_PRIVATE_KEY),
    Nseed
  );

  const { secretKey: clientPrivateKey, publicKey: clientPublicKey } =
    deriveDiffieHellmanKeyPair(seed);

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
 * Full registration. Pass overrides through `options` for deterministic
 * vector testing.
 */
export async function register(
  password: string,
  username: string,
  oprfKey: Uint8Array,
  serverPublicKey: Uint8Array,
  options: {
    serverIdentity?: Uint8Array;
    clientIdentity?: Uint8Array;
    stretchFn?: StretchFn;
    envelopeNonce?: Uint8Array;
    blind?: Uint8Array; // pre-chosen OPRF blind for vector testing
  } = {}
): Promise<{ record: RegistrationRecord; exportKey: Uint8Array }> {
  const passwordBytes = new TextEncoder().encode(password);
  const stretchFn = options.stretchFn ?? stretchScrypt;

  const { blind, blinded } = oprfBlind(passwordBytes, options.blind);
  const evaluated = oprfBlindEvaluate(oprfKey, blinded);
  const oprfOutput = oprfFinalize(passwordBytes, blind, evaluated);

  const randomizedPwd = deriveRandomizedPassword(oprfOutput, stretchFn);

  const serverIdentity = options.serverIdentity ?? new Uint8Array(0);
  const clientIdentity =
    options.clientIdentity ?? new TextEncoder().encode(username);

  const { envelope, clientPublicKey, maskingKey, exportKey } = store(
    randomizedPwd,
    serverPublicKey,
    serverIdentity,
    clientIdentity,
    { envelopeNonce: options.envelopeNonce }
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
