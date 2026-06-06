/**
 * Credential Envelope — AES-256-GCM encryption of client credentials.
 *
 * The envelope contains:
 * - Client's static private key (32-byte P-256 scalar, used in 3DH)
 * - Server's static public key (65-byte uncompressed P-256 point)
 *
 * Encrypted with `rwd` (from OPRF output). Only someone who knows the
 * password AND the server's OPRF key can derive rwd and decrypt.
 *
 * ECC key handling uses @noble/curves directly — WebCrypto disallows
 * raw private-key export, so we keep ECC scalars/points outside of
 * crypto.subtle and use WebCrypto only for AES-GCM/HKDF.
 */

import { p256 } from '@noble/curves/nist.js';
import { oprfClientBlind, oprfServerEvaluate, oprfClientUnblind } from './oprf';

export interface Credentials {
  clientPrivateKey: Uint8Array; // 32-byte P-256 scalar
  serverPublicKey: Uint8Array; // 65-byte P-256 uncompressed point
}

/**
 * Server-side record. Contains NO password material — only ECC public data,
 * the encrypted envelope, and the per-user OPRF secret.
 */
export interface RegistrationRecord {
  credentialIdentifier: string;
  clientPublicKey: Uint8Array; // 65-byte uncompressed point
  envelope: Uint8Array;
  oprfKey: Uint8Array;
}

/**
 * Seal credentials with `rwd` using AES-256-GCM.
 * Layout: ciphertext(97 + 16 auth tag) || iv(12) = 125 bytes.
 */
export async function sealEnvelope(
  credentials: Credentials,
  rwd: Uint8Array
): Promise<Uint8Array> {
  const credentialBytes = new Uint8Array(97);
  credentialBytes.set(credentials.clientPrivateKey, 0);
  credentialBytes.set(credentials.serverPublicKey, 32);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const key = await crypto.subtle.importKey('raw', rwd, 'AES-GCM', false, [
    'encrypt'
  ]);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    credentialBytes
  );

  const result = new Uint8Array(ciphertext.byteLength + 12);
  result.set(new Uint8Array(ciphertext), 0);
  result.set(iv, ciphertext.byteLength);

  return result;
}

/** Open envelope with `rwd`. Throws on bad auth tag (wrong rwd). */
export async function openEnvelope(
  envelope: Uint8Array,
  rwd: Uint8Array
): Promise<Credentials> {
  const ciphertext = envelope.slice(0, envelope.byteLength - 12);
  const iv = envelope.slice(envelope.byteLength - 12);

  const key = await crypto.subtle.importKey('raw', rwd, 'AES-GCM', false, [
    'decrypt'
  ]);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );

  const plaintextArray = new Uint8Array(plaintext);

  return {
    clientPrivateKey: plaintextArray.slice(0, 32),
    serverPublicKey: plaintextArray.slice(32, 97)
  };
}

/**
 * Full registration flow (client-side):
 *   1. Generate client static P-256 keypair.
 *   2. Run OPRF (blind → evaluate → unblind) to derive `rwd`.
 *   3. Seal credentials with `rwd`.
 *   4. Derive per-user export key from `rwd`.
 */
export async function register(
  password: string,
  username: string,
  oprfKey: Uint8Array,
  serverPublicKey: Uint8Array
): Promise<{
  record: RegistrationRecord;
  exportKey: Uint8Array;
}> {
  const clientPrivateKey = p256.utils.randomSecretKey();
  const clientPublicKey = p256.getPublicKey(clientPrivateKey, false);

  const { blind, blindingFactor } = await oprfClientBlind(password);
  const evaluated = await oprfServerEvaluate(oprfKey, blind);
  const rwd = await oprfClientUnblind(password, evaluated, blindingFactor);

  const envelope = await sealEnvelope(
    {
      clientPrivateKey,
      serverPublicKey
    },
    rwd
  );

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
      salt: new TextEncoder().encode(username),
      info: new TextEncoder().encode('opaque-exportkey')
    },
    exportKeyMaterial,
    256
  );

  return {
    record: {
      credentialIdentifier: username,
      clientPublicKey,
      envelope,
      oprfKey
    },
    exportKey: new Uint8Array(exportKeyBits)
  };
}
