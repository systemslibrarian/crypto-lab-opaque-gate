/**
 * Credential Envelope — AES-256-GCM encryption of client credentials.
 *
 * The envelope contains:
 * - Client's static private key (used in 3DH)
 * - Server's static public key (used in 3DH)
 *
 * Encrypted with rwd (from OPRF output). Only someone who knows the
 * password AND the server's OPRF key can derive rwd and decrypt.
 */

import { oprfClientBlind, oprfServerEvaluate, oprfClientUnblind } from './oprf';

/**
 * Client's stored credentials (inside encrypted envelope).
 */
export interface Credentials {
  clientPrivateKey: Uint8Array; // 32-byte private key
  serverPublicKey: Uint8Array; // 65-byte P-256 public key (uncompressed)
}

/**
 * Server's registration record (what the server stores per user).
 * Contains NO password information.
 */
export interface RegistrationRecord {
  credentialIdentifier: string; // username
  clientPublicKey: Uint8Array; // 65-byte P-256 public key
  envelope: Uint8Array; // encrypted credentials
  oprfKey: Uint8Array; // server's OPRF private key for this user
}

/**
 * Seal (encrypt) credentials with rwd using AES-256-GCM.
 * Returns: ciphertext || iv || authTag (96-byte ciphertext, 12-byte IV, 16-byte tag)
 */
export async function sealEnvelope(
  credentials: Credentials,
  rwd: Uint8Array
): Promise<Uint8Array> {
  // Serialize credentials: concat privKey (32) || pubKey (65)
  const credentialBytes = new Uint8Array(97);
  credentialBytes.set(credentials.clientPrivateKey, 0);
  credentialBytes.set(credentials.serverPublicKey, 32);

  // Generate random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Import rwd as AES-256-GCM key
  const key = await crypto.subtle.importKey('raw', rwd, 'AES-GCM', false, [
    'encrypt'
  ]);

  // Encrypt
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    credentialBytes
  );

  // Return: ciphertext (97 bytes, includes auth tag) || iv (12 bytes)
  // Note: AES-GCM auth tag is included in ciphertext
  const result = new Uint8Array(ciphertext.byteLength + 12);
  result.set(new Uint8Array(ciphertext), 0);
  result.set(iv, ciphertext.byteLength);

  return result;
}

/**
 * Open (decrypt) envelope with rwd.
 * Returns credentials or throws if rwd is wrong.
 */
export async function openEnvelope(
  envelope: Uint8Array,
  rwd: Uint8Array
): Promise<Credentials> {
  // Split: ciphertext (113 bytes, 97 + 16 authTag) || iv (12 bytes)
  const ciphertext = envelope.slice(0, envelope.byteLength - 12);
  const iv = envelope.slice(envelope.byteLength - 12);

  // Import rwd as AES-256-GCM key
  const key = await crypto.subtle.importKey('raw', rwd, 'AES-GCM', false, [
    'decrypt'
  ]);

  // Decrypt (throws if auth fails)
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );

  const plaintextArray = new Uint8Array(plaintext);

  // Parse: privKey (32) || pubKey (65)
  return {
    clientPrivateKey: plaintextArray.slice(0, 32),
    serverPublicKey: plaintextArray.slice(32, 97)
  };
}

/**
 * Full registration flow (client-side):
 * 1. Generate client keypair
 * 2. Perform OPRF to get rwd
 * 3. Seal credentials
 * 4. Return record (to send to server) + exportKey
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
  // Step 1: Generate client keypair (P-256)
  const clientKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const clientPublicKeyRaw = await crypto.subtle.exportKey(
    'raw',
    clientKeyPair.publicKey
  );
  const clientPrivateKeyRaw = await crypto.subtle.exportKey(
    'raw',
    clientKeyPair.privateKey
  );

  // Step 2: OPRF blind-evaluate-unblind
  const { blind, blindingFactor } = await oprfClientBlind(password);
  const evaluated = await oprfServerEvaluate(oprfKey, blind);
  const rwd = await oprfClientUnblind(password, evaluated, blindingFactor);

  // Step 3: Seal envelope
  const envelope = await sealEnvelope(
    {
      clientPrivateKey: new Uint8Array(clientPrivateKeyRaw),
      serverPublicKey: serverPublicKey
    },
    rwd
  );

  // Step 4: Export key (RFC 9807: additional per-user key)
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
      clientPublicKey: new Uint8Array(clientPublicKeyRaw),
      envelope: envelope,
      oprfKey: oprfKey
    },
    exportKey: new Uint8Array(exportKeyBits)
  };
}
