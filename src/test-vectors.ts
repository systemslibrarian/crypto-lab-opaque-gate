/**
 * RFC 9807 §C.1 P256-SHA256 internal-mode test vector validation.
 *
 * The vector comes from the CFRG OPAQUE reference repo
 * (poc/vectors/vectors.json). It uses the Identity Stretch (KSF) so the
 * randomized password equals the OPRF output verbatim.
 *
 * Each test compares one intermediate or output byte-for-byte. A failure
 * pinpoints exactly which derivation drifted from the spec.
 */

import { p256, p256_hasher } from '@noble/curves/nist.js';
import {
  Nh,
  Nseed,
  concat,
  expand,
  expandLabel,
  extract,
  deriveSecret,
  mac,
  hash,
  stretchIdentity,
  deriveRandomizedPassword,
  deriveDiffieHellmanKeyPair,
  dh
} from './kdf';
import { oprfBlind, oprfBlindEvaluate, oprfFinalize } from './oprf';
import {
  store,
  recover,
  deriveOprfKey,
  createCleartextCredentials,
  RegistrationRecord
} from './envelope';
import {
  clientLoginStep1,
  serverLoginStep2,
  clientLoginStep3,
  serverFinalize,
  serializeKE1,
  serializeCredentialResponse,
  deserializeKE1
} from './ake';

// ============================================================
// Vector (RFC 9807 §C P256-SHA256 internal, identity KSF)
// ============================================================

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.byteLength; i++) {
    out[i] = parseInt(s.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
  return true;
}

function toHex(b: Uint8Array): string {
  return Array.from(b)
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
}

/** big-endian 32-byte scalar → bigint */
function bytesToScalar(b: Uint8Array): bigint {
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  return n;
}

/**
 * Manual OPRF blind for testing: we pass in the scalar `r` directly (which
 * noble's `blind()` won't accept — it samples via hash-to-field). Uses
 * noble's hashToCurve internally with the RFC 9497 OPRF DST so the blinded
 * point bytes line up with the published vector.
 */
const OPRF_HASH_TO_GROUP_DST = new TextEncoder().encode(
  'HashToGroup-OPRFV1-\x00-P256-SHA256'
);

function manualBlind(input: Uint8Array, blindScalar: Uint8Array): Uint8Array {
  const M = p256_hasher.hashToCurve(input, { DST: OPRF_HASH_TO_GROUP_DST });
  const r = bytesToScalar(blindScalar);
  return M.multiply(r).toBytes(true); // compressed 33-byte point
}

const V = {
  context: hex('4f50415155452d504f43'), // "OPAQUE-POC"
  blind_login: hex('c497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1'),
  blind_registration: hex('411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153'),
  client_keyshare_seed: hex('633b875d74d1556d2a2789309972b06db21dfcc4f5ad51d7e74d783b7cfab8dc'),
  client_nonce: hex('ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1'),
  credential_identifier: hex('31323334'), // "1234"
  envelope_nonce: hex('a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f'),
  masking_nonce: hex('38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d'),
  oprf_seed: hex('62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2'),
  password: hex('436f7272656374486f72736542617474657279537461706c65'),
  server_keyshare_seed: hex('05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f'),
  server_nonce: hex('71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1'),
  server_private_key: hex('c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5'),
  server_public_key: hex('035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874'),

  // intermediates
  auth_key: hex('5bd4be1602516092dc5078f8d699f5721dc1720a49fb80d8e5c16377abd0987b'),
  client_mac_key: hex('afdc53910c25183b08b930e6953c35b3466276736d9de2e9c5efaf150f4082c5'),
  client_public_key: hex('03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae5214'),
  envelope: hex('a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8'),
  handshake_secret: hex('83a932431a8f25bad042f008efa2b07c6cd0faa8285f335b6363546a9f9b235f'),
  masking_key: hex('7f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aaf'),
  oprf_key: hex('2dfb5cb9aa1476093be74ca0d43e5b02862a05f5d6972614d7433acdc66f7f31'),
  randomized_password: hex('06be0a1a51d56557a3adad57ba29c5510565dcd8b5078fa319151b9382258fb0'),
  server_mac_key: hex('13e928581febfad28855e3e7f03306d61bd69489686f621535d44a1365b73b0d'),

  // outputs
  KE1: hex('037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6'),
  KE2: hex('0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae26837b6ce688bf9af2542f04eec9ab96a1b9328812dc2f5c89182ed47fead61f09f71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a103c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b50a73b145bc87a157e8c58c0342e2047ee22ae37b63db17e0a82a30fcc4ecf7b'),
  KE3: hex('e97cab4433aa39d598e76f13e768bba61c682947bdcf9936035e8a3a3ebfb66e'),
  export_key: hex('c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b'),
  registration_request: hex('029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8'),
  registration_response: hex('0350d3694c00978f00a5ce7cd08a00547e4ab5fb5fc2b2f6717cdaa6c89136efef035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874'),
  registration_upload: hex('03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8'),
  session_key: hex('484ad345715ccce138ca49e4ea362c6183f0949aaaa1125dc3bc3f80876e7cd1')
};

// ============================================================
// Checks
// ============================================================

interface CheckResult { name: string; ok: boolean; detail?: string }

function check(name: string, actual: Uint8Array, expected: Uint8Array): CheckResult {
  const ok = bytesEqual(actual, expected);
  if (ok) {
    return { name, ok };
  }
  return {
    name,
    ok,
    detail: `\n     actual:   ${toHex(actual)}\n     expected: ${toHex(expected)}`
  };
}

async function runVectorChecks(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const password = new TextDecoder().decode(V.password);

  // --- Server-side OPRF key derivation ---
  const oprfKey = deriveOprfKey(V.oprf_seed, V.credential_identifier);
  results.push(check('oprf_key derivation', oprfKey, V.oprf_key));

  // --- OPRF (registration blind) ---
  // Noble's blind() can't accept a pre-chosen scalar (it samples via
  // hash_to_field), so we do the blind multiplication manually using the
  // RFC 9497 HashToGroup DST and the vector's scalar `r`.
  const regRequest = manualBlind(V.password, V.blind_registration);
  results.push(check('registration_request', regRequest, V.registration_request));

  // --- Server evaluates registration request ---
  const regEvaluated = oprfBlindEvaluate(oprfKey, regRequest);
  // registration_response = evaluated_message || server_public_key
  results.push(check('registration_response', concat(regEvaluated, V.server_public_key), V.registration_response));

  // --- Client finalize OPRF and derive randomized_password ---
  const oprfOutput = oprfFinalize(V.password, V.blind_registration, regEvaluated);
  const randomizedPwd = deriveRandomizedPassword(oprfOutput, stretchIdentity);
  results.push(check('randomized_password', randomizedPwd, V.randomized_password));

  // --- Envelope-derived keys ---
  const maskingKey = expand(randomizedPwd, new TextEncoder().encode('MaskingKey'), Nh);
  results.push(check('masking_key', maskingKey, V.masking_key));

  const authKey = expand(randomizedPwd, concat(V.envelope_nonce, new TextEncoder().encode('AuthKey')), Nh);
  results.push(check('auth_key', authKey, V.auth_key));

  // --- Client static keypair from envelope_nonce ---
  const seed = expand(randomizedPwd, concat(V.envelope_nonce, new TextEncoder().encode('PrivateKey')), Nseed);
  const { publicKey: clientPub } = deriveDiffieHellmanKeyPair(seed);
  results.push(check('client_public_key', clientPub, V.client_public_key));

  // --- Store(): envelope construction ---
  // The RFC 9807 vectors leave both identities empty so the substitution
  // rule kicks in (server_id ← server_pub, client_id ← client_pub).
  // credential_identifier is used only for OPRF-key lookup, not as
  // client_identity.
  const storeOut = store(
    randomizedPwd,
    V.server_public_key,
    new Uint8Array(0),
    new Uint8Array(0),
    { envelopeNonce: V.envelope_nonce }
  );
  results.push(check('envelope', storeOut.envelope, V.envelope));
  results.push(check('export_key', storeOut.exportKey, V.export_key));

  // registration_upload = client_public_key || masking_key || envelope
  const regUpload = concat(storeOut.clientPublicKey, storeOut.maskingKey, storeOut.envelope);
  results.push(check('registration_upload', regUpload, V.registration_upload));

  // --- Login flow (deterministic, vector seeds) ---
  const username = new TextDecoder().decode(V.credential_identifier);
  const record: RegistrationRecord = {
    credentialIdentifier: username,
    clientPublicKey: storeOut.clientPublicKey,
    maskingKey: storeOut.maskingKey,
    envelope: storeOut.envelope,
    oprfKey: oprfKey
  };

  // For login we also leave client/server identities empty — vector has none.
  const { ke1, clientState } = await clientLoginStep1(password, '', {
    blind: V.blind_login,
    clientNonce: V.client_nonce,
    clientKeyshareSeed: V.client_keyshare_seed,
    context: V.context,
    stretchFn: stretchIdentity
  });
  results.push(check('KE1', serializeKE1(ke1), V.KE1));

  const { ke2, serverState } = await serverLoginStep2(
    ke1,
    record,
    V.server_private_key,
    V.server_public_key,
    {
      maskingNonce: V.masking_nonce,
      serverNonce: V.server_nonce,
      serverKeyshareSeed: V.server_keyshare_seed,
      context: V.context,
      clientIdentity: new Uint8Array(0)
    }
  );
  const ke2Bytes = concat(serializeCredentialResponse(ke2.credentialResponse), ke2.serverNonce, ke2.serverKeyshare, ke2.serverMac);
  results.push(check('KE2', ke2Bytes, V.KE2));

  const { ke3, sessionKey, exportKey: loginExportKey } = await clientLoginStep3(ke2, clientState);
  results.push(check('KE3', ke3.clientMac, V.KE3));
  results.push(check('login export_key', loginExportKey, V.export_key));
  results.push(check('session_key', sessionKey, V.session_key));

  const serverSessionKey = await serverFinalize(ke3, serverState);
  results.push(check('server session_key', serverSessionKey, V.session_key));

  return results;
}

// ============================================================
// Fake-login vector (RFC 9807 §6.1.2)
//
// When the server has no record for credential_identifier, it fabricates
// one indistinguishable from a real failed login:
//   - fake client_public_key (random/seeded per implementation)
//   - fake masking_key (random/seeded per implementation)
//   - envelope = zeros(Nn + Nm)
//   - oprf_key = deriveOprfKey(oprf_seed, credential_identifier)  // real
// Then runs the normal serverLoginStep2 with this fake record. The vector
// supplies the chosen fake values so the KE2 bytes are reproducible.
// ============================================================

const VF = {
  context: hex('4f50415155452d504f43'),
  client_identity: hex('616c696365'),
  server_identity: hex('626f62'),
  credential_identifier: hex('31323334'),
  oprf_seed: hex('bb1cd59e16ac09bc0cb6d528541695d7eba2239b1613a3db3ade77b36280f725'),
  KE1: hex('0396875da2b4f7749bba411513aea02dc514a48d169d8a9531bd61d3af3fa9baae42d4e61ed3f8d64cdd3b9d153343eca15b9b0d5e388232793c6376bd2d9cfd0a02147a6583983cc9973b5082db5f5070890cb373d70f7ac1b41ed2305361009784'),
  masking_nonce: hex('9c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a6'),
  masking_key: hex('caecc6ccb4cae27cb54d8f3a1af1bac52a3d53107ce08497cdd362b1992e4e5e'),
  client_public_key: hex('03b81708eae026a9370616c22e1e8542fe9dbebd36ce8a2661b708e9628f4a57fc'),
  server_private_key: hex('34fbe7e830be1fe8d2187c97414e3826040cbe49b893b64229bab5e85a5888c7'),
  server_public_key: hex('0221e034c0e202fe883dcfc96802a7624166fed4cfcab4ae30cf5f3290d01c88bf'),
  server_nonce: hex('1e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d12'),
  server_keyshare_seed: hex('360b0937f47d45f6123a4d8f0d0c0814b6120d840ebb8bc5b4f6b62df07f78c2'),

  KE2: hex('0201198dcd13f9792eb75dcfa815f61b049abfe2e3e9456d4bbbceec5f442efd049c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a6facda65ce0a97b9085e7af07f61fd3fdd046d257cbf2183ce8766090b8041a8bf28d79dd4c9031ddc75bb6ddb4c291e639937840e3d39fc0d5a3d6e7723c09f7945df485bcf9aefe3fe82d149e84049e259bb5b33d6a2ff3b25e4bfb7eff0962821e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d12023f82bbb24e75b8683fd13b843cd566efae996cd0016cffdcc24ee2bc937d026f80144878749a69565b433c1040aff67e94f79345de888a877422b9bbe21ec329')
};

async function runFakeVectorCheck(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];

  // Derive the per-user OPRF key just like in the real flow.
  const fakeOprfKey = deriveOprfKey(VF.oprf_seed, VF.credential_identifier);

  // Build the fake record per RFC 9807 §6.1.2: zero envelope, supplied
  // (vector-chosen) masking_key and client_public_key.
  const fakeRecord = {
    credentialIdentifier: new TextDecoder().decode(VF.credential_identifier),
    clientPublicKey: VF.client_public_key,
    maskingKey: VF.masking_key,
    envelope: new Uint8Array(64), // all zeros
    oprfKey: fakeOprfKey
  };

  const ke1 = deserializeKE1(VF.KE1);

  const { ke2 } = await serverLoginStep2(
    ke1,
    fakeRecord,
    VF.server_private_key,
    VF.server_public_key,
    {
      maskingNonce: VF.masking_nonce,
      serverNonce: VF.server_nonce,
      serverKeyshareSeed: VF.server_keyshare_seed,
      context: VF.context,
      clientIdentity: VF.client_identity,
      serverIdentity: VF.server_identity
    }
  );

  const ke2Bytes = concat(
    serializeCredentialResponse(ke2.credentialResponse),
    ke2.serverNonce,
    ke2.serverKeyshare,
    ke2.serverMac
  );
  results.push(check('fake login KE2', ke2Bytes, VF.KE2));

  return results;
}

async function runAll(): Promise<void> {
  let pass = 0;
  let fail = 0;

  const print = (label: string, results: CheckResult[]) => {
    console.log(`\n--- ${label} ---`);
    for (const r of results) {
      if (r.ok) {
        console.log(`✓ ${r.name}`);
        pass++;
      } else {
        console.log(`✗ ${r.name}${r.detail ?? ''}`);
        fail++;
      }
    }
  };

  print('RFC 9807 §C P256-SHA256 Real vector', await runVectorChecks());
  print('RFC 9807 §C P256-SHA256 Fake-login vector', await runFakeVectorCheck());

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

if (typeof window === 'undefined') {
  runAll().catch(e => {
    console.error('Test vector run threw:', e);
    process.exit(1);
  });
}
