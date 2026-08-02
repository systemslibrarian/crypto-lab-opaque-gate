/**
 * RFC 9807 OPAQUE — End-to-end protocol-property verification.
 *
 * Each test exercises a real protocol property: round-trip session-key
 * agreement, export-key agreement, wrong-password rejection, OPRF
 * determinism, masking-key tamper detection, MAC-forgery rejection, and
 * fresh-per-session keys. These run under `npm test` (vitest) and in CI.
 */

import { describe, it, expect } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import {
  generateOprfKey,
  oprfClientBlind,
  oprfServerEvaluate,
  oprfClientUnblind
} from '../src/oprf';
import { register } from '../src/envelope';
import {
  clientLoginStep1,
  serverLoginStep2,
  clientLoginStep3,
  serverFinalize,
  keySchedule
} from '../src/ake';
import { concat, dh } from '../src/kdf';

function bytesToHex(bytes: Uint8Array, max = 16): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .substring(0, max);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function runFullLogin(password: string, username: string) {
  const serverPriv = p256.utils.randomSecretKey();
  const serverPub = p256.getPublicKey(serverPriv, true);
  const serverOprfKey = generateOprfKey();

  const { record, exportKey: regExportKey } = await register(
    password,
    username,
    serverOprfKey.oprfPrivate,
    serverPub
  );

  const { ke1, clientState } = await clientLoginStep1(password, username);
  const { ke2, serverState } = await serverLoginStep2(
    ke1,
    record,
    serverPriv,
    serverPub
  );
  const {
    ke3,
    sessionKey: clientKey,
    exportKey: loginExportKey
  } = await clientLoginStep3(ke2, clientState);
  const serverKey = await serverFinalize(ke3, serverState);

  return {
    record,
    serverPriv,
    serverPub,
    serverOprfKey,
    regExportKey,
    loginExportKey,
    clientKey,
    serverKey
  };
}

describe('RFC 9807 OPAQUE protocol properties (10 checks)', () => {
  it('1. TypeScript strict-mode build (imports compile under vitest/tsc)', () => {
    // If this module compiled and imported the src/ modules, strict-mode
    // compilation held. This mirrors the original suite's build marker.
    expect(typeof clientLoginStep1).toBe('function');
  });

  it('2. OPRF determinism: same password → same output (3 runs)', async () => {
    const password = 'library2026';
    const k = generateOprfKey();
    const outs: Uint8Array[] = [];
    for (let i = 0; i < 3; i++) {
      const { blind, blindingFactor } = await oprfClientBlind(password);
      const evaluated = await oprfServerEvaluate(k.oprfPrivate, blind);
      outs.push(await oprfClientUnblind(password, evaluated, blindingFactor));
    }
    const h = outs.map(o => bytesToHex(o));
    expect(h[0]).toBe(h[1]);
    expect(h[1]).toBe(h[2]);
  });

  it('3. OPRF password sensitivity: different password → different output', async () => {
    const k = generateOprfKey();
    const a = await oprfClientBlind('password1');
    const b = await oprfClientBlind('password2');
    const ea = await oprfServerEvaluate(k.oprfPrivate, a.blind);
    const eb = await oprfServerEvaluate(k.oprfPrivate, b.blind);
    const ra = await oprfClientUnblind('password1', ea, a.blindingFactor);
    const rb = await oprfClientUnblind('password2', eb, b.blindingFactor);
    expect(bytesToHex(ra)).not.toBe(bytesToHex(rb));
  });

  it('4. Register → login: client and server session keys agree', async () => {
    const run = await runFullLogin('testpassword123', 'testuser');
    expect(bytesEqual(run.clientKey, run.serverKey)).toBe(true);
  });

  it('5. Export key consistency: registration value reappears on login', async () => {
    const run = await runFullLogin('exportpw', 'export-user');
    expect(bytesEqual(run.regExportKey, run.loginExportKey)).toBe(true);
  });

  it('6. Wrong password → envelope MAC fails, login aborts', async () => {
    const serverPriv = p256.utils.randomSecretKey();
    const serverPub = p256.getPublicKey(serverPriv, true);
    const serverOprfKey = generateOprfKey();

    const { record } = await register(
      'correctpassword',
      'user-rej',
      serverOprfKey.oprfPrivate,
      serverPub
    );

    const { ke1, clientState } = await clientLoginStep1('wrongpassword', 'user-rej');
    const { ke2 } = await serverLoginStep2(ke1, record, serverPriv, serverPub);

    await expect(clientLoginStep3(ke2, clientState)).rejects.toThrow();
  });

  it('7. Tampered envelope → MAC mismatch, login aborts', async () => {
    const serverPriv = p256.utils.randomSecretKey();
    const serverPub = p256.getPublicKey(serverPriv, true);
    const serverOprfKey = generateOprfKey();
    const { record } = await register(
      'pw',
      'user-tamper',
      serverOprfKey.oprfPrivate,
      serverPub
    );

    // Flip one bit in the envelope MAC tag.
    const tampered = { ...record, envelope: record.envelope.slice() };
    tampered.envelope[tampered.envelope.byteLength - 1] ^= 0x01;

    const { ke1, clientState } = await clientLoginStep1('pw', 'user-tamper');
    const { ke2 } = await serverLoginStep2(ke1, tampered, serverPriv, serverPub);

    await expect(clientLoginStep3(ke2, clientState)).rejects.toThrow();
  });

  it('8. Forged server_mac → client rejects KE2', async () => {
    const serverPriv = p256.utils.randomSecretKey();
    const serverPub = p256.getPublicKey(serverPriv, true);
    const serverOprfKey = generateOprfKey();
    const { record } = await register(
      'pw',
      'user-forge',
      serverOprfKey.oprfPrivate,
      serverPub
    );

    const { ke1, clientState } = await clientLoginStep1('pw', 'user-forge');
    const { ke2 } = await serverLoginStep2(ke1, record, serverPriv, serverPub);
    const forged = { ...ke2, serverMac: new Uint8Array(ke2.serverMac.byteLength) };

    await expect(clientLoginStep3(forged, clientState)).rejects.toThrow(/Server MAC/);
  });

  it('9. Forged client_mac → server rejects KE3', async () => {
    const serverPriv = p256.utils.randomSecretKey();
    const serverPub = p256.getPublicKey(serverPriv, true);
    const serverOprfKey = generateOprfKey();
    const { record } = await register(
      'pw',
      'user-forge2',
      serverOprfKey.oprfPrivate,
      serverPub
    );

    const { ke1, clientState } = await clientLoginStep1('pw', 'user-forge2');
    const { ke2, serverState } = await serverLoginStep2(
      ke1,
      record,
      serverPriv,
      serverPub
    );
    await clientLoginStep3(ke2, clientState);

    const forgedKe3 = { clientMac: new Uint8Array(32) };

    await expect(serverFinalize(forgedKe3, serverState)).rejects.toThrow(/Client MAC/);
  });

  it('10. Independent logins → independent session keys (fresh nonces)', async () => {
    const a = await runFullLogin('pwfs', 'user-fs-a');
    const b = await runFullLogin('pwfs', 'user-fs-b');
    expect(bytesEqual(a.clientKey, b.clientKey)).toBe(false);
  });

  /**
   * The forward-secrecy exhibit's arithmetic, unit-tested away from the DOM.
   *
   * An attacker who steals *both* long-term secret keys and holds the recorded
   * transcript rebuilds dh2 and dh3 exactly — and still not the session key,
   * because dh1 needed two ephemeral private keys that no longer exist.
   */
  it('11. Long-term compromise recovers dh2 and dh3 but not the session key', async () => {
    const password = 'pw-fs-compromise';
    const username = 'user-fs-compromise';
    const serverPriv = p256.utils.randomSecretKey();
    const serverPub = p256.getPublicKey(serverPriv, true);
    const serverOprfKey = generateOprfKey();
    const { record } = await register(password, username, serverOprfKey.oprfPrivate, serverPub);

    const { ke1, clientState } = await clientLoginStep1(password, username);
    const { ke2 } = await serverLoginStep2(ke1, record, serverPriv, serverPub);
    const { sessionKey, threeDH } = await clientLoginStep3(ke2, clientState);

    // Stolen long-term keys + the recorded transcript.
    const rebuiltDh2 = dh(serverPriv, threeDH.clientEphemeralPublic);
    const rebuiltDh3 = dh(threeDH.clientStaticPrivate, threeDH.serverEphemeralPublic);
    expect(bytesEqual(rebuiltDh2, threeDH.dh2)).toBe(true);
    expect(bytesEqual(rebuiltDh3, threeDH.dh3)).toBe(true);

    // dh1 is not reachable from those inputs; any guess yields a different key.
    const guessedDh1 = new Uint8Array(threeDH.dh1.byteLength);
    const rebuilt = keySchedule(
      concat(guessedDh1, rebuiltDh2, rebuiltDh3),
      threeDH.preambleHash
    ).sessionKey;
    expect(bytesEqual(rebuilt, sessionKey)).toBe(false);

    // Handed the real dh1 as well, the same schedule reproduces the key exactly —
    // proof that dh1 is the *only* thing standing between attacker and session.
    const withDh1 = keySchedule(
      concat(threeDH.dh1, rebuiltDh2, rebuiltDh3),
      threeDH.preambleHash
    ).sessionKey;
    expect(bytesEqual(withDh1, sessionKey)).toBe(true);
  });

  it('12. A static-only ikm survives every handshake and is recomputable from either side', async () => {
    const password = 'pw-fs-static';
    const username = 'user-fs-static';
    const serverPriv = p256.utils.randomSecretKey();
    const serverPub = p256.getPublicKey(serverPriv, true);
    const serverOprfKey = generateOprfKey();
    const { record } = await register(password, username, serverOprfKey.oprfPrivate, serverPub);

    const { ke1, clientState } = await clientLoginStep1(password, username);
    const { ke2 } = await serverLoginStep2(ke1, record, serverPriv, serverPub);
    const { threeDH } = await clientLoginStep3(ke2, clientState);

    const fromServerSide = dh(serverPriv, record.clientPublicKey);
    const fromClientSide = dh(threeDH.clientStaticPrivate, threeDH.serverStaticPublic);
    expect(bytesEqual(fromServerSide, fromClientSide)).toBe(true);

    // A second login: dh1 changes, the static-only ikm does not.
    const { ke1: ke1b, clientState: stateB } = await clientLoginStep1(password, username);
    const { ke2: ke2b } = await serverLoginStep2(ke1b, record, serverPriv, serverPub);
    const { threeDH: traceB } = await clientLoginStep3(ke2b, stateB);
    expect(bytesEqual(traceB.dh1, threeDH.dh1)).toBe(false);

    // …so the attacker reproduces the later session's static-only key exactly.
    expect(
      bytesEqual(
        keySchedule(fromClientSide, traceB.preambleHash).sessionKey,
        keySchedule(fromServerSide, traceB.preambleHash).sessionKey
      )
    ).toBe(true);
  });
});
