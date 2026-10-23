import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import {
  aeadOpen,
  expandLabel,
  MAX_OPRF_INPUT_BYTES,
  Npk,
  stretchIdentity
} from '../src/kdf';
import { generateOprfKey, oprfBlind } from '../src/oprf';
import { recover, register } from '../src/envelope';
import {
  clientLoginStep1,
  deserializeKE1,
  keySchedule,
  serverLoginStep2
} from '../src/ake';

describe('fail-closed protocol boundaries', () => {
  it('rejects empty or overlong application passwords before expensive work', async () => {
    await expect(clientLoginStep1('', 'alice')).rejects.toThrow(/password.*at least 1/i);
    await expect(
      clientLoginStep1('a'.repeat(MAX_OPRF_INPUT_BYTES + 1), 'alice')
    ).rejects.toThrow(/password.*limit/i);
  });

  it('rejects an overlong OPRF input and a zero pre-selected blind', () => {
    expect(() => oprfBlind(new Uint8Array(MAX_OPRF_INPUT_BYTES + 1))).toThrow(/limit/i);
    expect(() => oprfBlind(new Uint8Array([1]), new Uint8Array(32))).toThrow(
      /invalid P-256 secret scalar/i
    );
  });

  it('rejects malformed serialized curve points rather than carrying them forward', () => {
    expect(() => deserializeKE1(new Uint8Array(98))).toThrow(/invalid compressed P-256 point/i);
  });

  it('rejects ambiguous injected ephemeral keys and malformed nonces', async () => {
    const secret = p256.utils.randomSecretKey();
    await expect(
      clientLoginStep1('pw', 'alice', {
        clientKeyshareSeed: new Uint8Array(32).fill(1),
        clientEphemeralPrivate: secret
      })
    ).rejects.toThrow(/seed or private key, not both/i);
    await expect(
      clientLoginStep1('pw', 'alice', { clientNonce: new Uint8Array(31) })
    ).rejects.toThrow(/client nonce.*32 bytes/i);
  });

  it('rejects mismatched server static keypairs before constructing KE2', async () => {
    const serverPrivate = p256.utils.randomSecretKey();
    const serverPublic = p256.getPublicKey(serverPrivate, true);
    const otherPrivate = p256.utils.randomSecretKey();
    const { oprfPrivate } = generateOprfKey();
    const { record } = await register('pw', 'alice', oprfPrivate, serverPublic, {
      stretchFn: stretchIdentity
    });
    const { ke1 } = await clientLoginStep1('pw', 'alice', {
      stretchFn: stretchIdentity
    });

    await expect(
      serverLoginStep2(ke1, record, otherPrivate, serverPublic)
    ).rejects.toThrow(/public key does not match private key/i);
  });

  it('snapshots caller-owned OPRF key material in registration records', async () => {
    const serverPrivate = p256.utils.randomSecretKey();
    const serverPublic = p256.getPublicKey(serverPrivate, true);
    const sourceKey = generateOprfKey().oprfPrivate;
    const expected = sourceKey.slice();
    const { record } = await register('pw', 'alice', sourceKey, serverPublic, {
      stretchFn: stretchIdentity
    });
    sourceKey.fill(0);
    expect(record.oprfKey).toEqual(expected);
  });

  it('rejects malformed envelope, HKDF label, key-schedule, and AEAD inputs', async () => {
    const serverPrivate = p256.utils.randomSecretKey();
    const serverPublic = p256.getPublicKey(serverPrivate, true);
    expect(() =>
      recover(
        new Uint8Array(32),
        serverPublic,
        new Uint8Array(63),
        new Uint8Array(0),
        new Uint8Array(0)
      )
    ).toThrow(/envelope.*64 bytes/i);
    expect(() => expandLabel(new Uint8Array(32), 'x', new Uint8Array(256), 32)).toThrow(
      /context.*255-byte limit/i
    );
    expect(() => keySchedule(new Uint8Array(99), new Uint8Array(31))).toThrow(
      /preamble hash.*32 bytes/i
    );
    expect(() => keySchedule(new Uint8Array(2 * Npk), new Uint8Array(32))).toThrow(
      /expected 33 or 99 bytes/i
    );
    await expect(
      aeadOpen(new Uint8Array(32), new Uint8Array(11), new Uint8Array(16))
    ).rejects.toThrow(/nonce.*12 bytes/i);
  });
});
