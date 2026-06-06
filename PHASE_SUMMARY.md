# OPAQUE Demo — Phase Completion Summary

## Status: RFC 9807-compliant OPAQUE-3DH on P256-SHA256 — validated against §C test vector

The demo implements the internal-mode OPAQUE protocol from RFC 9807 end to end,
on top of the RFC 9497 OPRF from `@noble/curves`. Byte-for-byte agreement with
the published `P256-SHA256` test vector (CFRG `vectors.json`, identity KSF)
across all 16 named intermediate and output values.

### Phase 0: Repository Gate
- vite.config.ts with base: '/crypto-lab-opaque-gate/'
- .github/workflows/deploy.yml using actions/deploy-pages (artifact-based)
- tsconfig.json with strict: true
- index.html with anti-flash theme init

### Phase 1: OPRF — RFC 9497 on P-256
- File: src/oprf.ts
- Thin wrapper around `@noble/curves/nist.js`'s `p256_oprf.oprf`.
- Exposes the three protocol steps (`oprfBlind`, `oprfBlindEvaluate`,
  `oprfFinalize`) and demo-friendly aliases (`oprfClientBlind`,
  `oprfServerEvaluate`, `oprfClientUnblind`).

### Phase 2: KDF & Helpers
- File: src/kdf.ts
- I2OSP, concat, ct-equal, XOR.
- HKDF-Extract / HKDF-Expand (via `@noble/hashes`).
- `Expand-Label` and `Derive-Secret` per RFC 9807 §6.4.2 — `OPAQUE-` prefix,
  length-prefixed label and context. Used by the AKE side of the protocol.
- Envelope-side derivations use **raw HKDF-Expand** with
  `info = envelope_nonce || label` (RFC 9807 §4.3), NOT Expand-Label.
- `deriveRandomizedPassword(oprf_output, stretch)` =
  `HKDF-Extract("", oprf_output || stretch(oprf_output))` (RFC 9807 §4.1).
- `stretch` ships with two implementations: `stretchScrypt` (N=2^15, r=8, p=1
  — default for the demo) and `stretchIdentity` (used by the §C test vectors
  and for debugging). Production should bump scrypt to N=2^17 (OWASP 2023) or
  swap in Argon2id.
- `deriveKeyPair(seed, info)` — RFC 9497 §3.2.1 deterministic keypair
  derivation. Wrapped by `deriveDiffieHellmanKeyPair` (info
  `"OPAQUE-DeriveDiffieHellmanKeyPair"`, used for client static, client
  ephemeral, and server ephemeral) and `deriveOprfKeyPair` (info
  `"OPAQUE-DeriveKeyPair"`, used for per-user OPRF secret).
- `dh()` returns the 33-byte SEC1-compressed shared point (RFC 9807 §6.4).

### Phase 3: Credential Envelope (RFC 9807 §4, internal mode)
- File: src/envelope.ts
- `store(randomized_pwd, server_pub, server_id, client_id)`:
  - Derives `masking_key`, `auth_key`, `export_key`, `seed` via Expand-Label.
  - `(sk, pk) = DeriveAuthKeyPair(seed)` — client static keypair is
    deterministic in `randomized_pwd` and `envelope_nonce`.
  - `envelope = envelope_nonce || HMAC(auth_key, envelope_nonce || cleartext_creds)`.
  - No AES encryption of the private key.
- `recover()` — inverse of `store`, throws on auth_tag mismatch (wrong
  password or tampered envelope).
- `createCleartextCredentials()` — RFC 9807 §4.1.4 length-prefixed format.
- `register()` runs the OPRF, stretches, calls `store`, and produces the
  `RegistrationRecord` the server holds.

### Phase 4: 3DH AKE (RFC 9807 §6)
- File: src/ake.ts
- Three messages with RFC-correct serialization:
  - **KE1**: `blinded_message || client_nonce || client_keyshare`
  - **KE2**: `(evaluated_message || masking_nonce || masked_response) ||
              server_nonce || server_keyshare || server_mac`
  - **KE3**: `client_mac`
- `masked_response = (server_pub || envelope) XOR
   HKDF-Expand(masking_key, masking_nonce || "CredentialResponsePad")`
- 3DH ordering matches RFC 9807 §6.4.4: `(eph-eph, eph-static, static-eph)`.
- Key schedule:
  - `prk = HKDF-Extract("", dh1||dh2||dh3)`
  - `handshake_secret = Derive-Secret(prk, "HandshakeSecret", H(preamble))`
  - `session_key      = Derive-Secret(prk, "SessionKey",      H(preamble))`
  - `km2 = Expand-Label(handshake_secret, "ServerMAC", "", Nh)`
  - `km3 = Expand-Label(handshake_secret, "ClientMAC", "", Nh)`
  - `server_mac = MAC(km2, H(preamble))`
  - `client_mac = MAC(km3, H(preamble || server_mac))`
- Preamble (RFC 9807 §6.3) built by a single `buildPreamble` helper that
  matches the CFRG reference byte-for-byte:
  ```
  "OPAQUEv1-" ||
  I2OSP(len(context), 2) || context ||
  I2OSP(len(client_id), 2) || client_id ||
  KE1 ||
  I2OSP(len(server_id), 2) || server_id ||
  credential_response ||
  server_nonce || server_keyshare
  ```
  Note that `server_identity` precedes `credential_response`.

### Phase 5: UI & Five Exhibits
- File: src/main.ts
- Exhibit 1: Why current password auth is broken.
- Exhibit 2: OPRF blind / evaluate / finalize — visualizes the values
  going over the wire.
- Exhibit 3: Full registration + login round-trip; surfaces the session
  key and the export key.
- Exhibit 4: Server breach simulation.
- Exhibit 5: Real-world deployments & library patron context.

### Phase 6: Style & Accessibility
- File: src/style.css
- Dark/light toggle with localStorage persistence.
- WCAG 2.1 AA: aria-labels, role attributes, focus outlines.
- Responsive mobile-first (320px / 768px / 1440px).

### Phase 7: Verification

**`npx tsx src/verify.ts` — protocol property tests (10/10):**

1. TypeScript strict-mode compile.
2. OPRF determinism — 3 runs, identical output.
3. OPRF password sensitivity — different password ⇒ different output.
4. Full RFC 9807 register→login round-trip — `client_session_key == server_session_key`.
5. Export-key consistency — registration's `export_key` reappears on login.
6. Wrong password → envelope MAC fails, login aborts in `Recover`.
7. Bit-flipped envelope → MAC mismatch detected.
8. Forged `server_mac` → client rejects KE2.
9. Forged `client_mac` → server rejects KE3.
10. Two independent logins produce two independent session keys (forward secrecy).

**`npx tsx src/test-vectors.ts` — RFC 9807 §C vector validation (16/16):**

Byte-for-byte comparison against the CFRG `vectors.json` `P256-SHA256` /
Identity-KSF vector for every named intermediate and output:

  `oprf_key`, `registration_request`, `registration_response`,
  `randomized_password`, `masking_key`, `auth_key`, `client_public_key`,
  `envelope`, `export_key`, `registration_upload`, `KE1`, `KE2`, `KE3`,
  `login export_key`, `session_key` (both client and server side).

## Build Artifacts

```
dist/
  index.html              0.62 KB
  assets/index-<hash>.css 7.07 KB (1.91 KB gzipped)
  assets/index-<hash>.js  69.53 KB (25.14 KB gzipped)
```

The JS bundle grew from 18 KB (broken HKDF-as-OPRF) → 62 KB (real OPRF) →
69 KB (full RFC 9807 with scrypt + Expand-Label). Still under 30 KB gzipped.

## Source Files

```
src/
  oprf.ts          RFC 9497 OPRF (noble) + step-by-step demo wrappers; manual blind hook for vectors
  kdf.ts           I2OSP, HKDF, Expand-Label, Derive-Secret, stretch variants, DeriveKeyPair wrappers
  envelope.ts      RFC 9807 §4 Store/Recover, CleartextCredentials, register(); deriveOprfKey from oprf_seed
  ake.ts           RFC 9807 §6 KE1/KE2/KE3, masked credential response, full key schedule
  verify.ts        End-to-end protocol property tests (round-trip, tampering, FS)
  test-vectors.ts  RFC 9807 §C P256-SHA256 vector validation
  main.ts          Five interactive exhibits
  style.css        Dark/light theme, responsive, accessible
```

## Technology Stack

- **Language**: TypeScript 5.3 (strict)
- **Build**: Vite 5.4
- **ECC + OPRF**: @noble/curves 2.2 (audited)
- **HKDF / scrypt / HMAC**: @noble/hashes 2.2
- **Symmetric stretch**: scrypt (N=2^15, r=8, p=1)
- **Randomness**: `crypto.getRandomValues()` and noble's RNG
- **UI**: Vanilla HTML/CSS/JavaScript
- **Deployment**: GitHub Pages (no backend; both sides simulated client-side)

## Properties This Implementation Provides

- Password never sent to server (RFC 9497 OPRF, mathematically enforced).
- Zero password material in the server record — only `client_pub`,
  `masking_key`, `envelope`, and the per-user OPRF key.
- Offline attack cost = one OPRF + one scrypt per guess.
- Mutual authentication via the RFC 9807 key schedule (separate `km2`,
  `km3` MAC keys; `server_mac` and `client_mac` chained through the
  preamble).
- Forward secrecy via ephemeral DH keys (3DH `eph-eph`, `eph-static`,
  `static-eph`).
- Deterministic credential derivation: same password ⇒ same client
  static keypair on every login (RFC 9807 internal mode).
- Tamper-evident envelope (HMAC over `envelope_nonce ||
  cleartext_credentials`).
- All randomness from `crypto.getRandomValues()`.

## What this implementation is NOT

- Not a replacement for an audited PAKE library. It's teaching code that
  reproduces the RFC 9807 §C reference vector — that's strong evidence
  that each derivation matches the spec, but it's still well short of the
  testing, fuzzing, and side-channel review a production deployment needs.
  Use a vetted implementation for production. The library context
  discussion in Exhibit 5 still applies.
- Only one of the published test vectors is checked. Adding the remaining
  P256 and other-suite vectors would extend coverage; the framework in
  `test-vectors.ts` is the right place to add them.

## Deployment

`main` → GitHub Actions builds via Vite → `actions/deploy-pages` publishes the artifact.

Live at: https://systemslibrarian.github.io/crypto-lab-opaque-gate/
