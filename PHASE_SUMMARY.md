# OPAQUE Demo — Phase Completion Summary

## Status: RFC 9807-compliant OPAQUE-3DH on P256-SHA256

The demo implements the internal-mode OPAQUE protocol from RFC 9807 end to end,
on top of the RFC 9497 OPRF from `@noble/curves`. No more "educational
simplification" disclaimer — the protocol pieces match the spec.

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
  length-prefixed label and context.
- `stretch()` = scrypt(N=2^15, r=8, p=1, dkLen=32). Defaults sized for snappy
  exhibits; production should bump to N=2^17 (OWASP 2023) or switch to
  Argon2id.
- `deriveAuthKeyPair(seed)` — RFC 9807's deterministic keypair derivation
  via RFC 9497 DeriveKeyPair semantics (counter + `hashToScalar`).
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
- Preamble built from `context || client_identity || ke1 ||
  credential_response || server_identity || server_nonce || server_keyshare`
  (RFC 9807 §6.3) — single `buildPreamble` helper is the source of truth.

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

### Phase 7: Verification (10/10 passing)

`npx tsx src/verify.ts`:

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
  oprf.ts          RFC 9497 OPRF (noble) + step-by-step demo wrappers
  kdf.ts           I2OSP, HKDF, Expand-Label, Derive-Secret, stretch, DeriveAuthKeyPair
  envelope.ts      RFC 9807 §4 Store/Recover, CleartextCredentials, register()
  ake.ts           RFC 9807 §6 KE1/KE2/KE3, masked credential response, full key schedule
  verify.ts        End-to-end protocol property tests
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

## What this implementation is NOT (yet)

- Not validated against RFC 9807 test vectors. The protocol logic matches
  the spec section by section, but exhaustive byte-for-byte comparison
  against the published vectors would require seeded-RNG plumbing. Worth
  doing as a follow-up.
- Not a replacement for an audited PAKE library. It's teaching code that
  matches the spec — use a vetted implementation for production
  deployments. The library context discussion in Exhibit 5 still applies.

## Deployment

`main` → GitHub Actions builds via Vite → `actions/deploy-pages` publishes the artifact.

Live at: https://systemslibrarian.github.io/crypto-lab-opaque-gate/
