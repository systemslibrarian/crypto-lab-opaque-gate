# crypto-lab-opaque-gate

## What It Is

A browser-based educational demo of **OPAQUE** (RFC 9807, July 2025) — an Augmented Password-Authenticated Key Exchange (aPAKE) where **the server never sees the password**, not during registration, not during login, not ever.

This is the most practically relevant password authentication scheme for the post-hash-compromise era:

- **Registration**: Client generates credentials, encrypts them with a key derived from the password via an Oblivious PRF. Server stores only the encrypted envelope, the OPRF evaluation key, and the client's public key. Zero password bytes.

- **Login**: Client blinds the password with a random factor. Server evaluates it with a secret key (only known to the server). Client unblinds the result to recover the key that opens the credential envelope. Server never sees the unblinded value, never sees the password.

- **Mutual Authentication & Forward Secrecy**: Three Diffie-Hellman operations provide mutual proof that both client and server know the recovered credentials, with ephemeral keys ensuring forward secrecy (if session keys are leaked, future sessions are safe).

**Key property**: If the server database is breached:
- Attacker has encrypted credential envelope + OPRF key
- Offline dictionary attack _is_ possible (but requires 1+ evaluation per guess, same computational cost as bcrypt cost-10)
- No plaintext password exposed; no rainbow tables work (OPRF key varies per user)
- Pre-computation attacks are **impossible**

## When to Use It

- Replacing bcrypt+TLS password authentication in applications where database breaches are a concern
- Patron portal authentication in library systems (ILS, self-checkout, staff login)
- Understanding why current password hashing (even modern schemes) still exposes credentials to offline attacks
- Any system where you want to eliminate "password compromise in a breach" from the threat model
- Do NOT deploy this in production — it is a teaching demo with both client and server simulated in one browser; use a vetted PAKE library in real systems.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-opaque-gate](https://systemslibrarian.github.io/crypto-lab-opaque-gate/)**

The demo simulates both client and server in one browser across five interactive exhibits: why plaintext and hashed password auth is broken, the blind/evaluate/unblind OPRF flow showing what the server sees versus never sees, the full KE1 → KE2 → KE3 registration and login message flow with session-key agreement and mutual authentication, a server-breach simulation that shows why offline dictionary attacks are possible but pre-computation is not, and a tour of real-world deployments.

## What Can Go Wrong

- **Validated, but not audited.** Every named intermediate and output matches the CFRG `vectors.json` for P256-SHA256 byte-for-byte (`src/test-vectors.ts` — 17 checks across one Real and one Fake vector), and the spec-derived protocol properties pass (`src/verify.ts` — 10 checks). That's strong evidence each derivation matches RFC 9807, but it isn't a substitute for the testing, fuzzing, constant-time review, and side-channel analysis a production deployment needs. Use a vetted PAKE library in real systems.
- **Offline attack surface with OPRF key compromise.** If an attacker gets the server's OPRF key for a user (via database breach), they can try offline password guesses. Each guess costs one OPRF evaluation plus one `stretch()` (scrypt N=2^15 here ≈ 50 ms). OPAQUE's advantages: pre-computation is impossible (the OPRF key varies per user), no plaintext password exposure, mutual authentication + forward secrecy.
- **Registration requires TLS.** OPAQUE doesn't bootstrap trust from nothing. First registration assumes the client can trust the server (via TLS). Subsequent logins are password-only. By design (RFC 9807 §10); real deployments may layer additional factors on top.
- **No backend in this demo.** All crypto runs client-side; both "sides" are simulated in the same browser. Real deployments need a server to store registration records, perform OPRF evaluations (server's OPRF key never leaves), enforce rate limits to slow online attacks, and possibly use an HSM to protect OPRF keys.
- **Only the P256-SHA256 suite is validated.** The CFRG publishes vectors for ristretto255-SHA512 as well; supporting them requires generalizing this codebase across OPRF groups. The framework in `src/test-vectors.ts` is ready for them.

## Real-World Usage

- **RFC 9807** was published by the IRTF Crypto Forum Research Group in July 2025. Authors: Hugo Krawczyk (AWS; also designed HMAC, HKDF, Noise, IKE), Kevin Lewi (Meta, WhatsApp E2E Encrypted Backups), Christopher Wood (Cloudflare), and Stanislaw Jarecki (UC Irvine).
- **WhatsApp** (2021+): End-to-End Encrypted Backups for 300M+ users use an OPAQUE-based construction.
- **Cloudflare Zero Trust**: Exploring OPAQUE for passwordless authentication.
- **Apple Private Cloud Compute**: Uses related OPRF constructions for privacy-preserving authentication.
- **1Password**: Research into OPAQUE for vault unlock.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-opaque-gate
cd crypto-lab-opaque-gate
npm install
npm run dev
```

## Related Demos

- [crypto-lab-webauthn](https://systemslibrarian.github.io/crypto-lab-webauthn/) — FIDO2 passkeys, the passwordless alternative to password-based aPAKE.
- [crypto-lab-x3dh-wire](https://systemslibrarian.github.io/crypto-lab-x3dh-wire/) — X25519 asynchronous key agreement from the Signal protocol.
- [crypto-lab-psi-gate](https://systemslibrarian.github.io/crypto-lab-psi-gate/) — also built on an OPRF (DH-PSI) for private contact discovery.
- [crypto-lab-noise-pipe](https://systemslibrarian.github.io/crypto-lab-noise-pipe/) — X25519 handshake patterns and key exchange.

## Stack

- **Vite** + TypeScript (strict mode)
- **[@noble/curves](https://github.com/paulmillr/noble-curves)** for the
  P-256 ECC and the RFC 9497 OPRF (audited, ~25 KB gzipped contribution)
- **[@noble/hashes](https://github.com/paulmillr/noble-hashes)** for HKDF,
  HMAC, and scrypt
- **WebCrypto** for randomness (`crypto.getRandomValues`)
- **Vanilla CSS** with light/dark theme toggle
- Deployable to **GitHub Pages** (no backend)
- Mobile-first, responsive layout
- WCAG 2.1 AA compliant

## How OPAQUE Works

### Component 1: OPRF (Oblivious Pseudorandom Function)

The server has a secret key **k**. The client has a password **pwd**. An OPRF computes F(k, pwd) such that:

1. **Client blinds**: Generate random factor _r_, send blinded(pwd) to server
2. **Server evaluates**: Compute evaluated = F(k, blinded), send back
3. **Client unblinds**: Compute rwd = F(k, pwd) without ever learning k or sending pwd

The server sees only _blinded_ values (look like random noise). The client computes the final key _rwd_.

**Implementation**: real RFC 9497 OPRF on NIST P-256 with hash-to-curve
(SSWU map), via `@noble/curves`. The blind, evaluate, and unblind steps
use scalar multiplication on the curve — not HKDF stand-ins. The final
`oprf_output` is `Hash(input || N || "Finalize")` where `N = r⁻¹·evaluated`.

### Component 2: Credential Envelope (RFC 9807 §4, internal mode)

The client's long-term private key is _not_ encrypted — it's *derived*
from the OPRF output. The envelope is just a MAC tag that proves the
server hasn't tampered with the credentials.

```
oprf_output      = OPRF.Finalize(password, blind, evaluated)
randomized_pwd   = HKDF-Extract("", oprf_output || stretch(oprf_output))
envelope_nonce   = random(32)

seed             = HKDF-Expand(randomized_pwd, envelope_nonce || "PrivateKey", 32)
(client_sk, pk)  = DeriveAuthKeyPair(seed)
auth_key         = HKDF-Expand(randomized_pwd, envelope_nonce || "AuthKey", 32)
export_key       = HKDF-Expand(randomized_pwd, envelope_nonce || "ExportKey", 32)
masking_key      = HKDF-Expand(randomized_pwd, "MaskingKey", 32)

envelope         = envelope_nonce || HMAC(auth_key, envelope_nonce || cleartext_creds)
```

Same password → same `randomized_pwd` → same `client_sk` and same
`envelope` MAC. Wrong password (or tampered envelope) → MAC mismatch on
recovery. The `stretch` step (scrypt N=2^15 by default) is what makes
each guess in an offline attack expensive.

Server stores: `{credential_identifier, client_public_key, masking_key, envelope, oprf_key}`.
**No password material on the server.**

### Component 3: 3DH AKE (RFC 9807 §6, internal mode)

After OPRF unblinding and envelope recovery, both sides compute three
Diffie-Hellman shared secrets:

```
dh1 = DH(client_eph_sk, server_eph_pk)     [ephemeral × ephemeral — fresh-fresh]
dh2 = DH(client_eph_sk, server_static_pk)  [ephemeral × static    — fresh-server]
dh3 = DH(client_static_sk, server_eph_pk)  [static × ephemeral    — client-fresh]
```

These feed an HKDF-based key schedule that derives separate keys for
each direction:

```
prk              = HKDF-Extract("", dh1 || dh2 || dh3)
handshake_secret = Derive-Secret(prk, "HandshakeSecret", H(preamble))
session_key      = Derive-Secret(prk, "SessionKey",      H(preamble))
km2              = Expand-Label(handshake_secret, "ServerMAC", "", 32)
km3              = Expand-Label(handshake_secret, "ClientMAC", "", 32)

server_mac       = HMAC(km2, H(preamble))
client_mac       = HMAC(km3, H(preamble || server_mac))
```

- **dh1** provides "fresh × fresh" forward secrecy.
- **dh2 + dh3** mix in long-term keys, giving mutual authentication.
- The preamble commits to context, identities, KE1, the credential
  response, and the server's keyshare — any byte modified by an attacker
  changes `H(preamble)` and breaks both MACs.

## Library Patron Context

Current library systems send patron passwords to ILS servers (or store hashes):

```
Patron enters password → TLS → ILS server hashes and compares → database
```

Risk: ILS database breach → patron passwords (or hashes) leaked → credential stuffing, reuse attacks

OPAQUE deployment would mean:

```
Patron enters password (never leaves device) → 
  Blind with OPRF → 
  Server evaluates (returns encrypted credentials) → 
  Patron decrypts locally → 
  3DH session established

Breach: Encrypted envelope + OPRF key (useless without password)
Auth failure: Attacker cannot forge login without correct password
```

**Practical path**: SirsiDynix Symphony, Innovative Interfaces Polaris, EBSCO Discovery Service could integrate OPAQUE. Requires vendor adoption; no standards barrier (RFC 9807 is published).

## Exhibit Tour

The demo includes five interactive exhibits:

1. **Why Current Password Auth Is Broken**: Compare plaintext, hashed, and OPAQUE to show the breach risk at each level.

2. **The OPRF**: Interactive blind/evaluate/unblind flow showing what server sees vs. never sees.

3. **Registration and Login Protocol**: Full message flow (KE1 → KE2 → KE3) with session key agreement and mutual authentication.

4. **Server Breach Simulation**: Analyze attack scenarios when the database is compromised. Show why offline dictionary attacks _are_ possible with OPRF key, but pre-computation is impossible.

5. **Real-World Deployments**: WhatsApp, Cloudflare, Apple, 1Password. Library patron privacy impact.

## No Math.random()

All randomness uses `crypto.getRandomValues()`. No `Math.random()` anywhere in the codebase.

```bash
grep -r "Math.random" src/
# Output: (empty)
```

## Build & Run

```bash
npm install
npm run build        # TypeScript strict, zero errors
npm run dev          # Local development server
```

The built output is in `dist/` — ready to deploy to GitHub Pages.

## Code Architecture

```
src/
  oprf.ts          — RFC 9497 OPRF wrapper (@noble/curves) + demo wrappers
  kdf.ts           — HKDF, Expand-Label, Derive-Secret, DeriveKeyPair,
                     stretch (scrypt + identity), dh()
  envelope.ts      — RFC 9807 §4 Store / Recover, register()
  ake.ts           — RFC 9807 §6 KE1 / KE2 / KE3, masked credential
                     response, full key schedule
  verify.ts        — protocol-property tests (round-trip, tampering, FS)
  test-vectors.ts  — RFC 9807 §C P256-SHA256 vector validation
                     (Real + Fake-login)
  main.ts          — UI: five interactive exhibits
  style.css        — Dark/light theme, responsive, accessible
```

## Security Considerations

- **Password strength**: OPAQUE assumes strong passwords. Weak passwords can be cracked offline (same as bcrypt).
- **OPRF key protection**: Server OPRF key (k) must be protected. If leaked, offline attacks become practical. Use HSM or key management service in production.
- **TLS**: All communication should still be over TLS (OPAQUE is not a replacement for transport security).
- **Rate limiting**: Server should limit login attempts to slow offline attacks.
- **Session key reuse**: Session keys are ephemeral and discarded after use. They don't protect across sessions.

## WCAG 2.1 AA Compliance

- Keyboard navigation (all buttons, inputs, tabs focusable)
- `aria-label` on all inputs and code blocks
- `role="alert"` on errors
- High contrast light/dark themes
- `prefers-color-scheme` NOT used (explicit toggle instead)
- Mobile-first responsive design (320px+)
- Focus outlines on all interactive elements

## Repository Description (GitHub)

Browser-based OPAQUE aPAKE demo (RFC 9807, July 2025). Real RFC 9497
OPRF on P-256 via `@noble/curves`. RFC 9807-compliant envelope (HMAC
tag + derived static key, no AES), full 3DH key schedule with separate
MAC keys per direction. Validated byte-for-byte against the CFRG
P256-SHA256 test vectors (Real and Fake-login). Password never touches
the server.

## Topics

`cryptography` `pake` `opaque` `password-authentication` `oprf` `authenticated-key-exchange` `3dh` `forward-secrecy` `browser-demo` `educational` `typescript` `vite` `rfc9807` `library-auth` `patron-privacy`

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
