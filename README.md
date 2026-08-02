# crypto-lab-opaque-gate

## What It Is

A browser-based educational demo of **OPAQUE** (RFC 9807, July 2025) — an Augmented Password-Authenticated Key Exchange (aPAKE) where **the server never sees the password**, not during registration, not during login, not ever.

It opens with a one-screen **map of the whole protocol** (`password → OPRF → RWD → envelope → keys → 3DH → session`, each stage clickable to jump to the exhibit that runs it) so a newcomer meets the three stacked primitives in dependency order before diving into any one of them.

This is the most practically relevant password authentication scheme for the post-hash-compromise era:

- **Registration**: Client derives credentials from the password-assisted OPRF and authenticates them with an HMAC. In internal mode, the server stores an envelope containing only a nonce and HMAC tag, plus the OPRF evaluation key and client's public key. Zero password bytes and no envelope ciphertext.

- **Login**: Client blinds the password with a random factor. Server evaluates it with a secret key (only known to the server). Client unblinds the result, re-derives its credentials, and authenticates the envelope's HMAC tag. Server never sees the unblinded value or the password.

- **Mutual Authentication & Forward Secrecy**: Three Diffie-Hellman operations provide mutual proof that both client and server hold the right long-term keys. One of the three mixes a fresh ephemeral from each side, which is what gives *forward secrecy*: because those ephemeral private keys are discarded when the handshake ends, later compromise of the long-term keys (or of the password, or of the server record) does not let an attacker recompute the session keys of past logins it recorded off the wire.

**Key property**: If the server database is breached:
- Attacker has an authenticated envelope (nonce + HMAC tag, no ciphertext) + OPRF key
- Offline dictionary attack _is_ possible, but each guess costs one OPRF evaluation plus one run of the key-stretching function. Exhibit 4 measures that rate in your own browser rather than quoting a figure; this build uses scrypt N=2^15, r=8, which is memory-hard in a way bcrypt is not, so the two are not interchangeable cost units.
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

The demo simulates both client and server in one browser. It opens with a clickable **map of the whole protocol**, then five interactive exhibits: why plaintext and salted-hash password auth is broken (grounded in your own registered envelope), a live obliviousness demo where re-running the OPRF with a fresh blinding factor changes the wire value but not the recovered secret, a *stepped* KE1 → KE2 → KE3 login handshake you walk one message at a time — with cards that cross the CLIENT ↔ SERVER gap, tappable definitions on the jargon in each byte-grid label, a wrong-password path where you watch the envelope MAC fail, and — on success — a **drawn 3DH diagram** (four keypairs, three labeled pairings feeding one session key) plus a *poke-the-forward-secrecy* button, a server-breach simulation that attacks your real envelope and measures the offline-guess cost live from the browser's actual scrypt, and a tour of real-world deployments.

## What Can Go Wrong

- **Validated, but not audited.** Every named intermediate and output matches the CFRG `vectors.json` for P256-SHA256 byte-for-byte (`tests/test-vectors.test.ts` — 16 checks against a Real vector plus 1 against a Fake-login vector), and the spec-derived protocol properties pass (`tests/verify.test.ts` — 10 checks). These run under `npm test` (vitest) and are enforced in CI on every push, so a regression in any derivation fails the build. That's strong evidence each derivation matches RFC 9807, but it isn't a substitute for the testing, fuzzing, constant-time review, and side-channel analysis a production deployment needs. Use a vetted PAKE library in real systems.
- **Offline attack surface with OPRF key compromise.** If an attacker gets the server's OPRF key for a user (via database breach), they can try offline password guesses. Each guess costs one OPRF evaluation plus one `stretch()` (scrypt N=2^15 here; Exhibit 4 times real guesses in your browser instead of quoting a number). OPAQUE's advantages: pre-computation is impossible (the OPRF key varies per user), no plaintext password exposure, mutual authentication + forward secrecy.
- **Registration requires TLS.** OPAQUE doesn't bootstrap trust from nothing. First registration assumes the client can trust the server (via TLS). Subsequent logins are password-only. By design: RFC 9807 §3.2 states registration is the only stage requiring a server-authenticated channel with confidentiality and integrity. Real deployments may layer additional factors on top.
- **No backend in this demo.** All crypto runs client-side; both "sides" are simulated in the same browser. Real deployments need a server to store registration records, perform OPRF evaluations (server's OPRF key never leaves), enforce rate limits to slow online attacks, and possibly use an HSM to protect OPRF keys.
- **Only the P256-SHA256 suite is validated.** The CFRG publishes vectors for ristretto255-SHA512 as well; supporting them requires generalizing this codebase across OPRF groups. The framework in `tests/test-vectors.test.ts` is ready for them.

## Real-World Usage

- **RFC 9807** was published by the IRTF Crypto Forum Research Group in July 2025. Authors: Daniel Bourdrez, Hugo Krawczyk (AWS; also co-designed HMAC, HKDF, IKE and SIGMA), Kevin Lewi (Meta, WhatsApp E2E Encrypted Backups), and Christopher Wood (Cloudflare). The underlying OPAQUE construction is due to Jarecki, Krawczyk and Xu (EUROCRYPT 2018).
- **WhatsApp** (2021+): End-to-End Encrypted Backups gate the backup key behind a user password held in an HSM-backed Backup Key Vault. Meta's public engineering write-up describes the design without naming OPAQUE, so treat this as adjacent rather than a confirmed deployment; RFC 9807 co-author Kevin Lewi is at Meta.
- **Cloudflare**: Published OPAQUE research and a public interactive demo. Not a shipped production login path.
- **Apple Private Cloud Compute**: A neighbour rather than an example — PCC authorizes requests with single-use RSA Blind Signatures (RFC 9474), not an OPRF.
- **1Password**: Has published research on OPAQUE for vault unlock; ships SRP today.

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
  Server evaluates (returns the masked credential response) →
  Patron unmasks it, verifies the envelope tag, and re-derives credentials locally →
  3DH session established

Breach: Authenticated envelope (nonce + HMAC tag) + OPRF key
Auth failure: Attacker cannot forge login without correct password
```

**Practical path**: SirsiDynix Symphony, Innovative Interfaces Polaris, EBSCO Discovery Service could integrate OPAQUE. Requires vendor adoption; no standards barrier (RFC 9807 is published).

## Exhibit Tour

The demo opens with a **Start Here** map of the whole protocol — `password → OPRF → RWD → envelope → keys → 3DH → session` laid out top to bottom, with the three operations (OPRF, envelope, 3DH) boxed and clickable to jump straight to the exhibit that runs each one. It states the OPRF's *purpose* ("turn a weak password into a strong key the server can't derive") up front, before the mechanics, so the primitives are met in dependency order. Below it are five interactive exhibits:

1. **Why Current Password Auth Is Broken**: Compare plaintext, salted-hash, and OPAQUE breach outcomes. Once you register in Exhibit 3, the OPAQUE row shows *your own* stored envelope bytes — the exact record the server holds — rather than a canned string.

2. **The OPRF**: Leads with a plain statement of *what this stage is for*, then a one-picture "locked box" primer plus a live obliviousness demo. Press **Run OPRF**, then **Run again (fresh r)**, and watch side-by-side runs: the blinding factor `r` and the on-the-wire **Blind** change every time (changed bytes highlighted), while the recovered **RWD** stays byte-for-byte identical (also highlighted) — so the server gets fresh noise it can't correlate, yet the client always recovers the same secret. Expand-on-demand definitions for RWD, envelope, 3DH, aPAKE, and HKDF-Extract.

3. **Registration and the Login Handshake**: Registration shows the client handing the server only a public key, masking key, and envelope (no password, no hash). Login is **stepped**: walk KE1 → KE2 → KE3 one message at a time as each card animates *across* the gap from the sending column to the receiving one, listing what it carries *and what it never carries*. Jargon in the byte-grid labels (`masked_response`, `evaluated_message`, `keyshare`, `preamble`, …) is **tappable** — click a term for an inline definition at the point of confusion. A **wrong-password** checkbox lets you watch envelope recovery fail — the MAC mismatch aborts the handshake at KE3 with the specific broken step named. On a successful login the exhibit **draws the 3DH**: the client and server static + ephemeral keypairs as four labeled dots, the three DH pairings as connecting lines (each labeled with what it buys — `dh1` = forward secrecy, `dh2`/`dh3` = mutual auth) feeding one session-key box, with the real shared-secret bytes shown. A **"Leak the session key and run the attack"** button then turns the forward-secrecy claim into an experiment rather than a paragraph: it runs a *second* complete login, seals traffic under each session key with AES-256-GCM, hands a simulated attacker the leaked session key **and** both long-term secret keys **and** the recorded transcript, and reports which tags actually verified. The attacker rebuilds `dh2` and `dh3` byte-for-byte and still cannot open the second session, because `dh1` needed two ephemeral private keys that no longer exist. The same key schedule is then re-run over a static-only ikm (`DH(client_static, server_static)`, no ephemeral term) and the same attacker decrypts both sessions — the negative case, measured rather than described.

4. **Server Breach Simulation**: Actually runs four attacks against the envelope you registered in Exhibit 3 and prints what happened, not a canned verdict. Attack 1 calls `recover()` with a random RWD and shows the thrown MAC error. Attack 2 is a real offline dictionary attack: several wrong candidates plus the true password, each taken all the way through OPRF evaluation, `randomized_pwd` derivation and `recover()`, with the wall-clock per-guess rate measured from those guesses. Attack 3 evaluates the same password under two different per-user OPRF keys and compares the outputs. Attack 4 forges a KE2 from the stolen record with an attacker-generated server keypair and hands it to the real `clientLoginStep3`. Each verdict is derived from the outcome, so a broken build would report a successful attack.

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
npm test             # RFC 9807 KATs + protocol properties (vitest)
npm run test:a11y    # axe-core WCAG A/AA gate (Playwright)
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
  main.ts          — UI: five interactive exhibits
  style.css        — Dark/light theme, responsive, accessible

tests/                        (run by `npm test`, never shipped in the bundle)
  verify.test.ts       — protocol-property tests (round-trip, tampering, FS)
  test-vectors.test.ts — RFC 9807 §C P256-SHA256 vector validation
                         (Real + Fake-login)
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

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
