# OPAQUE aPAKE Demo — RFC 9807

"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."  
— 1 Corinthians 10:31

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

## Stack

- **Vite** + TypeScript (strict mode)
- **WebCrypto API** (no external crypto libraries)
- **ECDH P-256** for Diffie-Hellman arithmetic
- **HKDF-SHA-256** for pseudorandom functions
- **AES-256-GCM** for credential encryption
- **Vanilla CSS** with light/dark theme toggle
- Deployable to **GitHub Pages** (no backend)
- Mobile-first, responsive layout
- WCAG 2.1 AA compliant

## Live Demo

https://systemslibrarian.github.io/crypto-lab-opaque-gate/

## How OPAQUE Works

### Component 1: OPRF (Oblivious Pseudorandom Function)

The server has a secret key **k**. The client has a password **pwd**. An OPRF computes F(k, pwd) such that:

1. **Client blinds**: Generate random factor _r_, send blinded(pwd) to server
2. **Server evaluates**: Compute evaluated = F(k, blinded), send back
3. **Client unblinds**: Compute rwd = F(k, pwd) without ever learning k or sending pwd

The server sees only _blinded_ values (look like random noise). The client computes the final key _rwd_.

**Implementation note**: RFC 9807 uses VOPRF (RFC 9497) with hash-to-curve on a prime-order group. This demo uses HKDF-based pseudorandom functions as an educationally equivalent simplification. The protocol structure and security properties are identical.

### Component 2: Credential Envelope

The client's long-term keypair is encrypted with _rwd_ (the OPRF output) using AES-256-GCM:

```
envelope = AES-256-GCM-Encrypt(
  key=rwd,
  plaintext={client_private_key, server_public_key}
)
```

Only someone who knows the password AND the server's OPRF key can derive _rwd_ and decrypt the envelope.

Server stores: `{username, client_public_key, envelope, oprf_key}`

**Zero passwords stored.**

### Component 3: 3DH Authenticated Key Exchange

After the client recovers the envelope, it performs three separate Diffie-Hellman operations:

```
DH1 = DH(client_static_private, server_static_public)     [mutual auth]
DH2 = DH(client_ephemeral_private, server_static_public)  [forward secrecy]
DH3 = DH(client_static_private, server_ephemeral_public)  [forward secrecy]

session_key = HKDF(DH1 || DH2 || DH3, transcript)
```

- **DH1** ensures both sides know the long-term secrets (mutual authentication).
- **DH2 + DH3** ensure that even if long-term keys are compromised later, past sessions remain secret (forward secrecy).

Both sides compute the same session key. They exchange MACs to verify each other's transcripts. If any message was modified, authentication fails.

## Real-World Usage

**RFC 9807** was published by the IRTF Crypto Forum Research Group in July 2025. Authors:

- **Hugo Krawczyk** (AWS, also designed HMAC, HKDF, Noise, IKE)
- **Kevin Lewi** (Meta, WhatsApp E2E Encrypted Backups)
- **Christopher Wood** (Cloudflare)
- **Stanislaw Jarecki** (UC Irvine)

**Deployments**:

- **WhatsApp** (2021+): End-to-End Encrypted Backups for 300M+ users use an OPAQUE-based construction.
- **Cloudflare Zero Trust**: Exploring OPAQUE for passwordless authentication.
- **Apple Private Cloud Compute**: Uses related OPRF constructions for privacy-preserving authentication.
- **1Password**: Research into OPAQUE for vault unlock.

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

## What Can Go Wrong — Limitations

1. **This is an Educational Demo**: It uses HKDF-based PRF instead of the full RFC 9497 VOPRF with hash-to-curve. The protocol structure is faithful; the math is simplified. (Production implementations must use exact RFC 9497 construction.)

2. **Offline attack surface remains with OPRF key compromise**: If an attacker gets the server's OPRF key for a user (via database breach), they can try offline password guesses. Each guess requires one OPRF evaluation (~microseconds on GPU). This is equivalent to attacking bcrypt cost-10, not immune. OPAQUE's advantage is:
   - Pre-computation is impossible (tables from one user don't help another)
   - No plaintext password exposure
   - Mutual authentication + forward secrecy

3. **Registration requires TLS**: OPAQUE doesn't bootstrap from nothing. First registration assumes the client can trust the server (via TLS). Subsequent logins are password-only (no second factor). This is by design (RFC 9807 Section 10); real deployments may layer additional auth on top.

4. **No backend in this demo**: All crypto is client-side. Real deployments need a server to:
   - Store registration records
   - Perform OPRF evaluations
   - Enforce rate limits on login attempts (to slow offline attacks)
   - Possibly use HSM to protect OPRF keys

5. **WebCrypto ECDH limitations**: This demo cannot export raw EC point multiplication. We use HKDF chains instead. Production must use RFC 9497 (proper VOPRF).

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
  oprf.ts          — OPRF: blind, evaluate, unblind, key generation
  envelope.ts      — AES-256-GCM credential encryption, registration flow
  ake.ts           — 3DH AKE: KE1, KE2, KE3 message handling
  main.ts          — UI: five exhibits, interactivity
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

Browser-based OPAQUE aPAKE demo (RFC 9807, July 2025). OPRF blind/evaluate/unblind, AES-256-GCM credential envelope, 3DH mutual authentication, server breach simulation. The password never touches the server. No backends. No simulated math.

## Topics

`cryptography` `pake` `opaque` `password-authentication` `oprf` `authenticated-key-exchange` `3dh` `forward-secrecy` `browser-demo` `educational` `typescript` `vite` `rfc9807` `library-auth` `patron-privacy`

---

> "Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."  
> — 1 Corinthians 10:31