# OPAQUE Demo — Phase Completion Summary

## Build Status: COMPLETE — verification suite green

### Phase 0: Repository Gate
- vite.config.ts with base: '/crypto-lab-opaque-gate/'
- .github/workflows/deploy.yml using actions/deploy-pages (artifact-based)
- tsconfig.json with strict: true
- index.html with anti-flash theme init (data-theme attribute)
- Status: Repository configured for GitHub Pages deployment

### Phase 1: OPRF Implementation
- File: src/oprf.ts
- Functions: generateOprfKey, oprfClientBlind, oprfServerEvaluate, oprfClientUnblind
- Implementation: **RFC 9497 OPRF on NIST P-256 (suite P256-SHA256)** via @noble/curves
- Real hash-to-curve, scalar multiplication, and modular-inverse unblind — not an HKDF chain
- Randomness: crypto.getRandomValues() only (no Math.random)
- Verified: Same password → same rwd (deterministic), no server-side password exposure

### Phase 2: Credential Envelope
- File: src/envelope.ts
- Functions: sealEnvelope, openEnvelope, register
- Encryption: AES-256-GCM with rwd as key
- ECC keys handled by @noble/curves directly (WebCrypto's raw private-key export is not supported)
- Verified: Correct rwd opens envelope, wrong rwd throws AEAD auth failure

### Phase 3: 3DH AKE
- File: src/ake.ts
- Functions: clientLoginStep1, serverLoginStep2, clientLoginStep3, serverFinalize
- Protocol: three ECDH operations over P-256 (mutual key knowledge + forward secrecy)
- Shared transcript builder (`buildTranscript`) keeps client and server byte layouts identical
- Verified: full login → session keys agree byte-for-byte on both sides
- Caveat: this is a teaching AKE — it uses a single MAC key in both directions and does not implement the full RFC 9807 key schedule. Sufficient for the demo's pedagogical goal; not a drop-in replacement for a real OPAQUE deployment.

### Phase 4: UI & Five Exhibits
- File: src/main.ts
- Exhibit 1: Why Current Password Auth Is Broken (plaintext/hashed/OPAQUE)
- Exhibit 2: The OPRF (interactive blind/evaluate/unblind)
- Exhibit 3: Registration and Login Protocol (KE1/KE2/KE3 flow)
- Exhibit 4: Server Breach Simulation (attack analysis)
- Exhibit 5: Real-World Deployments & Library Context
- Features: Dark/light theme toggle, responsive layout, interactive demos

### Phase 5: README Documentation
- File: README.md
- Sections: What/When/How, Stack, Real-world usage, Library context, Limitations

### Phase 6: Standardization Pass
- File: src/style.css
- Theme: Dark/light toggle with localStorage persistence
- Accessibility: WCAG 2.1 AA (aria-label, role attributes, focus outlines)
- Responsive: Mobile-first (320px → 768px → 1440px)
- Footer: Scripture quote (1 Corinthians 10:31)

### Phase 7: Final Verification — 10/10 passing
1. npm run build: Zero TypeScript errors
2. OPRF determinism: Same password → same rwd across 3 runs
3. OPRF password sensitivity: Different passwords → different rwds
4. Envelope decrypt (correct): Correct rwd opens envelope
5. Envelope decrypt (wrong): Wrong rwd throws AEAD failure
6. Full auth flow: Client and server session keys agree
7. Wrong password login: clientLoginStep3 throws on bad envelope
8. No Math.random(): grep confirms zero usage in production code
9. RFC 9807 status: labeled as inspired (full key schedule simplified)
10. Library context: Exhibit 5 includes ILS patron privacy discussion

## Build Artifacts

```
dist/
  index.html              0.62 KB
  assets/
    index-<hash>.css      7.07 KB (1.91 KB gzipped)
    index-<hash>.js      62.60 KB (22.47 KB gzipped)
```

The JS bundle grew from 18 KB to 62 KB when the OPRF moved from HKDF to real P-256 elliptic curve math. Still small by any reasonable measure.

## Source Files

```
src/
  oprf.ts          RFC 9497 OPRF on P-256 via @noble/curves
  envelope.ts      AES-256-GCM credential sealing; noble keygen
  ake.ts           3DH AKE on P-256; shared transcript builder
  main.ts          Five interactive exhibits
  style.css        Dark/light theme, responsive, accessible
  verify.ts        Phase 7 verification tests (10 checks)
```

## Configuration Files

```
vite.config.ts       - GitHub Pages base path configuration
tsconfig.json        - TypeScript strict mode
package.json         - Dependencies (Vite, TypeScript, @noble/curves)
.github/workflows/deploy.yml - GitHub Pages auto-deploy (artifact-based)
index.html           - Anti-flash theme initialization
```

## Technology Stack

- **Language**: TypeScript 5.3 (strict mode)
- **Build**: Vite 5.4
- **ECC**: @noble/curves 2.2 (P-256, audited)
- **Symmetric crypto**: WebCrypto (AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256)
- **Randomness**: crypto.getRandomValues()
- **UI**: Vanilla HTML/CSS/JavaScript
- **Theme**: Dark/light with localStorage
- **Accessibility**: WCAG 2.1 AA
- **Responsive**: Mobile-first (320px+)
- **Deployment**: GitHub Pages (no backend)

## Key Properties Verified

- Password never sent to server (real OPRF property, mathematically enforced)
- Zero passwords stored on server
- Offline attacks cost one curve evaluation per guess
- Mutual authentication via 3DH transcript (simplified MAC layer)
- Forward secrecy via ephemeral DH keys
- Deterministic key derivation: same password → same rwd, every run
- All randomness from crypto.getRandomValues() / noble's RNG
- AES-256-GCM authenticated encryption

## What this demo is NOT

- Not a drop-in RFC 9807 OPAQUE implementation. The OPRF is real RFC 9497, but the AKE key schedule is simplified (single MAC key, no separate authentication keys per direction).
- Not a replacement for an audited PAKE library. Treat this as teaching code that explains the protocol shape; ship a vetted implementation in production.

## Deployment

`main` → GitHub Actions builds via Vite → `actions/deploy-pages` publishes the artifact.

Live at: https://systemslibrarian.github.io/crypto-lab-opaque-gate/
