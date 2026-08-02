/**
 * OPAQUE aPAKE Demo — Five Exhibits
 *
 * Exhibit 1: Why Current Password Auth Is Broken
 * Exhibit 2: The OPRF — Blinding the Password (obliviousness, live)
 * Exhibit 3: Registration and the stepped KE1 → KE2 → KE3 login handshake
 * Exhibit 4: Server Breach Simulation (grounded in the user's own envelope)
 * Exhibit 5: Real-World Deployments and Library Context
 *
 * The cryptography under every exhibit is the real RFC 9807 / RFC 9497
 * implementation from src/oprf.ts, src/envelope.ts, src/ake.ts, src/kdf.ts —
 * spec-accurate and KAT-verified. The exhibits only *visualize* it; they never
 * fake, stub, or weaken a value.
 */

import { p256 } from '@noble/curves/nist.js';
import {
  generateOprfKey,
  oprfClientBlind,
  oprfServerEvaluate,
  oprfClientUnblind,
  oprfBlind,
  oprfBlindEvaluate,
  oprfFinalize
} from './oprf';
import { ENVELOPE_FORMAT, register, recover, RegistrationRecord } from './envelope';
import { stretchScrypt, deriveRandomizedPassword } from './kdf';
import {
  clientLoginStep1,
  serverLoginStep2,
  clientLoginStep3,
  serverFinalize,
  AKEMessage1,
  AKEMessage2,
  AKEMessage3,
  ClientState,
  ServerState,
  ThreeDHTrace
} from './ake';

// ============================================================
// Utility Functions
// ============================================================

/** Full lowercase hex of a byte array (no truncation). */
function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Truncated hex for compact display (first `bytesShown` bytes + ellipsis). */
function bytesToHex(bytes: Uint8Array, bytesShown = 16): string {
  const full = hex(bytes);
  return bytes.byteLength > bytesShown ? full.substring(0, bytesShown * 2) + '…' : full;
}

let exhibitIdCounter = 0;
function createContainer(title: string): HTMLElement {
  const section = document.createElement('section');
  section.className = 'exhibit';
  const headingId = `exhibit-${++exhibitIdCounter}-h`;
  section.setAttribute('aria-labelledby', headingId);
  const heading = document.createElement('h2');
  heading.id = headingId;
  heading.textContent = title;
  section.appendChild(heading);
  return section;
}

function createTwoColumn(): { container: HTMLElement; left: HTMLElement; right: HTMLElement } {
  const container = document.createElement('div');
  container.className = 'two-column';

  const left = document.createElement('div');
  left.className = 'column client-side';
  left.setAttribute('role', 'group');
  left.setAttribute('aria-label', 'Client side');
  left.innerHTML = '<h3>CLIENT</h3>';

  const right = document.createElement('div');
  right.className = 'column server-side';
  right.setAttribute('role', 'group');
  right.setAttribute('aria-label', 'Server side');
  right.innerHTML = '<h3>SERVER</h3>';

  container.appendChild(left);
  container.appendChild(right);

  return { container, left, right };
}

function createButton(label: string, onClick: () => void | Promise<void>): HTMLButtonElement {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.onclick = () => {
    button.disabled = true;
    Promise.resolve(onClick()).finally(() => {
      button.disabled = false;
    });
  };
  return button;
}

let inputIdCounter = 0;
function createLabeledInput(labelText: string, defaultValue?: string): {
  wrap: HTMLElement;
  input: HTMLInputElement;
} {
  const wrap = document.createElement('div');
  wrap.className = 'field';
  const id = `input-${++inputIdCounter}`;
  const label = document.createElement('label');
  label.setAttribute('for', id);
  label.textContent = labelText;
  const input = document.createElement('input');
  input.type = 'text';
  input.id = id;
  input.placeholder = labelText;
  input.autocomplete = 'off';
  input.autocapitalize = 'none';
  input.spellcheck = false;
  if (defaultValue) input.value = defaultValue;
  wrap.appendChild(label);
  wrap.appendChild(input);
  return { wrap, input };
}

/**
 * A named byte value rendered as a byte grid. Each byte is a cell so we can
 * highlight individual bytes that changed between runs. `changedMask` (same
 * length as bytes, true where the byte differs from a previous run) tints the
 * changed cells. Long values are scrollable and get the a11y region treatment.
 */
function createByteGrid(
  title: string,
  bytes: Uint8Array,
  opts: {
    variant?: 'wire' | 'secret' | 'neutral';
    changedMask?: boolean[];
    note?: string;
    maxBytes?: number;
    /** Optional trusted HTML for the label (used for inline tappable terms). */
    labelHtml?: string;
  } = {}
): HTMLElement {
  const wrap = document.createElement('div');
  wrap.className = 'bytegrid-block';

  const label = document.createElement('strong');
  label.className = 'bytegrid-label';
  if (opts.labelHtml) label.innerHTML = opts.labelHtml;
  else label.textContent = title;
  wrap.appendChild(label);

  const maxBytes = opts.maxBytes ?? 24;
  const shown = bytes.subarray(0, maxBytes);

  const grid = document.createElement('div');
  grid.className = `bytegrid bytegrid-${opts.variant ?? 'neutral'}`;
  // Scrollable region needs keyboard access + an accessible name (WCAG).
  grid.tabIndex = 0;
  grid.setAttribute('role', 'region');
  grid.setAttribute(
    'aria-label',
    `${title}: ${bytes.byteLength} bytes, hex ${hex(shown)}${
      bytes.byteLength > maxBytes ? ' (truncated)' : ''
    }`
  );

  shown.forEach((b, i) => {
    const cell = document.createElement('span');
    cell.className = 'byte-cell';
    if (opts.changedMask && opts.changedMask[i]) cell.classList.add('byte-changed');
    cell.setAttribute('aria-hidden', 'true');
    cell.textContent = b.toString(16).padStart(2, '0');
    grid.appendChild(cell);
  });
  if (bytes.byteLength > maxBytes) {
    const more = document.createElement('span');
    more.className = 'byte-more';
    more.setAttribute('aria-hidden', 'true');
    more.textContent = `+${bytes.byteLength - maxBytes}B`;
    grid.appendChild(more);
  }
  wrap.appendChild(grid);

  if (opts.note) {
    const note = document.createElement('span');
    note.className = 'bytegrid-note';
    note.textContent = opts.note;
    wrap.appendChild(note);
  }
  return wrap;
}

/** Status region — added to DOM when needed, announced to AT. */
function createStatusRegion(className: string, isError = false): HTMLElement {
  const div = document.createElement('div');
  div.className = className;
  div.setAttribute('role', isError ? 'alert' : 'status');
  div.setAttribute('aria-live', isError ? 'assertive' : 'polite');
  div.setAttribute('aria-atomic', 'true');
  return div;
}

/** Collapsible "expand for depth" block — progressive disclosure. */
function createDetails(summary: string, bodyHtml: string, className = 'primer'): HTMLElement {
  const details = document.createElement('details');
  details.className = className;
  const sum = document.createElement('summary');
  sum.textContent = summary;
  details.appendChild(sum);
  const body = document.createElement('div');
  body.className = 'details-body';
  body.innerHTML = bodyHtml;
  details.appendChild(body);
  return details;
}

// ============================================================
// Tappable jargon — inline, expand-on-click definitions
// ============================================================

/**
 * One-line definitions for the terms that show up inside byte-grid labels and
 * status text, where a newcomer can't reach the glossary. `term()` wraps a word
 * in a <button> that toggles a small popover with the definition, so the meaning
 * is available at the point of confusion. Definitions are plain text (escaped).
 */
const TERM_DEFS: Record<string, string> = {
  RWD: 'Randomized password: the 32-byte secret the client recovers by unblinding the OPRF. A deterministic function of the password AND the server’s per-user key. Every credential key is derived from it. The server never sees it.',
  randomized_pwd: 'The HKDF-Extract of the (scrypt-stretched) OPRF output. Same thing as the RWD in this demo’s code — the uniform pseudorandom key that every credential key is expanded from.',
  'HKDF-Extract': 'The “concentrate the entropy” half of HKDF (RFC 5869): maps messy input keying material to one uniform pseudorandom key that HKDF-Expand then fans out into named keys.',
  blinded_message: 'The hashed password point multiplied by a fresh random factor r. This is what crosses the wire to the server — it looks like random noise and changes every login.',
  evaluated_message: 'The blinded point after the server multiplied it by its secret OPRF key k. Still blinded, so the server learned nothing; the client will divide out r to finish.',
  masked_response: 'The server’s public key and the user’s envelope, XORed with a keystream derived from the per-user masking_key. Without the right password (→ RWD → masking_key) it is indistinguishable from random.',
  masking_key: 'A per-user key (derived from the RWD) the server uses to mask its response. The client re-derives it from the password on login to unmask the envelope.',
  envelope: `What the server stores per user: ${ENVELOPE_FORMAT}. The client’s long-term private key is NOT stored — it is re-derived from the RWD every login. A wrong password fails the tag.`,
  envelope_nonce: 'The random nonce inside the envelope. Combined with the auth_key it produces the HMAC tag that lets the client detect a wrong password or a tampered record.',
  keyshare: 'An ephemeral (single-use) Diffie-Hellman public key. Each side sends a fresh one per login; mixing the two ephemerals is what gives the session forward secrecy.',
  preamble: 'The handshake transcript: a byte string committing to the context, identities, and every message sent (KE1, the credential response, the server nonce and keyshare). Both MACs are computed over its hash, so any tampering breaks authentication.',
  'server_mac': 'A MAC the server computes over the preamble hash. The client checks it to prove it is talking to the real server (not an impostor) before revealing its own MAC.',
  '3DH': 'Three Diffie-Hellman: the login mixes three DH shared secrets — ephemeral×ephemeral (forward secrecy) plus ephemeral×static and static×ephemeral (mutual authentication) — into one key schedule. Visualized at the end of a successful login.',
  session_key: 'The shared secret both sides independently arrive at after a successful 3DH handshake. Used to encrypt the session. Fresh every login; leaking one reveals nothing about past or future sessions.',
  export_key: 'An extra key the client (only) derives from the RWD, stable across logins. Apps use it to encrypt client-side data (e.g. an E2E-encrypted backup) that even the server can’t read.'
};

let termIdCounter = 0;
/**
 * Return an HTML string for a tappable term. Uses a native popover-less pattern:
 * a <button> with aria-expanded controlling a sibling definition span, wired up
 * by delegated click handling in `wireTerms`. Safe to inject via innerHTML.
 */
function termHtml(word: string, key = word): string {
  const def = TERM_DEFS[key];
  if (!def) return escapeHtml(word);
  const id = `termdef-${++termIdCounter}`;
  return (
    `<span class="jargon-wrap">` +
    `<button type="button" class="jargon" aria-expanded="false" aria-controls="${id}" ` +
    `data-term="${escapeHtml(key)}">${escapeHtml(word)}<span class="jargon-mark" aria-hidden="true">?</span></button>` +
    `<span class="jargon-def" id="${id}" role="tooltip" hidden>${escapeHtml(def)}</span>` +
    `</span>`
  );
}

/** Create a real DOM node for a tappable term (for appendChild call sites). */
function termNode(word: string, key = word): HTMLElement {
  const span = document.createElement('span');
  span.innerHTML = termHtml(word, key);
  return span.firstElementChild as HTMLElement;
}

/** Delegated toggle for all .jargon buttons under `root`. Idempotent per root. */
function wireTerms(root: HTMLElement): void {
  root.addEventListener('click', e => {
    const btn = (e.target as HTMLElement).closest('.jargon') as HTMLButtonElement | null;
    if (!btn || !root.contains(btn)) return;
    const defId = btn.getAttribute('aria-controls');
    const def = defId ? root.querySelector<HTMLElement>(`#${CSS.escape(defId)}`) : null;
    if (!def) return;
    const open = btn.getAttribute('aria-expanded') === 'true';
    // Close any other open term first (one popover at a time).
    root.querySelectorAll<HTMLButtonElement>('.jargon[aria-expanded="true"]').forEach(b => {
      if (b !== btn) {
        b.setAttribute('aria-expanded', 'false');
        const d = b.getAttribute('aria-controls');
        const el = d ? root.querySelector<HTMLElement>(`#${CSS.escape(d)}`) : null;
        if (el) el.hidden = true;
      }
    });
    btn.setAttribute('aria-expanded', String(!open));
    def.hidden = open;
  });
}

// ============================================================
// Shared registration state (Exhibits 3 → 1/4 read the user's real record)
// ============================================================

interface DemoSession {
  record: RegistrationRecord;
  serverPrivate: Uint8Array;
  serverPublic: Uint8Array;
  password: string;
  username: string;
}

let demoSession: DemoSession | null = null;
const sessionListeners: Array<(s: DemoSession | null) => void> = [];
function setDemoSession(s: DemoSession | null): void {
  demoSession = s;
  sessionListeners.forEach(fn => fn(s));
}
function onDemoSession(fn: (s: DemoSession | null) => void): void {
  sessionListeners.push(fn);
  fn(demoSession);
}

// ============================================================
// Jargon primer (progressive disclosure, before Exhibit 2)
// ============================================================

function createGlossary(): HTMLElement {
  const wrap = document.createElement('div');
  wrap.className = 'glossary';

  wrap.appendChild(
    createDetails(
      'New here? What an OPRF is, in one picture',
      `
        <p><strong>The problem.</strong> You want a server to help you turn your
        password into a strong key — but you don't want the server to ever learn
        the password, and you don't want to learn the server's secret key either.</p>
        <p><strong>The picture.</strong> Put your password in a locked box only you
        can open. Hand the box to the server. The server <em>stamps</em> the outside
        with its secret ink and hands the box back — it never saw inside. You open
        the box and read the stamp. That stamp is your key.</p>
        <ul>
          <li><strong>blind</strong> = lock the box (multiply the hashed password by
          a fresh random factor <code>r</code>, so what crosses the wire looks random)</li>
          <li><strong>evaluate</strong> = stamp the box (server multiplies by its
          secret key <code>k</code>, still blinded)</li>
          <li><strong>unblind</strong> = open the box (divide out <code>r</code> to
          get the deterministic result <code>F(k, password)</code>)</li>
        </ul>
        <p>Because <code>r</code> is fresh every time, the box on the wire looks
        different on every run — but you always read the <em>same</em> stamp back.
        That is exactly what Exhibit 2 lets you watch happen.</p>
      `,
      'primer'
    )
  );

  const defs = document.createElement('div');
  defs.className = 'glossary-defs';
  defs.appendChild(
    createDetails(
      'RWD (randomized password / OPRF output)',
      `<p>The 32-byte secret the client recovers after unblinding. It is a
       deterministic function of the password <em>and</em> the server's per-user
       OPRF key. In the code the raw OPRF output is stretched (scrypt) and fed
       into HKDF-Extract to form <code>randomized_pwd</code>, which then derives
       every credential key. Same password + same server key → same RWD, always.</p>`,
      'primer small'
    )
  );
  defs.appendChild(
    createDetails(
      'Envelope',
      `<p>What the server stores per user: a random nonce plus one HMAC tag
       (<code>envelope = nonce || HMAC(auth_key, nonce || cleartext_creds)</code>).
       The client's long-term private key is <em>not</em> stored — it is re-derived
       from the RWD on every login. The tag lets the client detect a wrong password
       or a tampered record: recovery recomputes the MAC and rejects on mismatch.</p>`,
      'primer small'
    )
  );
  defs.appendChild(
    createDetails(
      '3DH (three Diffie-Hellman) authenticated key exchange',
      `<p>The login handshake mixes three DH shared secrets — ephemeral×ephemeral
       (forward secrecy), ephemeral×server-static and client-static×ephemeral
       (mutual authentication) — into one HKDF key schedule. Both sides arrive at
       the same session key <em>and</em> prove they hold the right long-term keys,
       via MACs over a transcript (the "preamble") that commits to everything sent.</p>`,
      'primer small'
    )
  );
  defs.appendChild(
    createDetails(
      'aPAKE / HKDF-Extract',
      `<p><strong>aPAKE</strong> = augmented Password-Authenticated Key Exchange:
       a PAKE where the server stores a password-derived <em>verifier</em>, not the
       password, so a breach can't hand out plaintext. <strong>HKDF-Extract</strong>
       is the "concentrate the entropy" half of HKDF (RFC 5869): it maps messy input
       keying material to a uniform pseudorandom key that HKDF-Expand then fans out.</p>`,
      'primer small'
    )
  );
  wrap.appendChild(defs);
  return wrap;
}

// ============================================================
// Exhibit 0: Map of the whole protocol (overview + jump links)
// ============================================================

/**
 * A one-screen overview shown before the mechanics. It answers the question a
 * newcomer has *before* meeting the OPRF — "why does a password need to become a
 * key at all, and why can't the server just derive it?" — and lays out the whole
 * pipeline as clickable stages that jump to the exhibit that teaches each one.
 */
function createProtocolMap(): HTMLElement {
  const exhibit = createContainer('Start Here: The Whole Protocol on One Screen');

  const intro = document.createElement('p');
  intro.innerHTML = `
    OPAQUE lets you log in with a password <strong>without the server ever learning
    it</strong> — not even a crackable hash of it. To pull that off it chains three
    ideas. Here is the whole pipeline; each stage below jumps to the exhibit that
    shows it running for real. Read it top to bottom once, then dive in.
  `;
  exhibit.appendChild(intro);

  const goal = document.createElement('p');
  goal.className = 'map-goal';
  goal.innerHTML = `
    <strong>The one job:</strong> turn a weak, human password into a strong
    cryptographic key — and do it so the <em>server can’t</em> derive that key on its
    own (so a breach is worthless) yet the <em>right client</em> always can. That is
    what the first stage, the OPRF, buys you. Everything after it uses that key.
  `;
  exhibit.appendChild(goal);

  interface Stage {
    kind: 'value' | 'op';
    label: string;
    sub: string;
    target?: string;
    targetLabel?: string;
  }
  const stages: Stage[] = [
    { kind: 'value', label: 'password', sub: 'weak, human, secret — never leaves the client' },
    {
      kind: 'op',
      label: 'OPRF',
      sub: 'server helps derive a key but stays blind to the password',
      target: 'exhibit-oprf',
      targetLabel: 'Exhibit 2'
    },
    { kind: 'value', label: 'RWD', sub: 'a strong key only the right password can recover' },
    {
      kind: 'op',
      label: 'envelope',
      sub: 'the RWD locks a credential the server stores but can’t open',
      target: 'exhibit-reg',
      targetLabel: 'Exhibit 3'
    },
    { kind: 'value', label: 'client keys', sub: 'long-term identity, re-derived each login' },
    {
      kind: 'op',
      label: '3DH',
      sub: 'three Diffie-Hellmans → mutual auth + forward secrecy',
      target: 'exhibit-login',
      targetLabel: 'Exhibit 3'
    },
    { kind: 'value', label: 'session key', sub: 'shared secret; the server proved its identity too' }
  ];

  const map = document.createElement('ol');
  map.className = 'protocol-map';
  map.setAttribute('aria-label', 'OPAQUE pipeline, password to session key');

  stages.forEach((st, i) => {
    const li = document.createElement('li');
    li.className = `map-stage map-${st.kind}`;

    let node: HTMLElement;
    if (st.target) {
      const a = document.createElement('a');
      a.href = `#${st.target}`;
      a.className = 'map-node map-link';
      a.innerHTML =
        `<span class="map-label">${escapeHtml(st.label)}</span>` +
        `<span class="map-sub">${escapeHtml(st.sub)}</span>` +
        `<span class="map-jump">${escapeHtml(st.targetLabel ?? '')} →</span>`;
      node = a;
    } else {
      const d = document.createElement('div');
      d.className = 'map-node';
      d.innerHTML =
        `<span class="map-label">${escapeHtml(st.label)}</span>` +
        `<span class="map-sub">${escapeHtml(st.sub)}</span>`;
      node = d;
    }
    li.appendChild(node);

    if (i < stages.length - 1) {
      const arrow = document.createElement('span');
      arrow.className = 'map-arrow';
      arrow.setAttribute('aria-hidden', 'true');
      arrow.textContent = '↓';
      li.appendChild(arrow);
    }
    map.appendChild(li);
  });
  exhibit.appendChild(map);

  const legend = document.createElement('p');
  legend.className = 'map-legend';
  legend.innerHTML = `
    <span class="map-chip map-chip-op">boxed</span> = an operation you can watch run.
    <span class="map-chip map-chip-value">plain</span> = a value it produces. The three
    boxed steps are OPAQUE’s three stacked primitives; the exhibits below take them one
    at a time, in this order.
  `;
  exhibit.appendChild(legend);

  return exhibit;
}

// ============================================================
// Exhibit 1: Why Current Password Auth Is Broken
// ============================================================

function createExhibit1(): HTMLElement {
  const exhibit = createContainer('Exhibit 1: Why Current Password Auth Is Broken');

  const description = document.createElement('p');
  description.innerHTML = `
    <strong>Three ways to store a login, three breach outcomes.</strong> Imagine the
    server database just leaked. What does the attacker walk away with?
  `;
  exhibit.appendChild(description);

  const hint = document.createElement('p');
  hint.className = 'exhibit-hint';
  exhibit.appendChild(hint);

  const out = document.createElement('div');
  exhibit.appendChild(out);

  const render = () => {
    out.replaceChildren();
    const s = demoSession;

    const result = createStatusRegion('breach-result');

    // OPAQUE row uses the user's REAL stored envelope from Exhibit 3 when present.
    const envelopeHex = s ? bytesToHex(s.record.envelope, 12) : '(register in Exhibit 3 to see your own)';
    const maskingHex = s ? bytesToHex(s.record.maskingKey, 8) : '—';
    const pw = s ? s.password : 'hunter2';

    result.innerHTML = `
      <div class="breach-option breach-bad">
        <strong>1. Plaintext</strong>
        <span>Server stored the password itself.</span>
        <span class="breach-verdict">Leak = <code>${escapeHtml(pw)}</code> exposed instantly.
        <span aria-hidden="true">❌</span><span class="sr-only"> worst</span></span>
      </div>
      <div class="breach-option breach-warn">
        <strong>2. Salted hash (bcrypt / scrypt)</strong>
        <span>Server stored <code>H(salt, password)</code>. No plaintext — but the hash
        is a verifier the attacker can test offline, one guess at a time.</span>
        <span class="breach-verdict">Leak = offline dictionary attack, bounded only by the
        hash's cost. <span aria-hidden="true">⚠</span><span class="sr-only"> risky</span></span>
      </div>
      <div class="breach-option breach-good">
        <strong>3. OPAQUE</strong>
        <span>Server stored an opaque-looking authenticated <em>envelope</em> + a per-user OPRF key,
        never the password or any password hash.</span>
        <span class="breach-verdict">Your stored envelope: <code>${envelopeHex}</code>
        (masking key <code>${maskingHex}</code>). Without the password it is
        indistinguishable from random, and the OPRF key is useless for precomputation.
        <span aria-hidden="true">✓</span><span class="sr-only"> best</span></span>
      </div>
    `;
    out.appendChild(result);

    const note = document.createElement('p');
    note.className = 'ground-note';
    note.textContent = s
      ? `Grounded in your Exhibit 3 registration (user "${s.username}"): the envelope bytes above are the exact record the server holds — the same bytes Exhibit 4 attacks.`
      : 'Tip: register in Exhibit 3 first — this row then shows YOUR real stored envelope, not a canned string.';
    out.appendChild(note);
  };

  onDemoSession(() => {
    hint.textContent = demoSession
      ? 'Showing your real registered record from Exhibit 3.'
      : '';
    // Only auto-refresh if the user has already opened the breach once.
    if (out.childElementCount) render();
  });

  exhibit.appendChild(
    createButton('Simulate database breach', () => {
      render();
    })
  );

  return exhibit;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string)
  );
}

// ============================================================
// Exhibit 2: The OPRF — obliviousness, demonstrated live
// ============================================================

function createExhibit2(): HTMLElement {
  const exhibit = createContainer('Exhibit 2: The OPRF — Hiding Password from Server');
  exhibit.id = 'exhibit-oprf';

  const purpose = document.createElement('p');
  purpose.className = 'exhibit-purpose';
  purpose.innerHTML = `
    <strong>What this stage is for:</strong> turn the weak password into a strong key
    (the <span class="tag tag-rwd">RWD</span>) that the server helps compute but can
    <em>never</em> derive on its own. That is the whole point of the OPRF — the two
    later stages (envelope, 3DH) just build on the key it produces.
  `;
  exhibit.appendChild(purpose);

  exhibit.appendChild(createGlossary());

  const intro = document.createElement('p');
  intro.innerHTML = `
    Watch the defining property of an OPRF: <strong>every run puts a different
    value on the wire, but you always recover the same secret.</strong> The server
    gets fresh noise each time (so it can't precompute or correlate you); the client
    always lands on the same <span class="tag tag-rwd">RWD</span>.
  `;
  exhibit.appendChild(intro);

  const { wrap: pwWrap, input: pwdInput } = createLabeledInput('Password', 'library2026');
  const controls = document.createElement('div');
  controls.className = 'oprf-controls';
  controls.appendChild(pwWrap);
  exhibit.appendChild(controls);

  const legend = document.createElement('p');
  legend.className = 'legend';
  legend.innerHTML = `
    <span class="swatch swatch-wire" aria-hidden="true"></span>
    <span><span class="tag tag-wire">Blind</span> = what crosses the wire (changes every run)</span>
    &nbsp;&nbsp;
    <span class="swatch swatch-rwd" aria-hidden="true"></span>
    <span><span class="tag tag-rwd">RWD</span> = the recovered secret (stays identical)</span>
  `;
  exhibit.appendChild(legend);

  // Server key is fixed for the exhibit so RWD stability is meaningful.
  const serverKey = generateOprfKey();

  const runsWrap = document.createElement('div');
  runsWrap.className = 'oprf-runs';
  exhibit.appendChild(runsWrap);

  let firstRwd: Uint8Array | null = null;
  let prevBlind: Uint8Array | null = null;
  let runCount = 0;

  const status = createStatusRegion('oprf-status');
  exhibit.appendChild(status);

  const runOnce = async () => {
    const pwd = pwdInput.value || 'library2026';

    // Real RFC 9497 OPRF: fresh random blinding factor r each call.
    const { blind, blindingFactor } = await oprfClientBlind(pwd);
    const evaluated = await oprfServerEvaluate(serverKey.oprfPrivate, blind);
    const rwd = await oprfClientUnblind(pwd, evaluated, blindingFactor);

    runCount += 1;

    const changedMask = prevBlind
      ? Array.from(blind).map((b, i) => b !== (prevBlind as Uint8Array)[i])
      : undefined;
    const rwdChanged = firstRwd
      ? Array.from(rwd).some((b, i) => b !== (firstRwd as Uint8Array)[i])
      : false;

    const card = document.createElement('div');
    card.className = 'oprf-run-card';

    const head = document.createElement('div');
    head.className = 'oprf-run-head';
    head.textContent = `Run ${runCount}`;
    card.appendChild(head);

    const { container, left, right } = createTwoColumn();
    card.appendChild(container);

    left.appendChild(
      createByteGrid('r — blinding factor (secret, client only)', blindingFactor, {
        variant: 'secret',
        note: 'fresh random every run'
      })
    );
    left.appendChild(
      createByteGrid('Blind → to server', blind, {
        variant: 'wire',
        changedMask,
        note:
          runCount === 1
            ? 'first wire value'
            : changedMask && changedMask.some(Boolean)
            ? 'highlighted bytes differ from the previous run'
            : 'identical to previous run'
      })
    );
    right.appendChild(
      createByteGrid('Evaluated ← to client', evaluated, {
        variant: 'wire',
        note: 'server stamped the blinded point with k'
      })
    );
    left.appendChild(
      createByteGrid('RWD — recovered secret', rwd, {
        variant: 'secret',
        changedMask: firstRwd
          ? Array.from(rwd).map((b, i) => b !== (firstRwd as Uint8Array)[i])
          : undefined,
        note:
          runCount === 1
            ? 'baseline'
            : rwdChanged
            ? 'DIFFERS — did the password change?'
            : 'identical to Run 1 ✓'
      })
    );

    runsWrap.prepend(card);
    // Keep at most the two most recent runs so the side-by-side stays readable.
    while (runsWrap.children.length > 2) {
      runsWrap.removeChild(runsWrap.lastElementChild as Node);
    }

    if (!firstRwd) {
      firstRwd = rwd;
      status.textContent =
        'Run 1 recorded. Now press "Run again (fresh r)" and compare the two cards.';
    } else if (rwdChanged) {
      status.textContent =
        'The password changed, so the RWD changed. Reset and keep the password fixed to see obliviousness.';
    } else {
      status.textContent =
        'Same password: the Blind changed (fresh noise on the wire) but the RWD is byte-for-byte identical. The server cannot tell these two runs came from the same password.';
    }
    prevBlind = blind;
  };

  const runBtn = createButton('Run OPRF', () => runOnce());
  const againBtn = createButton('Run again (fresh r)', () => runOnce());
  const resetBtn = createButton('Reset', () => {
    firstRwd = null;
    prevBlind = null;
    runCount = 0;
    runsWrap.replaceChildren();
    status.textContent = '';
  });
  resetBtn.classList.add('btn-secondary');

  const btnRow = document.createElement('div');
  btnRow.className = 'btn-row';
  btnRow.append(runBtn, againBtn, resetBtn);
  exhibit.appendChild(btnRow);

  const explanation = document.createElement('div');
  explanation.className = 'explanation';
  explanation.innerHTML = `
    <strong>What the server sees:</strong> only <span class="tag tag-wire">Blind</span>
    — a random-looking curve point, different every run.<br />
    <strong>What the server never sees:</strong> the password, <code>H(pwd)</code>,
    the blinding factor <code>r</code>, or the <span class="tag tag-rwd">RWD</span>.<br />
    <strong>Why unblinding is deterministic:</strong> blinding multiplies the hashed
    password point by <code>r</code>; the server multiplies by its key <code>k</code>;
    unblinding multiplies by <code>r⁻¹</code>. The <code>r</code> cancels, leaving
    <code>k·H(pwd)</code> regardless of which <code>r</code> you picked.
  `;
  exhibit.appendChild(explanation);

  exhibit.appendChild(
    createDetails(
      'For the cryptographer: why this is more than "it looks random"',
      `<p>The wire value is <code>blinded = r·H(pwd)</code> where <code>H</code> is
       hash-to-curve (SSWU) on P-256 and <code>r</code> is a uniform non-zero scalar.
       Since scalar multiplication by a uniform <code>r</code> maps any fixed point to
       a uniformly random group element, <code>blinded</code> is distributed
       independently of the password — this is <em>information-theoretic</em> blinding of
       the request, not a computational assumption. Obliviousness of the <em>output</em>
       (that the client learns nothing but <code>F(k, pwd)</code> and the server learns
       nothing at all) rests on the one-more-DH / 2HashDH assumption. The final
       <code>oprf_output = Hash(pwd || I2OSP(len(N),2) || N || "Finalize")</code> with
       <code>N = r⁻¹·evaluated</code> re-binds the password into the hash so a malicious
       server swapping <code>evaluated</code> can't make two distinct passwords collide.</p>`,
      'primer'
    )
  );

  return exhibit;
}

// ============================================================
// 3DH visualizer — the authenticated key exchange, drawn
// ============================================================

const SVG_NS = 'http://www.w3.org/2000/svg';
function svgEl(name: string, attrs: Record<string, string>): SVGElement {
  const el = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

/**
 * Draw the three Diffie-Hellman combinations that authenticate an OPAQUE login.
 * Four dots = the four public keys (client static/ephemeral, server
 * static/ephemeral). Three lines = the three DH shared secrets, each labeled
 * with the real first bytes it produced and with what security property it buys.
 * All values come from the actual login (ThreeDHTrace) — nothing is invented.
 */
function createThreeDHDiagram(t: ThreeDHTrace): HTMLElement {
  const wrap = document.createElement('div');
  wrap.className = 'threedh';

  const heading = document.createElement('strong');
  heading.className = 'threedh-title';
  heading.innerHTML =
    'The 3DH that just authenticated this login';
  wrap.appendChild(heading);

  const lede = document.createElement('p');
  lede.className = 'threedh-lede';
  lede.innerHTML =
    'Each side holds two keypairs: a <em>static</em> one (its long-term identity) and a ' +
    'fresh <em>ephemeral</em> one (single-use, this login only). OPAQUE combines them three ' +
    'ways with Diffie-Hellman and stirs all three secrets into one key schedule. The three ' +
    'pairings are what make the handshake mutually authenticated <em>and</em> forward-secret.';
  wrap.appendChild(lede);

  // ---- SVG diagram ----------------------------------------------------------
  // Layout: client keys on the left, server keys on the right, session box
  // centered below. Wide viewBox leaves room for the dot labels either side.
  const W = 440;
  const H = 250;
  const svg = svgEl('svg', {
    viewBox: `0 0 ${W} ${H}`,
    class: 'threedh-svg',
    role: 'img',
    'aria-label':
      'Diagram: client ephemeral and static keys on the left, server ephemeral and static ' +
      'keys on the right. Three lines connect them: ephemeral-to-ephemeral gives forward ' +
      'secrecy, client-ephemeral to server-static and client-static to server-ephemeral give ' +
      'mutual authentication. All three feed one session key.'
  }) as SVGSVGElement;

  // Dot coordinates. Dots sit well inside the viewBox so their outward labels
  // ("client static", "server ephemeral", …) have room and don't clip.
  const cEph = { x: 135, y: 45 };
  const cStat = { x: 135, y: 120 };
  const sEph = { x: 305, y: 45 };
  const sStat = { x: 305, y: 120 };
  const session = { x: 220, y: 210 };

  const lines: Array<{
    a: { x: number; y: number };
    b: { x: number; y: number };
    cls: string;
    id: string;
  }> = [
    { a: cEph, b: sEph, cls: 'dh1', id: 'dh1-line' }, // eph × eph
    { a: cEph, b: sStat, cls: 'dh2', id: 'dh2-line' }, // eph × static
    { a: cStat, b: sEph, cls: 'dh3', id: 'dh3-line' } // static × eph
  ];
  for (const ln of lines) {
    svg.appendChild(
      svgEl('line', {
        x1: String(ln.a.x),
        y1: String(ln.a.y),
        x2: String(ln.b.x),
        y2: String(ln.b.y),
        class: `threedh-line threedh-line-${ln.cls}`
      })
    );
  }

  // Lines from each dot down into the session box.
  for (const p of [cEph, cStat, sEph, sStat]) {
    svg.appendChild(
      svgEl('line', {
        x1: String(p.x),
        y1: String(p.y),
        x2: String(session.x),
        y2: String(session.y - 18),
        class: 'threedh-feed'
      })
    );
  }

  const dot = (p: { x: number; y: number }, label: string, side: 'l' | 'r') => {
    svg.appendChild(svgEl('circle', { cx: String(p.x), cy: String(p.y), r: '9', class: `threedh-dot threedh-dot-${side}` }));
    const txt = svgEl('text', {
      x: String(side === 'l' ? p.x - 14 : p.x + 14),
      y: String(p.y + 4),
      class: 'threedh-dotlabel',
      'text-anchor': side === 'l' ? 'end' : 'start'
    });
    txt.textContent = label;
    svg.appendChild(txt);
  };
  dot(cEph, 'client ephemeral', 'l');
  dot(cStat, 'client static', 'l');
  dot(sEph, 'server ephemeral', 'r');
  dot(sStat, 'server static', 'r');

  // Session key box.
  svg.appendChild(
    svgEl('rect', {
      x: String(session.x - 60),
      y: String(session.y - 18),
      width: '120',
      height: '34',
      rx: '6',
      class: 'threedh-session'
    })
  );
  const sessLabel = svgEl('text', {
    x: String(session.x),
    y: String(session.y + 4),
    class: 'threedh-sessionlabel',
    'text-anchor': 'middle'
  });
  sessLabel.textContent = 'session key';
  svg.appendChild(sessLabel);

  wrap.appendChild(svg);

  // ---- Per-line explanation cards (with the real DH bytes) ------------------
  const legend = document.createElement('div');
  legend.className = 'threedh-legend';

  const shortHex = (b: Uint8Array) => hex(b.subarray(0, 6)) + '…';
  const rows: Array<{ cls: string; name: string; pairing: string; buys: string; buysCls: string; bytes: Uint8Array }> = [
    {
      cls: 'dh1',
      name: 'dh1',
      pairing: 'client ephemeral × server ephemeral',
      buys: 'forward secrecy',
      buysCls: 'buys-fs',
      bytes: t.dh1
    },
    {
      cls: 'dh2',
      name: 'dh2',
      pairing: 'client ephemeral × server static',
      buys: 'authenticates the server',
      buysCls: 'buys-auth',
      bytes: t.dh2
    },
    {
      cls: 'dh3',
      name: 'dh3',
      pairing: 'client static × server ephemeral',
      buys: 'authenticates the client',
      buysCls: 'buys-auth',
      bytes: t.dh3
    }
  ];
  rows.forEach(r => {
    const card = document.createElement('div');
    card.className = `threedh-row threedh-row-${r.cls}`;
    card.innerHTML =
      `<span class="threedh-swatch threedh-swatch-${r.cls}" aria-hidden="true"></span>` +
      `<div class="threedh-rowbody">` +
      `<span class="threedh-rowname"><code>${r.name}</code> = ${escapeHtml(r.pairing)}</span>` +
      `<span class="threedh-buys ${r.buysCls}">${escapeHtml(r.buys)}</span>` +
      `<span class="threedh-bytes">shared secret ${escapeHtml(shortHex(r.bytes))} (mixed into the key schedule)</span>` +
      `</div>`;
    legend.appendChild(card);
  });
  wrap.appendChild(legend);

  const why = document.createElement('p');
  why.className = 'threedh-why';
  why.innerHTML =
    '<strong>Why three, not one?</strong> <code>dh1</code> uses only the throwaway ephemeral ' +
    'keys, so even if both long-term keys leak later, this session key can’t be recomputed — ' +
    'that is <span class="buys-fs">forward secrecy</span>. <code>dh2</code> and <code>dh3</code> ' +
    'each fold in one side’s <em>static</em> key, so only the party holding that long-term ' +
    'secret can produce the matching MAC — that is <span class="buys-auth">mutual ' +
    'authentication</span>. The key schedule is <code>HKDF-Extract("", dh1 ‖ dh2 ‖ dh3)</code>: ' +
    'drop any one and both the session key and the MACs change, so the handshake fails.';
  wrap.appendChild(why);

  return wrap;
}

/**
 * A small, pokeable forward-secrecy demonstration attached under the 3DH
 * diagram. "Leak" the real session key and show, concretely, that it (a) has no
 * path back to the password, and (b) can't be reproduced from the long-term keys
 * alone, because dh1 mixed in ephemeral secrets that are now gone. Contrasted
 * with a hypothetical static-only scheme where the same long-term keys would
 * always regenerate the same key (no forward secrecy). Nothing is faked: the
 * ephemeral secret keys genuinely never leave the AKE, so the demo can only
 * *state* they're destroyed — which is exactly the security argument.
 */
function addForwardSecrecyPoke(host: HTMLElement, sessionKey: Uint8Array): void {
  const wrap = document.createElement('div');
  wrap.className = 'fs-poke';

  const h = document.createElement('strong');
  h.className = 'fs-poke-title';
  h.textContent = 'Poke the forward-secrecy claim';
  wrap.appendChild(h);

  const p = document.createElement('p');
  p.className = 'fs-poke-lede';
  p.innerHTML =
    'Suppose an attacker records this whole login off the wire and later steals ' +
    'this exact <span class="tag tag-rwd">session key</span>. What did they get?';
  wrap.appendChild(p);

  const out = createStatusRegion('fs-poke-out');
  wrap.appendChild(out);

  const btn = createButton('Leak this session key', () => {
    out.replaceChildren();

    const grid = createByteGrid('LEAKED session_key', sessionKey, {
      variant: 'secret',
      note: 'the attacker now holds every one of these bytes'
    });
    out.appendChild(grid);

    const facts = document.createElement('div');
    facts.className = 'fs-facts';
    facts.innerHTML =
      `<div class="fs-fact fs-good"><span aria-hidden="true">✓</span> ` +
      `<span>The password and the <span class="tag tag-rwd">RWD</span> are safe. The session ` +
      `key is an HKDF output; there is no computational path from it back to the OPRF output ` +
      `or the password.</span></div>` +
      `<div class="fs-fact fs-good"><span aria-hidden="true">✓</span> ` +
      `<span>Past and future logins are safe. Each mixes in <code>dh1</code> = ` +
      `ephemeral×ephemeral, and those ephemeral private keys were discarded when the handshake ` +
      `finished — they were never stored and never sent. Without them this key can’t be ` +
      `recomputed, and the next login draws fresh ones.</span></div>` +
      `<div class="fs-fact fs-bad"><span aria-hidden="true">✗</span> ` +
      `<span><strong>Contrast — a static-only scheme</strong> (no ephemeral keys, key derived ` +
      `from long-term keys alone): stealing the long-term keys once would regenerate <em>every</em> ` +
      `past and future session key. That scheme has <em>no</em> forward secrecy. The single ` +
      `<code>dh1</code> term is the entire difference.</span></div>`;
    out.appendChild(facts);
    return Promise.resolve();
  });
  wrap.appendChild(btn);
  host.appendChild(wrap);
}

// ============================================================
// Exhibit 3: Registration + stepped KE1 → KE2 → KE3 login
// ============================================================

function createExhibit3(): HTMLElement {
  const exhibit = createContainer('Exhibit 3: Registration and the Login Handshake');
  exhibit.id = 'exhibit-reg';

  // ---- Tabs (ARIA Authoring Practices tab pattern) --------------------------
  const tabContainer = document.createElement('div');
  tabContainer.className = 'tabs';
  tabContainer.setAttribute('role', 'tablist');
  tabContainer.setAttribute('aria-label', 'Protocol step');

  const regTabId = 'ex3-tab-reg';
  const logTabId = 'ex3-tab-log';
  const regPanelId = 'ex3-panel-reg';
  const logPanelId = 'ex3-panel-log';

  const mkTab = (id: string, text: string, controls: string, selected: boolean) => {
    const t = document.createElement('button');
    t.type = 'button';
    t.id = id;
    t.textContent = text;
    t.className = selected ? 'tab active' : 'tab';
    t.setAttribute('role', 'tab');
    t.setAttribute('aria-selected', String(selected));
    t.setAttribute('aria-controls', controls);
    t.tabIndex = selected ? 0 : -1;
    return t;
  };
  const regTab = mkTab(regTabId, 'REGISTRATION', regPanelId, true);
  const logTab = mkTab(logTabId, 'LOGIN', logPanelId, false);
  tabContainer.append(regTab, logTab);
  exhibit.appendChild(tabContainer);

  // ---- Registration panel ---------------------------------------------------
  const regPanel = document.createElement('div');
  regPanel.id = regPanelId;
  regPanel.className = 'protocol-panel active';
  regPanel.setAttribute('role', 'tabpanel');
  regPanel.setAttribute('aria-labelledby', regTabId);
  regPanel.tabIndex = 0;

  const regIntro = document.createElement('p');
  regIntro.innerHTML =
    'Register once. The client derives everything from the password locally and hands the ' +
    'server only a public key, a masking key, and an envelope — <strong>no password, no hash</strong>.';
  regPanel.appendChild(regIntro);

  const { wrap: regUserWrap, input: regUsername } = createLabeledInput('Username', 'alice');
  const { wrap: regPwWrap, input: regPassword } = createLabeledInput('Password', 'library2026');
  regPanel.append(regUserWrap, regPwWrap);

  const regResultHost = document.createElement('div');

  const regRegisterBtn = createButton('Register', async () => {
    const serverPrivRaw = p256.utils.randomSecretKey();
    const serverPubRaw = p256.getPublicKey(serverPrivRaw, true);
    const serverOprfKey = generateOprfKey();

    const { record } = await register(
      regPassword.value,
      regUsername.value,
      serverOprfKey.oprfPrivate,
      serverPubRaw
    );

    setDemoSession({
      record,
      serverPrivate: serverPrivRaw,
      serverPublic: serverPubRaw,
      password: regPassword.value,
      username: regUsername.value
    });

    const result = createStatusRegion('reg-result');
    const done = document.createElement('div');
    done.innerHTML = `<strong class="status-success"><span aria-hidden="true">✓</span>
      Registered — the server now holds this record for "${escapeHtml(record.credentialIdentifier)}":</strong>`;
    result.appendChild(done);
    result.appendChild(
      createByteGrid('client_public_key (→ server)', record.clientPublicKey, { variant: 'wire' })
    );
    result.appendChild(
      createByteGrid('masking_key (server only)', record.maskingKey, {
        variant: 'neutral',
        labelHtml: termHtml('masking_key') + ' <span class="grid-hint">(server only)</span>'
      })
    );
    result.appendChild(
      createByteGrid('envelope (server only)', record.envelope, {
        variant: 'neutral',
        labelHtml: termHtml('envelope') + ' <span class="grid-hint">(server only)</span>',
        note: 'nonce || HMAC(auth_key, nonce || cleartext_creds) — no password inside'
      })
    );
    const zero = document.createElement('strong');
    zero.className = 'status-success';
    zero.innerHTML = '<span aria-hidden="true">✓</span> Zero password bytes stored on the server.';
    result.appendChild(zero);
    regResultHost.replaceChildren(result);
  });
  regPanel.append(regRegisterBtn, regResultHost);

  // ---- Login panel: stepped handshake --------------------------------------
  const logPanel = document.createElement('div');
  logPanel.id = logPanelId;
  logPanel.className = 'protocol-panel';
  logPanel.setAttribute('role', 'tabpanel');
  logPanel.setAttribute('aria-labelledby', logTabId);
  logPanel.hidden = true;
  logPanel.tabIndex = 0;

  const logIntro = document.createElement('p');
  logIntro.innerHTML =
    'Login is a <strong>three-message handshake</strong>: KE1 (client→server), KE2 (server→client), ' +
    'KE3 (client→server). Step through them one at a time and watch what each message carries — ' +
    'and, just as important, what it does <em>not</em>.';
  logPanel.appendChild(logIntro);

  const { wrap: logUserWrap, input: logUsername } = createLabeledInput('Username', 'alice');
  const { wrap: logPwWrap, input: logPassword } = createLabeledInput('Password', 'library2026');

  const wrongWrap = document.createElement('div');
  wrongWrap.className = 'field field-check';
  const wrongCb = document.createElement('input');
  wrongCb.type = 'checkbox';
  wrongCb.id = `input-${++inputIdCounter}`;
  const wrongLabel = document.createElement('label');
  wrongLabel.setAttribute('for', wrongCb.id);
  wrongLabel.textContent = 'Log in with the WRONG password (watch the MAC fail)';
  wrongWrap.append(wrongCb, wrongLabel);

  logPanel.append(logUserWrap, logPwWrap, wrongWrap);

  // The animated CLIENT | SERVER stage where message cards move across.
  const { container: stage, left: clientCol, right: serverCol } = createTwoColumn();
  stage.classList.add('handshake-stage');
  const clientLog = document.createElement('div');
  clientLog.className = 'wire-log';
  clientCol.appendChild(clientLog);
  const serverLog = document.createElement('div');
  serverLog.className = 'wire-log';
  serverCol.appendChild(serverLog);
  logPanel.appendChild(stage);

  const stepStatus = createStatusRegion('handshake-status');
  logPanel.appendChild(stepStatus);

  // Handshake driver state.
  type Phase = 'idle' | 'ke1' | 'ke2' | 'ke3' | 'done' | 'failed';
  let phase: Phase = 'idle';
  let ke1: AKEMessage1 | null = null;
  let clientState: ClientState | null = null;
  let ke2: AKEMessage2 | null = null;
  let serverState: ServerState | null = null;
  let ke3: AKEMessage3 | null = null;
  let threeDH: ThreeDHTrace | null = null;

  const stepBtn = createButton('Start login →', () => advance());
  const restartBtn = createButton('Restart', () => resetHandshake());
  restartBtn.classList.add('btn-secondary');
  const btnRow = document.createElement('div');
  btnRow.className = 'btn-row';
  btnRow.append(stepBtn, restartBtn);
  logPanel.appendChild(btnRow);

  const addMsgCard = (
    col: HTMLElement,
    dir: 'to-server' | 'to-client',
    title: string,
    contains: Array<{ label: string; bytes?: Uint8Array; text?: string; labelHtml?: string }>,
    notContains: string[]
  ) => {
    const card = document.createElement('div');
    card.className = `msg-card ${dir}`;
    const h = document.createElement('div');
    h.className = 'msg-card-head';
    h.innerHTML = `<span class="msg-arrow" aria-hidden="true">${
      dir === 'to-server' ? '→' : '←'
    }</span> ${title} <span class="msg-dir">${
      dir === 'to-server' ? 'to server' : 'to client'
    }</span>`;
    card.appendChild(h);

    contains.forEach(item => {
      if (item.bytes) {
        card.appendChild(
          createByteGrid(item.label, item.bytes, {
            variant: 'wire',
            maxBytes: 16,
            labelHtml: item.labelHtml
          })
        );
      } else {
        const line = document.createElement('div');
        line.className = 'msg-line';
        line.innerHTML = `<strong>${escapeHtml(item.label)}:</strong> ${escapeHtml(item.text ?? '')}`;
        card.appendChild(line);
      }
    });

    const nc = document.createElement('div');
    nc.className = 'msg-notcontains';
    nc.innerHTML =
      '<strong>Not on the wire:</strong> ' +
      notContains.map(x => `<span class="never-chip">${escapeHtml(x)}</span>`).join(' ');
    card.appendChild(nc);
    col.appendChild(card);
  };

  const resetHandshake = () => {
    phase = 'idle';
    ke1 = clientState = ke2 = serverState = ke3 = null;
    threeDH = null;
    clientLog.replaceChildren();
    serverLog.replaceChildren();
    logPanel.querySelectorAll('.threedh-reveal').forEach(el => el.remove());
    stepStatus.textContent = '';
    stepBtn.textContent = 'Start login →';
    stepBtn.disabled = false;
    stage.classList.remove('stage-failed');
  };

  const fail = (step: string, message: string) => {
    phase = 'failed';
    stage.classList.add('stage-failed');
    const box = createStatusRegion('login-result error', true);
    box.innerHTML = `<strong class="status-error"><span aria-hidden="true">✗</span>
      HANDSHAKE ABORTED at ${escapeHtml(step)}</strong><br />${escapeHtml(message)}`;
    serverLog.appendChild(box);
    stepStatus.textContent = `${step}: ${message}`;
    stepBtn.textContent = 'Start login →';
  };

  const advance = async () => {
    const s = demoSession;
    if (!s) {
      stepStatus.textContent = 'Register first (Registration tab), then step through login.';
      return;
    }

    if (phase === 'done' || phase === 'failed') resetHandshake();

    if (phase === 'idle') {
      // ---- KE1: client → server -------------------------------------------
      const usePwd = wrongCb.checked ? logPassword.value + '_WRONG' : logPassword.value;
      const r = await clientLoginStep1(usePwd, logUsername.value);
      ke1 = r.ke1;
      clientState = r.clientState;
      addMsgCard(
        clientLog,
        'to-server',
        'KE1',
        [
          {
            label: 'blinded_message',
            labelHtml: termHtml('blinded_message') + ' <span class="grid-hint">(r·H(pwd))</span>',
            bytes: ke1.blindedMessage
          },
          { label: 'client_nonce', bytes: ke1.clientNonce },
          {
            label: 'client_keyshare',
            labelHtml: termHtml('client_keyshare', 'keyshare') + ' <span class="grid-hint">(ephemeral pk)</span>',
            bytes: ke1.clientKeyshare
          }
        ],
        ['the password', 'the unblinded RWD', 'the client static secret key']
      );
      phase = 'ke1';
      stepStatus.textContent = wrongCb.checked
        ? 'KE1 sent with the WRONG password. The blinded point still looks valid — the server cannot tell yet. The break will surface at KE3.'
        : 'KE1 sent: a blinded password point + a fresh ephemeral key. The password itself never leaves the client.';
      stepBtn.textContent = 'Send KE2 (server) →';
      return;
    }

    if (phase === 'ke1' && ke1) {
      // ---- KE2: server → client -------------------------------------------
      const r = await serverLoginStep2(ke1, s.record, s.serverPrivate, s.serverPublic);
      ke2 = r.ke2;
      serverState = r.serverState;
      addMsgCard(
        serverLog,
        'to-client',
        'KE2',
        [
          {
            label: 'evaluated_message',
            labelHtml: termHtml('evaluated_message') + ' <span class="grid-hint">(k·blinded)</span>',
            bytes: ke2.credentialResponse.evaluatedMessage
          },
          {
            label: 'masked_response',
            labelHtml: termHtml('masked_response') + ' <span class="grid-hint">(pk‖envelope ⊕ pad)</span>',
            bytes: ke2.credentialResponse.maskedResponse
          },
          { label: 'server_nonce', bytes: ke2.serverNonce },
          {
            label: 'server_keyshare',
            labelHtml: termHtml('server_keyshare', 'keyshare') + ' <span class="grid-hint">(ephemeral pk)</span>',
            bytes: ke2.serverKeyshare
          },
          {
            label: 'server_mac',
            labelHtml: termHtml('server_mac') + ' <span class="grid-hint">(over the ' + termHtml('preamble') + ')</span>',
            bytes: ke2.serverMac
          }
        ],
        ['the OPRF key k', 'the server static secret key', 'anything about the password']
      );
      phase = 'ke2';
      stepStatus.textContent =
        'KE2 sent: the OPRF evaluation (still blinded), the masked credentials, the server keyshare, and a MAC proving the server knows the shared handshake secret.';
      stepBtn.textContent = 'Send KE3 (client) →';
      return;
    }

    if (phase === 'ke2' && ke2 && clientState) {
      // ---- KE3: client unblinds, recovers envelope, verifies server MAC ----
      try {
        const r = await clientLoginStep3(ke2, clientState);
        ke3 = r.ke3;
        addMsgCard(
          clientLog,
          'to-server',
          'KE3',
          [{ label: 'client_mac', bytes: ke3.clientMac }],
          ['the password', 'the RWD', 'the recovered client secret key']
        );
        phase = 'ke3';
        stepStatus.textContent =
          'Client unblinded the RWD, re-derived its static key, authenticated the envelope (server MAC verified), and sent its own MAC. One step left: the server checks it.';
        stepBtn.textContent = 'Server verifies KE3 →';

        // Stash session-key material + the real 3DH trace for the final step.
        threeDH = r.threeDH;
        (advance as unknown as { _sk?: Uint8Array; _ek?: Uint8Array })._sk = r.sessionKey;
        (advance as unknown as { _sk?: Uint8Array; _ek?: Uint8Array })._ek = r.exportKey;
      } catch (e) {
        // Wrong password path: envelope recovery / server-MAC verification fails
        // inside clientLoginStep3 (the RWD is wrong → auth_key wrong → MAC mismatch).
        fail(
          'KE3 (client envelope recovery)',
          `${(e as Error).message}. Wrong password → wrong RWD → wrong auth_key → the ` +
            `envelope's HMAC tag doesn't verify, so the envelope won't open. The client ` +
            `aborts before it can prove anything to the server.`
        );
      }
      return;
    }

    if (phase === 'ke3' && ke3 && serverState) {
      // ---- Server verifies client MAC -------------------------------------
      try {
        const finalKey = await serverFinalize(ke3, serverState);
        const sk = (advance as unknown as { _sk?: Uint8Array })._sk;
        const ek = (advance as unknown as { _ek?: Uint8Array })._ek;
        if (!sk || hex(sk) !== hex(finalKey)) throw new Error('Session key mismatch');

        const box = createStatusRegion('login-result success');
        const head = document.createElement('strong');
        head.className = 'status-success';
        head.innerHTML = '<span aria-hidden="true">✓</span> LOGIN SUCCESSFUL — both sides agree on the session key';
        box.appendChild(head);
        box.appendChild(createByteGrid('session_key (client == server)', finalKey, { variant: 'secret' }));
        if (ek) box.appendChild(createByteGrid('export_key (client only)', ek, { variant: 'secret' }));
        serverLog.appendChild(box);

        // Now unveil the 3DH that produced this session key + mutual auth.
        if (threeDH) {
          const dhBox = document.createElement('div');
          dhBox.className = 'threedh-reveal';
          dhBox.appendChild(createThreeDHDiagram(threeDH));
          logPanel.appendChild(dhBox);
          addForwardSecrecyPoke(dhBox, finalKey);
        }

        phase = 'done';
        stepStatus.textContent =
          'Server verified the client MAC. Mutual authentication complete; the ephemeral 3DH gives forward secrecy. See the 3DH diagram below for how. Press Restart to try the wrong-password path.';
        stepBtn.textContent = 'Done ✓';
        stepBtn.disabled = true;
      } catch (e) {
        fail('server verification of KE3', (e as Error).message);
      }
      return;
    }
  };

  // ---- Tab switching -------------------------------------------------------
  const selectTab = (which: 'reg' | 'log', focusTab = true) => {
    const activeTab = which === 'reg' ? regTab : logTab;
    const inactiveTab = which === 'reg' ? logTab : regTab;
    const activePanel = which === 'reg' ? regPanel : logPanel;
    const inactivePanel = which === 'reg' ? logPanel : regPanel;

    activeTab.classList.add('active');
    activeTab.setAttribute('aria-selected', 'true');
    activeTab.tabIndex = 0;
    inactiveTab.classList.remove('active');
    inactiveTab.setAttribute('aria-selected', 'false');
    inactiveTab.tabIndex = -1;

    activePanel.classList.add('active');
    activePanel.hidden = false;
    inactivePanel.classList.remove('active');
    inactivePanel.hidden = true;
    if (focusTab) activeTab.focus();
  };
  regTab.onclick = () => selectTab('reg');
  logTab.onclick = () => selectTab('log');

  // The protocol map (Exhibit 0) links to #exhibit-login. Honor that by opening
  // the LOGIN tab and scrolling the exhibit into view, without stealing focus.
  const honorLoginHash = () => {
    if (location.hash === '#exhibit-login') {
      selectTab('log', false);
      exhibit.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };
  window.addEventListener('hashchange', honorLoginHash);

  const onTabKey = (e: KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        e.preventDefault();
        selectTab(document.activeElement === regTab ? 'log' : 'reg');
        break;
      case 'ArrowLeft':
      case 'ArrowUp':
        e.preventDefault();
        selectTab(document.activeElement === logTab ? 'reg' : 'log');
        break;
      case 'Home':
        e.preventDefault();
        selectTab('reg');
        break;
      case 'End':
        e.preventDefault();
        selectTab('log');
        break;
    }
  };
  regTab.addEventListener('keydown', onTabKey);
  logTab.addEventListener('keydown', onTabKey);

  exhibit.append(regPanel, logPanel);
  return exhibit;
}

// ============================================================
// Exhibit 4: Server Database Breach — the attacks actually run
// ============================================================

/**
 * Everything a breach hands the attacker, and nothing else: the server's
 * per-user record (client_public_key, masking_key, envelope, oprf_key) plus
 * the server's own public key. Deliberately does NOT carry the password or
 * the server's private key — if an attack in here needed either, it would
 * fail to compile, which is the point.
 */
interface StolenRecord {
  record: RegistrationRecord;
  serverPublic: Uint8Array;
  username: string;
}

/**
 * One offline password guess, run for real: OPRF-evaluate the candidate with
 * the stolen per-user OPRF key, derive randomized_password (including the
 * scrypt stretch), then try to authenticate the envelope and recover the
 * credentials. `recover()` throws on MAC
 * mismatch, so a returned `true` means the envelope genuinely authenticated
 * and the client credentials were recovered.
 */
function tryOfflineGuess(stolen: StolenRecord, candidate: string): boolean {
  const bytes = new TextEncoder().encode(candidate);
  const { blind, blinded } = oprfBlind(bytes);
  const evaluated = oprfBlindEvaluate(stolen.record.oprfKey, blinded);
  const oprfOutput = oprfFinalize(bytes, blind, evaluated);
  const randomizedPwd = deriveRandomizedPassword(oprfOutput, stretchScrypt);
  try {
    recover(
      randomizedPwd,
      stolen.serverPublic,
      stolen.record.envelope,
      new Uint8Array(0),
      new TextEncoder().encode(stolen.username)
    );
    return true;
  } catch {
    return false;
  }
}

/** Attack 1: authenticate/recover without the password. Uses random RWD bytes. */
function attackWithoutPassword(stolen: StolenRecord): { opened: boolean; error: string } {
  const guessedRwd = crypto.getRandomValues(new Uint8Array(32));
  try {
    recover(
      guessedRwd,
      stolen.serverPublic,
      stolen.record.envelope,
      new Uint8Array(0),
      new TextEncoder().encode(stolen.username)
    );
    return { opened: true, error: '' };
  } catch (e) {
    return { opened: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Attack 3: is a table built against one user's OPRF key reusable against
 * another's? Evaluate the *same* password under the stolen key and under a
 * different user's key and compare the OPRF outputs.
 */
function attackPrecomputation(
  stolen: StolenRecord,
  password: string
): { sameKeyOut: Uint8Array; otherKeyOut: Uint8Array; reusable: boolean } {
  const bytes = new TextEncoder().encode(password);
  const evalUnder = (key: Uint8Array): Uint8Array => {
    const { blind, blinded } = oprfBlind(bytes);
    return oprfFinalize(bytes, blind, oprfBlindEvaluate(key, blinded));
  };
  const sameKeyOut = evalUnder(stolen.record.oprfKey);
  const otherKeyOut = evalUnder(generateOprfKey().oprfPrivate);
  const reusable =
    sameKeyOut.byteLength === otherKeyOut.byteLength &&
    sameKeyOut.every((b, i) => b === otherKeyOut[i]);
  return { sameKeyOut, otherKeyOut, reusable };
}

/**
 * Attack 4: impersonate the server on the next login using only the breached
 * record. The attacker has no server static private key, so it substitutes its
 * own keypair and runs a genuine KE2. The victim's real client code then runs
 * `clientLoginStep3`; whether that throws is the verdict.
 */
async function attackServerImpersonation(
  stolen: StolenRecord,
  password: string
): Promise<{ accepted: boolean; error: string }> {
  const forged = p256.utils.randomSecretKey();
  const forgedPub = p256.getPublicKey(forged, true);
  const { ke1, clientState } = await clientLoginStep1(password, stolen.username);
  const { ke2 } = await serverLoginStep2(ke1, stolen.record, forged, forgedPub);
  try {
    await clientLoginStep3(ke2, clientState);
    return { accepted: true, error: '' };
  } catch (e) {
    return { accepted: false, error: e instanceof Error ? e.message : String(e) };
  }
}

function createExhibit4(): HTMLElement {
  const exhibit = createContainer('Exhibit 4: Server Database Breach');

  const intro = document.createElement('p');
  intro.innerHTML =
    'Suppose the attacker steals the entire server record for a user and also the ' +
    "server's OPRF key. What can they actually do? Every verdict below is the " +
    'result of <strong>running the attack</strong> against the envelope you registered in ' +
    'Exhibit 3 — the offline guesses call the same <code>recover()</code> the real client ' +
    'calls, and the timings come from this browser. Nothing here is a canned answer: if ' +
    'an attack succeeded, this panel would say so.';
  exhibit.appendChild(intro);

  const host = document.createElement('div');
  exhibit.appendChild(host);

  const render = async (btn: HTMLButtonElement) => {
    const s = demoSession;
    const analysis = createStatusRegion('breach-analysis');

    if (!s) {
      analysis.innerHTML = `
        <p class="ground-note">No envelope to attack yet. Register in
        <strong>Exhibit 3</strong> first — these attacks run against a real record, so
        there is nothing honest to show until one exists.</p>`;
      host.replaceChildren(analysis);
      return;
    }

    const stolen: StolenRecord = {
      record: s.record,
      serverPublic: s.serverPublic,
      username: s.username
    };

    btn.textContent = 'Running the attacks…';
    analysis.innerHTML = '<p class="ground-note">Running…</p>';
    host.replaceChildren(analysis);
    // Yield so the "running" state paints before the scrypt work blocks the thread.
    await new Promise(r => setTimeout(r, 0));

    // --- Attack 1: authenticate/recover with no password at all ---
    const a1 = attackWithoutPassword(stolen);

    // --- Attack 2: a real offline dictionary attack. The true password is put
    // LAST so the wrong guesses are genuinely tried and genuinely rejected. ---
    const wrongGuesses = ['password', '123456', 'letmein', 'library'].filter(
      g => g !== s.password
    );
    const dictionary = [...wrongGuesses, s.password];
    const t0 = performance.now();
    const results = dictionary.map(c => ({ candidate: c, hit: tryOfflineGuess(stolen, c) }));
    const elapsedMs = performance.now() - t0;
    const perOpMs = elapsedMs / dictionary.length;
    const perSec = 1000 / perOpMs;
    const hits = results.filter(r => r.hit);
    const cracked = hits.length === 1 && hits[0].candidate === s.password;

    // --- Attack 3: is the per-user OPRF key actually per-user? ---
    const a3 = attackPrecomputation(stolen, s.password);

    // --- Attack 4: forge a server using only the breached record ---
    const a4 = await attackServerImpersonation(stolen, s.password);

    btn.textContent = 'Re-run the attacks';

    const guessRows = results
      .map(
        r =>
          `<li><code>${escapeHtml(r.candidate)}</code> — ${
            r.hit
              ? '<strong>envelope authenticated; credentials recovered</strong>'
              : 'MAC mismatch, rejected'
          }</li>`
      )
      .join('');

    analysis.innerHTML = `
      <p class="ground-note">Target: your envelope <code>${bytesToHex(
        s.record.envelope,
        10
      )}</code> for user "${escapeHtml(s.username)}".</p>

      <div class="attack-scenario ${a1.opened ? 'attack-warn' : 'attack-blocked'}">
        <strong>Attack 1 — authenticate the envelope with no password</strong>
        <span>Called <code>recover()</code> with 32 random bytes standing in for the RWD.
        The client static key is <em>derived</em> from the RWD and the envelope is an HMAC
        under <code>auth_key = HKDF-Expand(RWD, nonce||"AuthKey")</code>, so a wrong RWD
        produces a wrong tag.</span>
        <span class="breach-verdict">${
          a1.opened
            ? '<span aria-hidden="true">⚠</span> IT AUTHENTICATED — the envelope is not binding the RWD'
            : `<span aria-hidden="true">✗</span> Blocked — <code>${escapeHtml(
                a1.error
              )}</code>`
        }</span>
      </div>

      <div class="attack-scenario ${cracked ? 'attack-warn' : 'attack-blocked'}">
        <strong>Attack 2 — offline dictionary attack (with the stolen OPRF key)</strong>
        <span>Each candidate was run all the way through: OPRF-evaluate under the stolen
        per-user key, <code>randomized_pwd' = HKDF-Extract("", z || scrypt(z))</code>, then
        <code>recover()</code> against your envelope.</span>
        <ul style="margin:0.4rem 0 0.4rem 1.2rem;line-height:1.7">${guessRows}</ul>
        <span>${dictionary.length} guesses took <strong>${elapsedMs.toFixed(
          0
        )} ms</strong> — <strong>${perOpMs.toFixed(0)} ms/guess &asymp; ${perSec.toFixed(
          1
        )} guesses/sec</strong> single-threaded here (scrypt N=2¹⁵, r=8). That rate, not any
        quoted figure, is the whole defence.</span>
        <span class="breach-verdict">${
          cracked
            ? '<span aria-hidden="true">⚠</span> Possible — the right guess authenticated it and recovered the credentials; the wrong ones did not. A weak password falls; a strong one is out of reach at this rate.'
            : '<span aria-hidden="true">✗</span> No candidate authenticated the envelope in this run.'
        }</span>
      </div>

      <div class="attack-scenario ${a3.reusable ? 'attack-warn' : 'attack-blocked'}">
        <strong>Attack 3 — reuse a precomputed table across users</strong>
        <span>Evaluated the <em>same</em> password under the stolen OPRF key and under a
        different user's freshly generated OPRF key:<br />
        <code>${bytesToHex(a3.sameKeyOut, 12)}</code><br />
        <code>${bytesToHex(a3.otherKeyOut, 12)}</code></span>
        <span class="breach-verdict">${
          a3.reusable
            ? '<span aria-hidden="true">⚠</span> Same output — a table WOULD transfer between users'
            : '<span aria-hidden="true">✓</span> Different outputs — a table built for one user is worthless against another, and neither can be built before the breach hands over a key.'
        }</span>
      </div>

      <div class="attack-scenario ${a4.accepted ? 'attack-warn' : 'attack-blocked'}">
        <strong>Attack 4 — impersonate the server on the next login</strong>
        <span>Ran a genuine KE2 from the stolen record using an attacker-generated static
        keypair (the server's real static private key was not breached), then handed it to
        the victim's real <code>clientLoginStep3</code>. Two things can catch it — the
        forged server public key is bound into <code>cleartext_creds</code>, so the envelope
        MAC fails, and the 3DH needs the real static key, so <code>server_mac</code> fails.
        The error below names whichever fired first.</span>
        <span class="breach-verdict">${
          a4.accepted
            ? '<span aria-hidden="true">⚠</span> THE CLIENT ACCEPTED IT — server authentication is broken'
            : `<span aria-hidden="true">✗</span> Client aborted — <code>${escapeHtml(
                a4.error
              )}</code>`
        }</span>
      </div>

      <p class="ground-note">The stretch is real <code>scrypt</code>, not the illustrative
      <code>k·H(pwd')</code> shorthand, and the per-guess cost above was measured by
      actually making the guesses. Production should raise the KSF cost well above the
      N=2¹⁵ used here to keep the demo responsive.</p>
    `;
    host.replaceChildren(analysis);
  };

  const btn = createButton('Analyze breach', () => render(btn));
  exhibit.appendChild(btn);
  onDemoSession(session => {
    btn.disabled = !session;
    btn.title = session ? '' : 'Register in Exhibit 3 first';
  });
  return exhibit;
}

// ============================================================
// Exhibit 5: Real-World Deployments
// ============================================================

function createExhibit5(): HTMLElement {
  const exhibit = createContainer('Exhibit 5: Real-World Deployments & Library Context');

  const deployments = document.createElement('div');
  deployments.className = 'deployments';
  deployments.innerHTML = `
    <div class="deployment">
      <strong>WhatsApp (2021+)</strong><br />
      End-to-End Encrypted Backups<br />
      Password-gated key retrieval from an HSM-backed Backup Key Vault. Meta's public
      write-up describes the design but does not name OPAQUE; RFC 9807 co-author
      Kevin Lewi is at Meta.
    </div>
    <div class="deployment">
      <strong>Cloudflare</strong><br />
      Published OPAQUE research and a public demo<br />
      Not a shipped production login path
    </div>
    <div class="deployment">
      <strong>Apple Private Cloud Compute</strong><br />
      A neighbour, not an example: PCC authorizes requests with single-use
      RSA Blind Signatures (RFC 9474), not an OPRF
    </div>
    <div class="deployment">
      <strong>1Password</strong><br />
      Research into OPAQUE for vault unlock
    </div>
  `;
  exhibit.appendChild(deployments);

  const libraryContext = document.createElement('div');
  libraryContext.className = 'library-context';
  libraryContext.innerHTML = `
    <strong>OPAQUE and Library Patron Privacy</strong><br />
    <br />
    Current library systems: Patron enters password → sent to ILS server<br />
    Risk: ILS breach exposes patron passwords (reuse risk for bank, email)<br />
    <br />
    OPAQUE deployment would mean:<br />
    ✓ ILS breach reveals NO patron passwords<br />
    ✓ Patron not identifiable by password reuse<br />
    ✓ Mutual auth: patron verifies server identity<br />
    ✓ Session keys ephemeral (forward secrecy)<br />
    <br />
    Status: RFC 9807 (IRTF 2025) published. Library ILS vendors not yet implementing.<br />
    Advocacy needed: SirsiDynix, Innovative Interfaces, EBSCO
  `;
  exhibit.appendChild(libraryContext);

  return exhibit;
}

// ============================================================
// Main
// ============================================================

function initApp() {
  const header = document.getElementById('app-header');
  const main = document.getElementById('main-content');
  const footer = document.getElementById('app-footer');
  if (!header || !main || !footer) return;

  header.classList.add('cl-hero');

  header.innerHTML = `
    <div class="cl-hero-main">
      <h1 class="cl-hero-title">OPAQUE</h1>
      <p class="cl-hero-sub">aPAKE · RFC 9807</p>
      <p class="cl-hero-desc">Runs the real OPRF → authenticated envelope (${ENVELOPE_FORMAT}) → 3-message 3DH handshake so you can step through a registration and login where the server never sees your password.</p>
    </div>
    <aside class="cl-hero-why" aria-label="Why it matters">
      <span class="cl-hero-why-label">WHY IT MATTERS</span>
      <p class="cl-hero-why-text">Breaches leak billions of reused credentials every year. OPAQUE makes a stolen database useless: there is no password, and no crackable password hash, for an attacker to walk away with.</p>
    </aside>
  `;

  const themeToggle = document.createElement('button');
  themeToggle.type = 'button';
  themeToggle.className = 'theme-toggle';

  const updateThemeToggle = (current: string) => {
    const next = current === 'dark' ? 'light' : 'dark';
    const icon = next === 'light' ? '☀️' : '🌙';
    themeToggle.innerHTML = `<span aria-hidden="true">${icon}</span>`;
    themeToggle.setAttribute('aria-label', `Switch to ${next} theme`);
  };

  updateThemeToggle(document.documentElement.getAttribute('data-theme') || 'dark');

  themeToggle.onclick = () => {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('cv-theme', next);
    updateThemeToggle(next);
  };
  header.appendChild(themeToggle);

  // Exhibit 3 registers first in the DOM-independent sense, but visual order is
  // 1..5. Exhibits 1 and 4 subscribe to the shared session, so registering in
  // Exhibit 3 lights them up with real data.
  main.appendChild(createProtocolMap());
  main.appendChild(createExhibit1());
  main.appendChild(createExhibit2());
  main.appendChild(createExhibit3());
  main.appendChild(createExhibit4());
  main.appendChild(createExhibit5());

  // Delegated toggle for every inline tappable jargon term across the exhibits.
  wireTerms(main);

  // If the page loaded already pointing at the login tab, honor it after render.
  if (location.hash === '#exhibit-login') {
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  }

  footer.innerHTML = `
    <p>Related demos:
      <a href="https://systemslibrarian.github.io/crypto-lab-webauthn/">crypto-lab-webauthn</a> ·
      <a href="https://systemslibrarian.github.io/crypto-lab-x3dh-wire/">crypto-lab-x3dh-wire</a> ·
      <a href="https://systemslibrarian.github.io/crypto-lab-psi-gate/">crypto-lab-psi-gate</a> ·
      <a href="https://systemslibrarian.github.io/crypto-lab-noise-pipe/">crypto-lab-noise-pipe</a></p>
    <p>"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."
    — 1 Corinthians 10:31</p>
  `;
}

document.addEventListener('DOMContentLoaded', initApp);
