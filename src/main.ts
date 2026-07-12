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
import { generateOprfKey, oprfClientBlind, oprfServerEvaluate, oprfClientUnblind } from './oprf';
import { register, RegistrationRecord } from './envelope';
import { stretchScrypt } from './kdf';
import {
  clientLoginStep1,
  serverLoginStep2,
  clientLoginStep3,
  serverFinalize,
  AKEMessage1,
  AKEMessage2,
  AKEMessage3,
  ClientState,
  ServerState
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
  } = {}
): HTMLElement {
  const wrap = document.createElement('div');
  wrap.className = 'bytegrid-block';

  const label = document.createElement('strong');
  label.className = 'bytegrid-label';
  label.textContent = title;
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
        <span>Server stored an encrypted-looking <em>envelope</em> + a per-user OPRF key,
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
// Exhibit 3: Registration + stepped KE1 → KE2 → KE3 login
// ============================================================

function createExhibit3(): HTMLElement {
  const exhibit = createContainer('Exhibit 3: Registration and the Login Handshake');

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
      createByteGrid('masking_key (server only)', record.maskingKey, { variant: 'neutral' })
    );
    result.appendChild(
      createByteGrid('envelope (server only)', record.envelope, {
        variant: 'neutral',
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
    contains: Array<{ label: string; bytes?: Uint8Array; text?: string }>,
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
        card.appendChild(createByteGrid(item.label, item.bytes, { variant: 'wire', maxBytes: 16 }));
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
    clientLog.replaceChildren();
    serverLog.replaceChildren();
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
          { label: 'blinded_message (r·H(pwd))', bytes: ke1.blindedMessage },
          { label: 'client_nonce', bytes: ke1.clientNonce },
          { label: 'client_keyshare (ephemeral pk)', bytes: ke1.clientKeyshare }
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
          { label: 'evaluated_message (k·blinded)', bytes: ke2.credentialResponse.evaluatedMessage },
          { label: 'masked_response (pk||envelope ⊕ pad)', bytes: ke2.credentialResponse.maskedResponse },
          { label: 'server_nonce', bytes: ke2.serverNonce },
          { label: 'server_keyshare (ephemeral pk)', bytes: ke2.serverKeyshare },
          { label: 'server_mac', bytes: ke2.serverMac }
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
          'Client unblinded the RWD, re-derived its static key, opened the envelope (server MAC verified), and sent its own MAC. One step left: the server checks it.';
        stepBtn.textContent = 'Server verifies KE3 →';

        // Stash session-key material for the final step.
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
        phase = 'done';
        stepStatus.textContent =
          'Server verified the client MAC. Mutual authentication complete; the ephemeral 3DH gives forward secrecy. Press Restart to try the wrong-password path.';
        stepBtn.textContent = 'Done ✓';
        stepBtn.disabled = true;
      } catch (e) {
        fail('server verification of KE3', (e as Error).message);
      }
      return;
    }
  };

  // ---- Tab switching -------------------------------------------------------
  const selectTab = (which: 'reg' | 'log') => {
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
    activeTab.focus();
  };
  regTab.onclick = () => selectTab('reg');
  logTab.onclick = () => selectTab('log');

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
// Exhibit 4: Server Database Breach — grounded in real data
// ============================================================

function createExhibit4(): HTMLElement {
  const exhibit = createContainer('Exhibit 4: Server Database Breach');

  const intro = document.createElement('p');
  intro.innerHTML =
    'Suppose the attacker steals the entire server record for a user and also the ' +
    "server's OPRF key. What can they actually do? These attacks run against the " +
    '<strong>envelope you registered in Exhibit 3</strong>, and the cost number below is ' +
    "measured live from this browser's real scrypt, not a canned figure.";
  exhibit.appendChild(intro);

  const host = document.createElement('div');
  exhibit.appendChild(host);

  const render = async (btn: HTMLButtonElement) => {
    const s = demoSession;
    const analysis = createStatusRegion('breach-analysis');

    // Measure the REAL stretch cost used in the code (scrypt N=2^15).
    btn.textContent = 'Measuring real scrypt cost…';
    const samples = 3;
    const t0 = performance.now();
    for (let i = 0; i < samples; i++) {
      stretchScrypt(new Uint8Array([i & 0xff, 1, 2, 3, 4]));
    }
    const perOpMs = (performance.now() - t0) / samples;
    const perSec = 1000 / perOpMs;
    btn.textContent = 'Analyze breach';

    const envLine = s
      ? `Target: your envelope <code>${bytesToHex(s.record.envelope, 10)}</code> for user "${escapeHtml(
          s.username
        )}".`
      : 'Target: register in Exhibit 3 first to attack your own envelope; showing the general argument meanwhile.';

    analysis.innerHTML = `
      <p class="ground-note">${envLine}</p>
      <div class="attack-scenario attack-blocked">
        <strong>Attack 1 — decrypt the envelope directly</strong>
        <span>The client static key is <em>derived</em> from the RWD, and the envelope is
        an HMAC under <code>auth_key = HKDF-Expand(RWD, nonce||"AuthKey")</code>. No RWD,
        no auth_key, no open.</span>
        <span class="breach-verdict"><span aria-hidden="true">✗</span> Blocked — RWD needs the password.</span>
      </div>
      <div class="attack-scenario attack-warn">
        <strong>Attack 2 — offline dictionary attack (with the stolen OPRF key)</strong>
        <span>For each guess <code>pwd'</code>: evaluate the OPRF locally, then
        <code>randomized_pwd' = HKDF-Extract("", z || scrypt(z))</code> where
        <code>z = OPRF(pwd')</code>, then test the envelope MAC. The gate is that
        <code>scrypt</code> stretch — measured just now at
        <strong>${perOpMs.toFixed(0)} ms/guess ≈ ${perSec.toFixed(0)} guesses/sec</strong>
        single-threaded on this machine (scrypt N=2¹⁵, r=8).</span>
        <span class="breach-verdict"><span aria-hidden="true">⚠</span> Possible but throttled —
        a strong password is out of reach; a weak one is not (same story as bcrypt/scrypt).</span>
      </div>
      <div class="attack-scenario attack-blocked">
        <strong>Attack 3 — precomputed rainbow tables</strong>
        <span>The OPRF key is <em>per user</em>. A table built for one user's key is
        worthless against another's, and it can't be built <em>before</em> the breach.</span>
        <span class="breach-verdict"><span aria-hidden="true">✓</span> Impossible — no cross-user or pre-breach precomputation.</span>
      </div>
      <div class="attack-scenario attack-warn">
        <strong>Attack 4 — impersonate the server on the next login</strong>
        <span>KE2's <code>server_mac</code> and the 3DH need the server's static private
        key; the client's <code>clientLoginStep3</code> aborts on a bad server MAC.</span>
        <span class="breach-verdict"><span aria-hidden="true">⚠</span> Needs the server static key too — envelope alone is not enough.</span>
      </div>
      <p class="ground-note">Notation note: this matches the code exactly — the stretch is
      <code>scrypt</code>, not the illustrative <code>k·H(pwd')</code> shorthand. "~100M hash
      ops" is a rule-of-thumb for bcrypt cost-10; here the honest, measured gate is the
      per-guess scrypt time shown above.</p>
    `;
    host.replaceChildren(analysis);
  };

  const btn = createButton('Analyze breach', () => render(btn));
  exhibit.appendChild(btn);
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
      300M+ users, OPAQUE-based construction
    </div>
    <div class="deployment">
      <strong>Cloudflare Zero Trust</strong><br />
      Passwordless authentication research<br />
      Eliminates credential stuffing surface
    </div>
    <div class="deployment">
      <strong>Apple Private Cloud Compute</strong><br />
      OPRF-based privacy constructions
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
      <p class="cl-hero-desc">Runs the real OPRF → encrypted-envelope → 3-message 3DH handshake so you can step through a registration and login where the server never sees your password.</p>
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
  main.appendChild(createExhibit1());
  main.appendChild(createExhibit2());
  main.appendChild(createExhibit3());
  main.appendChild(createExhibit4());
  main.appendChild(createExhibit5());

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
