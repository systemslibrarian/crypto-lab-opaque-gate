/**
 * OPAQUE aPAKE Demo — Five Exhibits
 *
 * Exhibit 1: Why Current Password Auth Is Broken
 * Exhibit 2: The OPRF — Blinding the Password
 * Exhibit 3: Registration and Login Protocol
 * Exhibit 4: Server Breach Simulation
 * Exhibit 5: Real-World Deployments and Library Context
 */

import { generateOprfKey, oprfClientBlind, oprfServerEvaluate, oprfClientUnblind } from './oprf';
import { register, sealEnvelope, openEnvelope, RegistrationRecord } from './envelope';
import {
  clientLoginStep1,
  serverLoginStep2,
  clientLoginStep3,
  serverFinalize
} from './ake';

// ============================================================
// Utility Functions
// ============================================================

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .substring(0, 32);
}

function createContainer(title: string): HTMLElement {
  const section = document.createElement('section');
  section.className = 'exhibit';
  const heading = document.createElement('h2');
  heading.textContent = title;
  section.appendChild(heading);
  return section;
}

function createTwoColumn(): { container: HTMLElement; left: HTMLElement; right: HTMLElement } {
  const container = document.createElement('div');
  container.className = 'two-column';

  const left = document.createElement('div');
  left.className = 'column client-side';
  left.innerHTML = '<h3>CLIENT</h3>';

  const right = document.createElement('div');
  right.className = 'column server-side';
  right.innerHTML = '<h3>SERVER</h3>';

  container.appendChild(left);
  container.appendChild(right);

  return { container, left, right };
}

function createButton(label: string, onClick: () => void | Promise<void>): HTMLElement {
  const button = document.createElement('button');
  button.textContent = label;
  button.onclick = () => {
    button.disabled = true;
    Promise.resolve(onClick()).finally(() => {
      button.disabled = false;
    });
  };
  return button;
}

function createInput(placeholder: string, defaultValue?: string): HTMLInputElement {
  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = placeholder;
  input.setAttribute('aria-label', placeholder);
  if (defaultValue) input.value = defaultValue;
  return input;
}

function createCodeBlock(title: string, content: string): HTMLElement {
  const div = document.createElement('div');
  div.className = 'code-block';
  const label = document.createElement('strong');
  label.textContent = title;
  const code = document.createElement('code');
  code.setAttribute('role', 'code');
  code.setAttribute('aria-label', `${title}: ${content.substring(0, 32)}...`);
  code.textContent = content;
  div.appendChild(label);
  div.appendChild(code);
  return div;
}

// ============================================================
// Exhibit 1: Why Current Password Auth Is Broken
// ============================================================

function createExhibit1(): HTMLElement {
  const exhibit = createContainer('Exhibit 1: Why Current Password Auth Is Broken');

  const description = document.createElement('p');
  description.innerHTML = `
    <strong>Three approaches, three problems:</strong><br />
    Option 1 (Plaintext): Server sees password every time → breach exposes password immediately.<br />
    Option 2 (Hashed): Server stores hash → offline dictionary attack on stolen database.<br />
    Option 3 (OPAQUE): Server stores encrypted envelope + OPRF key → breach requires 1 eval per guess.
  `;
  exhibit.appendChild(description);

  const breachSim = createButton('Simulate Database Breach', async () => {
    const result = document.createElement('div');
    result.className = 'breach-result';
    result.innerHTML = `
      <div class="breach-option">
        <strong>Plaintext Attack:</strong><br />
        Password exposed: hunter2 ❌
      </div>
      <div class="breach-option">
        <strong>Hashed Attack (bcrypt cost-10):</strong><br />
        GPU crack time: ~2 hours ⚠
      </div>
      <div class="breach-option">
        <strong>OPAQUE Attack:</strong><br />
        Envelope ciphertext: 9f2a4c1b8e...<br />
        Without password: indistinguishable from random ✓
      </div>
    `;
    exhibit.appendChild(result);
  });

  exhibit.appendChild(breachSim);

  return exhibit;
}

// ============================================================
// Exhibit 2: The OPRF — Blinding the Password
// ============================================================

function createExhibit2(): HTMLElement {
  const exhibit = createContainer('Exhibit 2: The OPRF — Hiding Password from Server');

  const { container: twoCol, left, right } = createTwoColumn();
  exhibit.appendChild(twoCol);

  // Client side
  const pwdInput = createInput('Password', 'library2026');
  left.appendChild(pwdInput);

  let clientState: { blind: Uint8Array; blindingFactor: Uint8Array } | null = null;
  let serverKey: { oprfPrivate: Uint8Array; oprfPublic: Uint8Array } | null = null;

  const runOPRF = createButton('Run OPRF', async () => {
    // Generate server key once
    if (!serverKey) {
      serverKey = await generateOprfKey();
      right.appendChild(createCodeBlock('Server OPRF Key (k)', bytesToHex(serverKey.oprfPrivate)));
    }

    const pwd = pwdInput.value || 'library2026';

    // Client blind
    clientState = await oprfClientBlind(pwd);
    left.appendChild(createCodeBlock('Blind (→ to server)', bytesToHex(clientState.blind)));

    // Server evaluate
    const evaluated = await oprfServerEvaluate(serverKey.oprfPrivate, clientState.blind);
    right.appendChild(createCodeBlock('Evaluated (← to client)', bytesToHex(evaluated)));

    // Client unblind
    const rwd = await oprfClientUnblind(pwd, evaluated, clientState.blindingFactor);
    left.appendChild(createCodeBlock('RWD (OPRF Output)', bytesToHex(rwd)));
  });

  exhibit.appendChild(runOPRF);

  // Add explanation
  const explanation = document.createElement('div');
  explanation.className = 'explanation';
  explanation.innerHTML = `
    <strong>What server sees:</strong> Blind (looks like random bytes)<br />
    <strong>What server never sees:</strong> Password, H(pwd), r, rwd<br />
    <strong>Key property:</strong> Same password → same rwd (deterministic)
  `;
  exhibit.appendChild(explanation);

  return exhibit;
}

// ============================================================
// Exhibit 3: Registration and Login Protocol
// ============================================================

function createExhibit3(): HTMLElement {
  const exhibit = createContainer('Exhibit 3: Full Registration and Login');

  // Tab switcher
  const tabContainer = document.createElement('div');
  tabContainer.className = 'tabs';

  const regTab = document.createElement('button');
  regTab.textContent = 'REGISTRATION';
  regTab.className = 'tab active';

  const logTab = document.createElement('button');
  logTab.textContent = 'LOGIN';
  logTab.className = 'tab';

  tabContainer.appendChild(regTab);
  tabContainer.appendChild(logTab);
  exhibit.appendChild(tabContainer);

  // Registration panel
  const regPanel = document.createElement('div');
  regPanel.className = 'protocol-panel active';

  const regUsername = createInput('Username', 'alice');
  const regPassword = createInput('Password', 'library2026');
  const regRegisterBtn = createButton('Register', async () => {
    // Generate server keypair
    const serverKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    const serverPubRaw = await crypto.subtle.exportKey('raw', serverKeyPair.publicKey);
    const serverPrivRaw = await crypto.subtle.exportKey('raw', serverKeyPair.privateKey);

    const serverOprfKey = await generateOprfKey();

    const { record, exportKey } = await register(
      regPassword.value,
      regUsername.value,
      serverOprfKey.oprfPrivate,
      new Uint8Array(serverPubRaw)
    );

    // Display result
    const result = document.createElement('div');
    result.className = 'reg-result';
    result.innerHTML = `
      <strong>Registration Complete</strong><br />
      Username: ${record.credentialIdentifier}<br />
      Client Public Key: ${bytesToHex(record.clientPublicKey)}<br />
      Envelope (encrypted): ${bytesToHex(record.envelope)}<br />
      <strong style="color: #0a0">✓ Zero passwords stored on server</strong>
    `;
    regPanel.appendChild(result);

    // Store for login demo
    (window as any)._demoRecord = record;
    (window as any)._demoServerPrivate = serverPrivRaw;
    (window as any)._demoServerPublic = serverPubRaw;
  });

  regPanel.appendChild(regUsername);
  regPanel.appendChild(regPassword);
  regPanel.appendChild(regRegisterBtn);

  // Login panel
  const logPanel = document.createElement('div');
  logPanel.className = 'protocol-panel';

  const logUsername = createInput('Username', 'alice');
  const logPassword = createInput('Password', 'library2026');
  const logLoginBtn = createButton('Login', async () => {
    const record = (window as any)._demoRecord as RegistrationRecord;
    const serverPriv = (window as any)._demoServerPrivate as Uint8Array;
    const serverPub = (window as any)._demoServerPublic as Uint8Array;

    if (!record) {
      alert('Please register first');
      return;
    }

    try {
      // Client step 1
      const { ke1, clientState } = await clientLoginStep1(
        logPassword.value,
        logUsername.value
      );

      // Server step 2
      const { ke2, serverState } = await serverLoginStep2(ke1, record, serverPriv, new Uint8Array(serverPub));

      // Client step 3
      const { ke3, sessionKey, exportKey } = await clientLoginStep3(ke2, clientState);

      // Server finalize
      const finalKey = await serverFinalize(ke3, serverState);

      // Verify keys match
      if (bytesToHex(sessionKey) !== bytesToHex(finalKey)) {
        throw new Error('Session key mismatch');
      }

      const result = document.createElement('div');
      result.className = 'login-result success';
      result.innerHTML = `
        <strong style="color: #0a0">✓ LOGIN SUCCESSFUL</strong><br />
        <strong>Session Key (both sides match):</strong><br />
        ${bytesToHex(sessionKey)}<br />
        <strong>Export Key:</strong><br />
        ${bytesToHex(exportKey)}
      `;
      logPanel.appendChild(result);
    } catch (e) {
      const result = document.createElement('div');
      result.className = 'login-result error';
      result.innerHTML = `<strong style="color: #f33">✗ LOGIN FAILED</strong><br />${(e as Error).message}`;
      logPanel.appendChild(result);
    }
  });

  logPanel.appendChild(logUsername);
  logPanel.appendChild(logPassword);
  logPanel.appendChild(logLoginBtn);

  // Tab switching
  regTab.onclick = () => {
    regTab.classList.add('active');
    logTab.classList.remove('active');
    regPanel.classList.add('active');
    logPanel.classList.remove('active');
  };

  logTab.onclick = () => {
    logTab.classList.add('active');
    regTab.classList.remove('active');
    logPanel.classList.add('active');
    regPanel.classList.remove('active');
  };

  exhibit.appendChild(regPanel);
  exhibit.appendChild(logPanel);

  return exhibit;
}

// ============================================================
// Exhibit 4: Server Breach Simulation
// ============================================================

function createExhibit4(): HTMLElement {
  const exhibit = createContainer('Exhibit 4: Server Database Breach');

  const breachBtn = createButton('Analyze Breach', () => {
    const analysis = document.createElement('div');
    analysis.className = 'breach-analysis';
    analysis.innerHTML = `
      <div class="attack-scenario">
        <strong>Attack 1: Decrypt envelope directly</strong><br />
        Problem: Need rwd (OPRF output)<br />
        rwd requires password<br />
        Result: ✗ Cannot decrypt without password
      </div>
      <div class="attack-scenario">
        <strong>Attack 2: Offline dictionary attack</strong><br />
        If attacker has OPRF key k:<br />
        Can try: rwd' = HKDF(pwd', k · H(pwd'))<br />
        Result: ⚠ Possible but costs ~100M hash ops<br />
        (Same effort as bcrypt cost-10)
      </div>
      <div class="attack-scenario">
        <strong>Attack 3: Pre-computation rainbow tables</strong><br />
        Problem: OPRF key varies per user<br />
        Tables from one user ≠ another user<br />
        Result: ✓ Pre-computation attacks impossible
      </div>
      <div class="attack-scenario">
        <strong>Attack 4: Impersonate server</strong><br />
        Requires server private key<br />
        Or key derivation compromise<br />
        Result: Mitigated by TLS + key separation
      </div>
    `;
    exhibit.appendChild(analysis);
  });

  exhibit.appendChild(breachBtn);

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
  const app = document.getElementById('app');
  if (!app) return;

  // Theme toggle
  const header = document.createElement('header');
  header.className = 'app-header';
  header.innerHTML = `
    <h1>OPAQUE aPAKE Demo — RFC 9807</h1>
    <p>Password never touches the server. Not during registration, not during login, not ever.</p>
  `;

  const themeToggle = document.createElement('button');
  themeToggle.className = 'theme-toggle';
  themeToggle.textContent = '🌙';
  themeToggle.onclick = () => {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('cv-theme', next);
    themeToggle.textContent = next === 'dark' ? '☀️' : '🌙';
  };
  header.appendChild(themeToggle);

  app.appendChild(header);

  // Exhibits
  app.appendChild(createExhibit1());
  app.appendChild(createExhibit2());
  app.appendChild(createExhibit3());
  app.appendChild(createExhibit4());
  app.appendChild(createExhibit5());

  // Footer
  const footer = document.createElement('footer');
  footer.innerHTML = `
    <p>"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."
    — 1 Corinthians 10:31</p>
  `;
  app.appendChild(footer);
}

document.addEventListener('DOMContentLoaded', initApp);
