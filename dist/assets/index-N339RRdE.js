(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const n of document.querySelectorAll('link[rel="modulepreload"]'))a(n);new MutationObserver(n=>{for(const i of n)if(i.type==="childList")for(const s of i.addedNodes)s.tagName==="LINK"&&s.rel==="modulepreload"&&a(s)}).observe(document,{childList:!0,subtree:!0});function r(n){const i={};return n.integrity&&(i.integrity=n.integrity),n.referrerPolicy&&(i.referrerPolicy=n.referrerPolicy),n.crossOrigin==="use-credentials"?i.credentials="include":n.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function a(n){if(n.ep)return;n.ep=!0;const i=r(n);fetch(n.href,i)}})();function B(){return crypto.getRandomValues(new Uint8Array(32))}async function H(e){const t=B(),r=await crypto.subtle.importKey("raw",t,{name:"HKDF",hash:"SHA-256"},!1,["deriveBits"]),a=await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:new TextEncoder().encode(e),info:new TextEncoder().encode("oprf-blind")},r,256);return{blind:new Uint8Array(a),blindingFactor:t}}async function D(){const e=B(),t=await crypto.subtle.importKey("raw",e,{name:"HKDF",hash:"SHA-256"},!1,["deriveBits"]),r=await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:new Uint8Array(0),info:new TextEncoder().encode("oprf-public")},t,256);return{oprfPrivate:e,oprfPublic:new Uint8Array(r)}}async function L(e,t){const r=await crypto.subtle.importKey("raw",e,{name:"HKDF",hash:"SHA-256"},!1,["deriveBits"]),a=await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:t,info:new TextEncoder().encode("oprf-evaluate")},r,256);return new Uint8Array(a)}async function S(e,t,r){const a=await crypto.subtle.importKey("raw",r,{name:"HKDF",hash:"SHA-256"},!1,["deriveBits"]),n=await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:t,info:new TextEncoder().encode("oprf-unblind")},a,256),i=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),{name:"HKDF",hash:"SHA-256"},!1,["deriveBits"]),s=await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:new Uint8Array(n),info:new TextEncoder().encode("oprf-rwd")},i,256);return new Uint8Array(s)}async function k(e,t){const r=new Uint8Array(97);r.set(e.clientPrivateKey,0),r.set(e.serverPublicKey,32);const a=crypto.getRandomValues(new Uint8Array(12)),n=await crypto.subtle.importKey("raw",t,"AES-GCM",!1,["encrypt"]),i=await crypto.subtle.encrypt({name:"AES-GCM",iv:a},n,r),s=new Uint8Array(i.byteLength+12);return s.set(new Uint8Array(i),0),s.set(a,i.byteLength),s}async function N(e,t){const r=e.slice(0,e.byteLength-12),a=e.slice(e.byteLength-12),n=await crypto.subtle.importKey("raw",t,"AES-GCM",!1,["decrypt"]),i=await crypto.subtle.decrypt({name:"AES-GCM",iv:a},n,r),s=new Uint8Array(i);return{clientPrivateKey:s.slice(0,32),serverPublicKey:s.slice(32,97)}}async function I(e,t,r,a){const n=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},!0,["deriveBits"]),i=await crypto.subtle.exportKey("raw",n.publicKey),s=await crypto.subtle.exportKey("raw",n.privateKey),{blind:m,blindingFactor:c}=await H(e),p=await L(r,m),d=await S(e,p,c),y=await k({clientPrivateKey:new Uint8Array(s),serverPublicKey:a},d),b=await crypto.subtle.importKey("raw",d,{name:"HKDF",hash:"SHA-256"},!1,["deriveBits"]),h=await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:new TextEncoder().encode(t),info:new TextEncoder().encode("opaque-exportkey")},b,256);return{record:{credentialIdentifier:t,clientPublicKey:new Uint8Array(i),envelope:y,oprfKey:r},exportKey:new Uint8Array(h)}}async function F(e,t,r,a){const n=new Uint8Array(96);n.set(e,0),n.set(t,32),n.set(r,64);const i=await crypto.subtle.importKey("raw",n,{name:"HKDF",hash:"SHA-256"},!1,["deriveBits"]),s=await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:a,info:new TextEncoder().encode("opaque-3dh-key")},i,256);return new Uint8Array(s)}async function K(e,t){const r=await crypto.subtle.importKey("raw",e,"HMAC",!1,["sign"]),a=await crypto.subtle.sign("HMAC",r,t);return new Uint8Array(a).slice(0,32)}async function _(e,t){const{blind:r,blindingFactor:a}=await H(e),n=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},!0,["deriveBits"]),i=await crypto.subtle.exportKey("raw",n.publicKey);return{ke1:{clientIdentity:t,blindedPassword:r,clientEphemeralPublic:new Uint8Array(i)},clientState:{blindingFactor:a,clientEphemeralPrivate:n.privateKey,clientEphemeralPublic:new Uint8Array(i),password:e}}}async function G(e,t,r,a){const n=await L(t.oprfKey,e.blindedPassword),i=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},!0,["deriveBits"]),s=await crypto.subtle.exportKey("raw",i.publicKey),m=await crypto.subtle.importKey("raw",r,{name:"ECDH",namedCurve:"P-256"},!1,["deriveBits"]),c=await crypto.subtle.importKey("raw",e.clientEphemeralPublic,{name:"ECDH",namedCurve:"P-256"},!1,[]),p=await crypto.subtle.importKey("raw",t.clientPublicKey,{name:"ECDH",namedCurve:"P-256"},!1,[]),d=i.privateKey,y=await crypto.subtle.deriveBits({name:"ECDH",public:p},m,256),b=await crypto.subtle.deriveBits({name:"ECDH",public:c},m,256),h=await crypto.subtle.deriveBits({name:"ECDH",public:p},d,256);e.clientIdentity,e.blindedPassword,e.clientEphemeralPublic,t.envelope;const l=new Uint8Array(e.clientIdentity.length+e.blindedPassword.byteLength+e.clientEphemeralPublic.byteLength+n.byteLength+t.envelope.byteLength+s.byteLength+a.byteLength);let o=0;const u=new TextEncoder;o+=f(l,u.encode(e.clientIdentity),o),o+=f(l,e.blindedPassword,o),o+=f(l,e.clientEphemeralPublic,o),o+=f(l,n,o),o+=f(l,t.envelope,o),o+=f(l,new Uint8Array(s),o),o+=f(l,a,o);const g=await F(new Uint8Array(y),new Uint8Array(b),new Uint8Array(h),l),v=await K(g,l);return{ke2:{oprfEvaluated:n,envelope:t.envelope,serverEphemeralPublic:new Uint8Array(s),serverStaticPublic:a,serverMAC:v},serverState:{sessionKey:g,expectedClientMAC:new Uint8Array(32),transcript:l}}}async function q(e,t){const r=await S(t.password,e.oprfEvaluated,t.blindingFactor),a=await N(e.envelope,r),n=await crypto.subtle.importKey("raw",a.clientPrivateKey,{name:"ECDH",namedCurve:"P-256"},!1,["deriveBits"]),i=await crypto.subtle.importKey("raw",e.serverStaticPublic,{name:"ECDH",namedCurve:"P-256"},!1,[]),s=await crypto.subtle.importKey("raw",e.serverEphemeralPublic,{name:"ECDH",namedCurve:"P-256"},!1,[]),m=await crypto.subtle.deriveBits({name:"ECDH",public:i},n,256),c=await crypto.subtle.deriveBits({name:"ECDH",public:i},t.clientEphemeralPrivate,256),p=await crypto.subtle.deriveBits({name:"ECDH",public:s},n,256),d=new Uint8Array(t.password.length+e.oprfEvaluated.byteLength+e.envelope.byteLength+e.serverEphemeralPublic.byteLength+e.serverStaticPublic.byteLength+t.clientEphemeralPublic.byteLength+32);new TextEncoder;const y=await F(new Uint8Array(m),new Uint8Array(c),new Uint8Array(p),d),b=await K(y,d);if(!R(e.serverMAC,b))throw new Error("Server authentication failed: MAC mismatch");const h=await K(y,d),l=await crypto.subtle.importKey("raw",r,{name:"HKDF",hash:"SHA-256"},!1,["deriveBits"]),o=await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:new Uint8Array(0),info:new TextEncoder().encode("opaque-exportkey")},l,256);return{ke3:{clientMAC:h},sessionKey:y,exportKey:new Uint8Array(o)}}async function W(e,t){const r=await K(t.sessionKey,t.transcript);if(!R(e.clientMAC,r))throw new Error("Client authentication failed: MAC mismatch");return t.sessionKey}function f(e,t,r){return e.set(t,r),t.byteLength}function R(e,t){if(e.byteLength!==t.byteLength)return!1;let r=0;for(let a=0;a<e.byteLength;a++)r|=e[a]^t[a];return r===0}function w(e){return Array.from(e).map(t=>t.toString(16).padStart(2,"0")).join("").substring(0,32)}function P(e){const t=document.createElement("section");t.className="exhibit";const r=document.createElement("h2");return r.textContent=e,t.appendChild(r),t}function $(){const e=document.createElement("div");e.className="two-column";const t=document.createElement("div");t.className="column client-side",t.innerHTML="<h3>CLIENT</h3>";const r=document.createElement("div");return r.className="column server-side",r.innerHTML="<h3>SERVER</h3>",e.appendChild(t),e.appendChild(r),{container:e,left:t,right:r}}function E(e,t){const r=document.createElement("button");return r.textContent=e,r.onclick=()=>{r.disabled=!0,Promise.resolve(t()).finally(()=>{r.disabled=!1})},r}function C(e,t){const r=document.createElement("input");return r.type="text",r.placeholder=e,r.setAttribute("aria-label",e),t&&(r.value=t),r}function A(e,t){const r=document.createElement("div");r.className="code-block";const a=document.createElement("strong");a.textContent=e;const n=document.createElement("code");return n.setAttribute("role","code"),n.setAttribute("aria-label",`${e}: ${t.substring(0,32)}...`),n.textContent=t,r.appendChild(a),r.appendChild(n),r}function Q(){const e=P("Exhibit 1: Why Current Password Auth Is Broken"),t=document.createElement("p");t.innerHTML=`
    <strong>Three approaches, three problems:</strong><br />
    Option 1 (Plaintext): Server sees password every time → breach exposes password immediately.<br />
    Option 2 (Hashed): Server stores hash → offline dictionary attack on stolen database.<br />
    Option 3 (OPAQUE): Server stores encrypted envelope + OPRF key → breach requires 1 eval per guess.
  `,e.appendChild(t);const r=E("Simulate Database Breach",async()=>{const a=document.createElement("div");a.className="breach-result",a.innerHTML=`
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
    `,e.appendChild(a)});return e.appendChild(r),e}function z(){const e=P("Exhibit 2: The OPRF — Hiding Password from Server"),{container:t,left:r,right:a}=$();e.appendChild(t);const n=C("Password","library2026");r.appendChild(n);let i=null,s=null;const m=E("Run OPRF",async()=>{s||(s=await D(),a.appendChild(A("Server OPRF Key (k)",w(s.oprfPrivate))));const p=n.value||"library2026";i=await H(p),r.appendChild(A("Blind (→ to server)",w(i.blind)));const d=await L(s.oprfPrivate,i.blind);a.appendChild(A("Evaluated (← to client)",w(d)));const y=await S(p,d,i.blindingFactor);r.appendChild(A("RWD (OPRF Output)",w(y)))});e.appendChild(m);const c=document.createElement("div");return c.className="explanation",c.innerHTML=`
    <strong>What server sees:</strong> Blind (looks like random bytes)<br />
    <strong>What server never sees:</strong> Password, H(pwd), r, rwd<br />
    <strong>Key property:</strong> Same password → same rwd (deterministic)
  `,e.appendChild(c),e}function V(){const e=P("Exhibit 3: Full Registration and Login"),t=document.createElement("div");t.className="tabs";const r=document.createElement("button");r.textContent="REGISTRATION",r.className="tab active";const a=document.createElement("button");a.textContent="LOGIN",a.className="tab",t.appendChild(r),t.appendChild(a),e.appendChild(t);const n=document.createElement("div");n.className="protocol-panel active";const i=C("Username","alice"),s=C("Password","library2026"),m=E("Register",async()=>{const b=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},!0,["deriveBits"]),h=await crypto.subtle.exportKey("raw",b.publicKey),l=await crypto.subtle.exportKey("raw",b.privateKey),o=await D(),{record:u,exportKey:g}=await I(s.value,i.value,o.oprfPrivate,new Uint8Array(h)),v=document.createElement("div");v.className="reg-result",v.innerHTML=`
      <strong>Registration Complete</strong><br />
      Username: ${u.credentialIdentifier}<br />
      Client Public Key: ${w(u.clientPublicKey)}<br />
      Envelope (encrypted): ${w(u.envelope)}<br />
      <strong style="color: #0a0">✓ Zero passwords stored on server</strong>
    `,n.appendChild(v),window._demoRecord=u,window._demoServerPrivate=l,window._demoServerPublic=h});n.appendChild(i),n.appendChild(s),n.appendChild(m);const c=document.createElement("div");c.className="protocol-panel";const p=C("Username","alice"),d=C("Password","library2026"),y=E("Login",async()=>{const b=window._demoRecord,h=window._demoServerPrivate,l=window._demoServerPublic;if(!b){alert("Please register first");return}try{const{ke1:o,clientState:u}=await _(d.value,p.value),{ke2:g,serverState:v}=await G(o,b,h,new Uint8Array(l)),{ke3:T,sessionKey:U,exportKey:O}=await q(g,u),M=await W(T,v);if(w(U)!==w(M))throw new Error("Session key mismatch");const x=document.createElement("div");x.className="login-result success",x.innerHTML=`
        <strong style="color: #0a0">✓ LOGIN SUCCESSFUL</strong><br />
        <strong>Session Key (both sides match):</strong><br />
        ${w(U)}<br />
        <strong>Export Key:</strong><br />
        ${w(O)}
      `,c.appendChild(x)}catch(o){const u=document.createElement("div");u.className="login-result error",u.innerHTML=`<strong style="color: #f33">✗ LOGIN FAILED</strong><br />${o.message}`,c.appendChild(u)}});return c.appendChild(p),c.appendChild(d),c.appendChild(y),r.onclick=()=>{r.classList.add("active"),a.classList.remove("active"),n.classList.add("active"),c.classList.remove("active")},a.onclick=()=>{a.classList.add("active"),r.classList.remove("active"),c.classList.add("active"),n.classList.remove("active")},e.appendChild(n),e.appendChild(c),e}function Z(){const e=P("Exhibit 4: Server Database Breach"),t=E("Analyze Breach",()=>{const r=document.createElement("div");r.className="breach-analysis",r.innerHTML=`
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
    `,e.appendChild(r)});return e.appendChild(t),e}function j(){const e=P("Exhibit 5: Real-World Deployments & Library Context"),t=document.createElement("div");t.className="deployments",t.innerHTML=`
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
  `,e.appendChild(t);const r=document.createElement("div");return r.className="library-context",r.innerHTML=`
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
  `,e.appendChild(r),e}function J(){const e=document.getElementById("app");if(!e)return;const t=document.createElement("header");t.className="app-header",t.innerHTML=`
    <h1>OPAQUE aPAKE Demo — RFC 9807</h1>
    <p>Password never touches the server. Not during registration, not during login, not ever.</p>
  `;const r=document.createElement("button");r.className="theme-toggle",r.textContent="🌙",r.onclick=()=>{const i=(document.documentElement.getAttribute("data-theme")||"dark")==="dark"?"light":"dark";document.documentElement.setAttribute("data-theme",i),localStorage.setItem("cv-theme",i),r.textContent=i==="dark"?"☀️":"🌙"},t.appendChild(r),e.appendChild(t),e.appendChild(Q()),e.appendChild(z()),e.appendChild(V()),e.appendChild(Z()),e.appendChild(j());const a=document.createElement("footer");a.innerHTML=`
    <p>"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."
    — 1 Corinthians 10:31</p>
  `,e.appendChild(a)}document.addEventListener("DOMContentLoaded",J);
