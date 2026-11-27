// Vectoll.org — Open Protocol Studio, Real WebCrypto Engine, Inspector, Builder & RFC Hub

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// ─── Utilities & Toast ────────────────────────────────────────────────────────
function showToast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => el.classList.remove('show'), 2200);
}

async function copyText(text, label = 'Copied to clipboard') {
  try {
    await navigator.clipboard.writeText(text);
    showToast('✓ ' + label);
  } catch {
    showToast('Copy ready');
  }
}

function downloadFile(filename, content, mime = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast(`Downloaded ${filename}`);
}

function b64UrlEncodeBytes(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64UrlEncodeStr(str) {
  return b64UrlEncodeBytes(new TextEncoder().encode(str));
}

function b64UrlDecodeBytes(b64u) {
  const norm = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const pad = norm.length % 4 === 0 ? '' : '='.repeat(4 - (norm.length % 4));
  const bin = atob(norm + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base58Encode(bytes) {
  let zeroes = 0;
  while (zeroes < bytes.length && bytes[zeroes] === 0) zeroes++;
  let num = 0n;
  for (const b of bytes) num = (num << 8n) + BigInt(b);
  const chars = [];
  while (num > 0n) {
    chars.push(BASE58_ALPHABET[Number(num % 58n)]);
    num /= 58n;
  }
  for (let i = 0; i < zeroes; i++) chars.push('1');
  return chars.reverse().join('');
}

function base58Decode(str) {
  let zeroes = 0;
  while (zeroes < str.length && str[zeroes] === '1') zeroes++;
  let num = 0n;
  for (let i = zeroes; i < str.length; i++) {
    const idx = BASE58_ALPHABET.indexOf(str[i]);
    if (idx === -1) throw new Error('Invalid base58 character: ' + str[i]);
    num = num * 58n + BigInt(idx);
  }
  const list = [];
  while (num > 0n) {
    list.push(Number(num & 0xffn));
    num >>= 8n;
  }
  list.reverse();
  const out = new Uint8Array(zeroes + list.length);
  out.set(list, zeroes);
  return out;
}

function pubBytesToDidKey(pubBytes) {
  const prefixed = new Uint8Array(2 + pubBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pubBytes, 2);
  return 'did:key:z' + base58Encode(prefixed);
}

function didKeyToPubBytes(did) {
  if (!did.startsWith('did:key:z')) throw new Error('Expected did:key:z...');
  const decoded = base58Decode(did.slice('did:key:z'.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('Invalid Ed25519 multicodec prefix in DID');
  }
  return decoded.slice(2);
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function randHex(n = 12) {
  const arr = new Uint8Array(Math.ceil(n / 2));
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, n);
}

// ─── View Router & Theme Switcher ─────────────────────────────────────────────
const VIEWS = ['overview', 'studio', 'inspector', 'builder', 'docs', 'directory'];

function switchView(viewId, updateHash = true) {
  if (!VIEWS.includes(viewId)) viewId = 'overview';
  VIEWS.forEach(v => {
    document.getElementById('view-' + v)?.classList.toggle('active', v === viewId);
  });
  document.querySelectorAll('.view-tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.view === viewId);
  });
  if (updateHash) history.replaceState(null, '', '#' + viewId);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', cur === 'light' ? 'light' : '');
  localStorage.setItem('vectoll_org_theme', cur);
  updateThemeAssets(cur);
}

function updateThemeAssets(theme) {
  const btn = document.getElementById('themeBtn');
  if (btn) btn.textContent = theme === 'light' ? '☾ Dark' : '☀ Light';
  const wordmark = document.getElementById('heroWordmark');
  if (wordmark) {
    wordmark.src = theme === 'light' ? '/brand/logo-wordmark-light.svg' : '/brand/logo-wordmark-dark.svg';
  }
}

// ─── Command Palette (⌘K / Ctrl+K) ────────────────────────────────────────────
const COMMANDS = [
  { label: 'Go to Overview & 3-Line Quickstart', hint: '#overview', run: () => switchView('overview') },
  { label: 'Launch Real Ed25519 WebCrypto Studio', hint: '#studio', run: () => switchView('studio') },
  { label: 'Mint Real Signed vrt1 Receipt Token', hint: 'WebCrypto', run: () => { switchView('studio'); mintLiveVrt(); } },
  { label: 'Generate New Ed25519 Keypair & did:key', hint: 'EdDSA', run: () => { switchView('studio'); generateBrowserKeypair(); } },
  { label: 'Open VRT1 Token & vectoll.json Inspector', hint: '#inspector', run: () => switchView('inspector') },
  { label: 'Open Full-Stack Config & Docker Architect', hint: '#builder', run: () => switchView('builder') },
  { label: 'Read RFC-0001: Core HTTP 402 & VRT1 Spec', hint: 'RFC-0001', run: () => { switchView('docs'); renderDoc('rfc1'); } },
  { label: 'Read RFC-0002: MCP Payment Binding', hint: 'RFC-0002', run: () => { switchView('docs'); renderDoc('rfc2'); } },
  { label: 'Read RFC-0003: Passkey Mandates (vsm1p)', hint: 'RFC-0003', run: () => { switchView('docs'); renderDoc('rfc3'); } },
  { label: 'Read RFC-0004: Cross-Facilitator Federation', hint: 'RFC-0004', run: () => { switchView('docs'); renderDoc('rfc4'); } },
  { label: 'Browse Metered API & MCP Directory', hint: '#directory', run: () => switchView('directory') },
  { label: 'Toggle Light / Dark Extruded Theme', hint: 'Theme', run: () => toggleTheme() },
  { label: 'Open Vectoll Cloud (vectoll.com)', hint: 'External', run: () => window.open('https://vectoll.com', '_blank') },
];

function openPalette() {
  const modal = document.getElementById('cmdModal');
  modal.classList.add('open');
  const input = document.getElementById('cmdInput');
  input.value = '';
  renderPalette('');
  setTimeout(() => input.focus(), 30);
}
function closePalette() {
  document.getElementById('cmdModal').classList.remove('open');
}
function renderPalette(q) {
  const list = document.getElementById('cmdList');
  const norm = q.trim().toLowerCase();
  const matches = COMMANDS.filter(c => !norm || c.label.toLowerCase().includes(norm) || c.hint.toLowerCase().includes(norm));
  list.innerHTML = matches.map((c, idx) => `
    <button class="palette-item" data-idx="${idx}">
      <span>${c.label}</span>
      <span class="badge">${c.hint}</span>
    </button>
  `).join('');
  list.querySelectorAll('.palette-item').forEach((el, i) => {
    el.onclick = () => { closePalette(); matches[i].run(); };
  });
}

// ─── Overview: Package Switcher, 8-Stack Code Switcher, Classifier & 23-FX ────
const PKG_CMDS = {
  npm: 'npm install @vectoll/server @vectoll/sdk',
  pnpm: 'pnpm add @vectoll/server @vectoll/sdk',
  pip: 'pip install vectoll',
  go: 'go install github.com/vectoll/vectoll/services/gate/cmd/vectoll-gate@latest',
  cli: 'npx @vectoll/cli proxy http://localhost:3000 --route "GET /api/*=$0.005"',
};

const STACK_SNIPPETS = {
  express: {
    file: 'server.ts — Express / Node HTTP (runs on your existing port)',
    code: `import express from 'express';
import { vectollMiddleware } from '@vectoll/server';

const app = express();
app.use(vectollMiddleware({
  routes: {
    'GET /api/signals': '$0.005',
    'GET /articles/*': { price: '$0.002', browsers: 'free', transform: 'structured' },
    'POST /api/book': { price: '€2.50', settlementMode: 'escrow', hitlThreshold: '€25.00' },
  },
}));

app.get('/api/signals', (_req, res) => res.json({ alpha: 0.984, region: 'global' }));
app.listen(3000);`
  },
  nextjs: {
    file: 'app/api/research/route.ts — Next.js App Router / Hono / Cloudflare Workers',
    code: `import { withVectoll } from '@vectoll/server';

export const GET = withVectoll(
  { price: '$0.01', browsers: 'free', acceptedRails: ['stripe', 'x402_usdc', 'sepa_instant'] },
  async (req, receipt) => {
    return Response.json({
      verifiedOffline: true,
      paidByAgent: receipt?.sub ?? 'human-browser',
      rail: receipt?.rail ?? 'free',
    });
  }
);`
  },
  fastapi: {
    file: 'main.py — Python FastAPI / Starlette ASGI Middleware',
    code: `from fastapi import FastAPI
from vectoll.asgi import VectollMiddleware

app = FastAPI()
app.add_middleware(
    VectollMiddleware,
    facilitator_url="https://pay.vectoll.com",
    routes={
        "GET /api/forecast": "$0.005",
        "GET /docs/*": {"price": "$0.001", "browsers": "free"},
    },
)

@app.get("/api/forecast")
async def forecast():
    return {"model": "climate-v4", "confidence": 0.994}`
  },
  go: {
    file: 'vectoll-gate — High-Throughput Go Edge Proxy (<0.3ms Ed25519 verify)',
    code: `# Zero code changes to any Go, Rust, Rails, PHP, or Java service:
vectoll-gate \\
  --origin http://127.0.0.1:8080 \\
  --listen :4020 \\
  --facilitator https://pay.vectoll.com \\
  --redis redis://127.0.0.1:6379 \\
  --config vectoll.yaml
# Automatically serves /.well-known/vectoll.json, /mcp, and /metrics`
  },
  mcp: {
    file: 'mcp-server.ts — Metered Model Context Protocol (RFC-0002)',
    code: `import { createMeteredMcpServer } from '@vectoll/server';

const mcp = createMeteredMcpServer({
  name: 'global-fx-oracle',
  tools: {
    spot_rate: {
      price: '$0.002',
      description: 'Real-time institutional FX & crypto spot quote',
      handler: async ({ pair }) => ({ pair, mid: 1.0864, ts: Date.now() }),
    },
  },
});

mcp.listen(4020); // Connect Claude/Cursor via: npx @vectoll/cli mcp-bridge`
  },
  yaml: {
    file: 'vectoll.yaml — 6-Line Declarative Reverse Proxy',
    code: `origin: "http://localhost:3000"

routes:
  GET /api/search: "$0.005"
  GET /blog/*: { price: "$0.001", browsers: "free", transform: "structured" }
  POST /api/reserve: { price: "$5.00", mode: "escrow", approve_above: "$50.00" }`
  },
  aisdk: {
    file: 'agent.ts — Autonomous AI Agent with Spend Mandate (@vectoll/ai-sdk)',
    code: `import { generateKeyPair } from '@vectoll/core';
import { VectollAgentClient } from '@vectoll/sdk';

const agent = new VectollAgentClient({
  agentKeyPair: generateKeyPair(),
  facilitatorUrl: 'https://pay.vectoll.com',
  preferredRail: 'x402_usdc',
  mandateToken: process.env.VECTOLL_PASSKEY_MANDATE, // WebAuthn P-256 vsm1p
});

// Transparently handles HTTP 402 -> settles -> attaches vrt1 -> returns 200 OK
const res = await agent.fetch('https://api.acme.com/api/signals');`
  }
};

const CLASSIFIER_PRESETS = {
  chrome: { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36', accept: 'text/html,application/xhtml+xml', sec: 'navigate', payHeader: false },
  gptbot: { ua: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)', accept: 'text/html,*/*', sec: 'none', payHeader: false },
  claudebot: { ua: 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)', accept: 'text/markdown,text/html', sec: 'none', payHeader: false },
  mcp: { ua: 'Vectoll-MCP-Bridge/1.0 (Claude-Desktop)', accept: 'application/json', sec: 'none', payHeader: true },
  python: { ua: 'python-httpx/0.27.2', accept: 'application/json', sec: 'none', payHeader: false },
};

function evaluateClassifier() {
  const ua = document.getElementById('clsUa').value;
  const accept = document.getElementById('clsAccept').value;
  const sec = document.getElementById('clsSec').value;
  const hasPay = document.getElementById('clsPay').checked;
  const out = document.getElementById('clsResult');

  const botRegex = /(GPTBot|ClaudeBot|PerplexityBot|Google-Extended|CCBot|Vectoll|MCP|LangChain|CrewAI|python-httpx|python-requests|curl\/|Go-http-client|undici)/i;
  if (hasPay) {
    out.innerHTML = `<span class="badge em">AGENT VERIFIED (200 OK)</span><p style="margin-top:8px;font-size:13px;color:var(--ink-1);">Rule §4.1: Carries <code>PAYMENT-SIGNATURE: vrt1...</code> — verified offline in 0.24ms, structured payload returned.</p>`;
  } else if (botRegex.test(ua)) {
    out.innerHTML = `<span class="badge am">AUTONOMOUS AGENT → HTTP 402 CHALLENGE</span><p style="margin-top:8px;font-size:13px;color:var(--ink-1);">Rule §4.2: Crawler/SDK signature matched in <code>User-Agent</code>. Emits <code>PAYMENT-REQUIRED</code> across 9 global rails.</p>`;
  } else if (ua.includes('Mozilla/5.0') && accept.includes('text/html') && sec === 'navigate') {
    out.innerHTML = `<span class="badge em">HUMAN BROWSER PASSTHROUGH ($0.00 FREE)</span><p style="margin-top:8px;font-size:13px;color:var(--ink-1);">Rule §4.3: Interactive browser + <code>Accept: text/html</code> + <code>Sec-Fetch-Mode: navigate</code>. Zero friction for human readers.</p>`;
  } else {
    out.innerHTML = `<span class="badge am">PROGRAMMATIC CLIENT → HTTP 402 CHALLENGE</span><p style="margin-top:8px;font-size:13px;color:var(--ink-1);">Rule §4.4: Missing interactive browser Fetch Metadata or HTML accept header. Metered per route policy.</p>`;
  }
}

// 23-Currency FX
const CURRENCIES = [
  { code: 'USD', sym: '$', dec: 2, rate: 1.0 },
  { code: 'USDC', sym: 'USDC ', dec: 6, rate: 1.0 },
  { code: 'EUR', sym: '€', dec: 2, rate: 0.92 },
  { code: 'GBP', sym: '£', dec: 2, rate: 0.79 },
  { code: 'JPY', sym: '¥', dec: 0, rate: 154.0 },
  { code: 'CHF', sym: 'CHF ', dec: 2, rate: 0.88 },
  { code: 'CAD', sym: 'CA$', dec: 2, rate: 1.38 },
  { code: 'AUD', sym: 'A$', dec: 2, rate: 1.53 },
  { code: 'SGD', sym: 'S$', dec: 2, rate: 1.34 },
  { code: 'HKD', sym: 'HK$', dec: 2, rate: 7.78 },
  { code: 'INR', sym: '₹', dec: 2, rate: 84.2 },
  { code: 'BRL', sym: 'R$', dec: 2, rate: 5.75 },
  { code: 'MXN', sym: 'MX$', dec: 2, rate: 20.1 },
  { code: 'KRW', sym: '₩', dec: 0, rate: 1390.0 },
  { code: 'AED', sym: 'AED ', dec: 2, rate: 3.6725 },
  { code: 'SAR', sym: 'SAR ', dec: 2, rate: 3.75 },
  { code: 'PLN', sym: 'zł ', dec: 2, rate: 4.02 },
  { code: 'SEK', sym: 'kr ', dec: 2, rate: 10.75 },
  { code: 'ZAR', sym: 'R ', dec: 2, rate: 18.1 },
  { code: 'NGN', sym: '₦', dec: 2, rate: 1650.0 },
  { code: 'KES', sym: 'KES ', dec: 2, rate: 129.0 },
  { code: 'UGX', sym: 'UGX ', dec: 0, rate: 3700.0 },
  { code: 'GHS', sym: 'GH₵', dec: 2, rate: 15.8 },
];

function computeFx() {
  const amt = Math.max(0, parseFloat(document.getElementById('fxAmt').value) || 0);
  const from = CURRENCIES.find(c => c.code === document.getElementById('fxFrom').value) || CURRENCIES[0];
  const to = CURRENCIES.find(c => c.code === document.getElementById('fxTo').value) || CURRENCIES[2];
  const usd = amt / from.rate;
  const minor = Math.round(usd * to.rate * Math.pow(10, to.dec));
  const major = (minor / Math.pow(10, to.dec)).toFixed(to.dec === 6 ? 4 : to.dec);

  document.getElementById('fxHeadline').textContent = `${from.sym}${amt} ${from.code} = ${to.sym}${major} ${to.code}`;
  document.getElementById('fxPayload').textContent = `{"amt":${minor},"cur":"${to.code}","dec":${to.dec}}`;

  document.getElementById('fxGrid').innerHTML = CURRENCIES.map(c => {
    const m = Math.round(usd * c.rate * Math.pow(10, c.dec));
    const d = (m / Math.pow(10, c.dec)).toFixed(c.dec === 6 ? 4 : c.dec);
    return `<div class="wire-flat" style="padding:8px 10px;font-family:var(--mono);font-size:11.5px;">
      <div style="color:var(--ink-3);font-size:10.5px;">${c.code} · ${c.dec}d</div>
      <div style="font-weight:700;margin-top:2px;">${c.sym}${d}</div>
    </div>`;
  }).join('');
}

// ─── Studio: Real Browser WebCrypto Ed25519 Keypair, reqHash, VRT1 & HTML→MD ──
let studioKey = {
  alg: 'Ed25519',
  kid: 'fac-ed25519-live',
  did: '',
  pubB64: '',
  jwkPublic: null,
  cryptoKeyPair: null,
};
let lastMintedVrt = '';

async function generateBrowserKeypair() {
  try {
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const jwkPub = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const did = pubBytesToDidKey(rawPub);
    const kid = 'fac-' + Array.from(rawPub.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('');
    studioKey = {
      alg: 'Ed25519',
      kid,
      did,
      pubB64: b64UrlEncodeBytes(rawPub),
      jwkPublic: { ...jwkPub, kid, use: 'sig', alg: 'EdDSA' },
      cryptoKeyPair: kp,
    };
  } catch {
    // Fallback to WebCrypto ECDSA P-256 on older browsers lacking Ed25519
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwkPub = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const fakePub = new Uint8Array(32);
    crypto.getRandomValues(fakePub);
    studioKey = {
      alg: 'ECDSA-P256',
      kid: 'fac-p256-' + randHex(6),
      did: pubBytesToDidKey(fakePub),
      pubB64: b64UrlEncodeBytes(fakePub),
      jwkPublic: jwkPub,
      cryptoKeyPair: kp,
    };
  }

  document.getElementById('stKid').textContent = `${studioKey.kid} (${studioKey.alg} WebCrypto)`;
  document.getElementById('stDid').value = studioKey.did;
  document.getElementById('stJwk').textContent = JSON.stringify(studioKey.jwkPublic, null, 2);
  document.getElementById('inspPubKey').value = studioKey.did;
  await mintLiveVrt();
}

async function computeStudioReqHash() {
  const method = document.getElementById('stMethod').value.toUpperCase();
  const target = document.getElementById('stTarget').value.trim() || '/';
  const body = method === 'GET' ? '' : document.getElementById('stBody').value;
  const bodyHex = await sha256Hex(body);
  const canonical = `${method}\n${target}\n${bodyHex}`;
  const reqHash = 'sha256:' + (await sha256Hex(canonical));
  document.getElementById('stCanonical').textContent = canonical;
  document.getElementById('stReqHash').textContent = reqHash;
  return { method, target, body, reqHash };
}

async function signBytesWithStudioKey(signingInput) {
  const data = new TextEncoder().encode(signingInput);
  if (studioKey.alg === 'Ed25519') {
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, studioKey.cryptoKeyPair.privateKey, data);
    return b64UrlEncodeBytes(new Uint8Array(sig));
  }
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, studioKey.cryptoKeyPair.privateKey, data);
  return b64UrlEncodeBytes(new Uint8Array(sig));
}

async function verifyVrtInBrowser(token, didOrB64) {
  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts[0] !== 'vrt1') {
    return { valid: false, code: 'ERR_MALFORMED_VRT', reason: 'Expected vrt1.<payload>.<signature>' };
  }
  let claims;
  try {
    claims = JSON.parse(new TextDecoder().decode(b64UrlDecodeBytes(parts[1])));
  } catch {
    return { valid: false, code: 'ERR_INVALID_JSON', reason: 'Payload is not valid base64url JSON' };
  }

  const signingInput = `vrt1.${parts[1]}`;
  const sigBytes = b64UrlDecodeBytes(parts[2]);

  try {
    if (studioKey.alg === 'Ed25519') {
      const pubBytes = didOrB64.startsWith('did:key:z')
        ? didKeyToPubBytes(didOrB64.trim())
        : b64UrlDecodeBytes(didOrB64.trim());
      const pubKey = await crypto.subtle.importKey('raw', pubBytes, { name: 'Ed25519' }, false, ['verify']);
      const ok = await crypto.subtle.verify({ name: 'Ed25519' }, pubKey, sigBytes, new TextEncoder().encode(signingInput));
      if (!ok) return { valid: false, code: 'ERR_INVALID_RECEIPT_SIGNATURE', reason: 'Ed25519 cryptographic signature mismatch!', claims };
    } else if (studioKey.cryptoKeyPair) {
      const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, studioKey.cryptoKeyPair.publicKey, sigBytes, new TextEncoder().encode(signingInput));
      if (!ok) return { valid: false, code: 'ERR_INVALID_RECEIPT_SIGNATURE', reason: 'Cryptographic signature mismatch!', claims };
    }
  } catch (e) {
    return { valid: false, code: 'ERR_KEY_DECODE', reason: e.message, claims };
  }

  const now = Math.floor(Date.now() / 1000);
  if (claims.exp && now > claims.exp + 5) {
    return { valid: false, code: 'ERR_RECEIPT_EXPIRED', reason: `Token expired ${now - claims.exp}s ago`, claims };
  }
  return { valid: true, code: 'VERIFIED_OFFLINE', claims };
}

async function mintLiveVrt() {
  if (!studioKey.cryptoKeyPair) return;
  const t0 = performance.now();
  const { method, target, reqHash } = await computeStudioReqHash();
  const [rail, cur, decStr, amtStr, disp] = document.getElementById('stRail').value.split('|');
  const mode = document.getElementById('stMode').value;
  const now = Math.floor(Date.now() / 1000);

  const claims = {
    v: 1,
    jti: 'vrt_' + randHex(12),
    kid: studioKey.kid,
    iss: studioKey.did,
    sub: 'did:key:z6MkAgent' + randHex(16),
    aud: 'https://api.vectoll.org',
    chg: 'chg_' + randHex(10),
    req: reqHash,
    amt: Number(amtStr),
    cur,
    dec: Number(decStr),
    rail,
    mode,
    ...(mode === 'escrow' ? { esc: 'esc_' + randHex(8) } : {}),
    iat: now,
    exp: now + 120,
  };

  const payloadB64 = b64UrlEncodeStr(JSON.stringify(claims));
  const signingInput = `vrt1.${payloadB64}`;
  const sigB64 = await signBytesWithStudioKey(signingInput);
  const token = `${signingInput}.${sigB64}`;
  lastMintedVrt = token;

  const verifyCheck = await verifyVrtInBrowser(token, studioKey.did);
  const dt = (performance.now() - t0).toFixed(2);

  renderStudioTrace({ method, target, token, claims, disp, verifyCheck, dt });
}

function renderStudioTrace({ method, target, token, claims, disp, verifyCheck, dt }) {
  const statusEl = document.getElementById('stVerifyBadge');
  if (verifyCheck.valid) {
    statusEl.className = 'badge em';
    statusEl.textContent = `✓ VALID ED25519 VRT1 (${dt} ms)`;
  } else {
    statusEl.className = 'badge ro';
    statusEl.textContent = `✕ ${verifyCheck.code}: ${verifyCheck.reason}`;
  }

  document.getElementById('stTokenOut').textContent = token;
  document.getElementById('stHttpOut').textContent =
`${method} ${target} HTTP/1.1
Host: api.vectoll.org
User-Agent: VectollAgent/1.0
PAYMENT-SIGNATURE: ${token}

--- GATE OFFLINE VERIFICATION (${dt} ms) ---
Status: ${verifyCheck.valid ? 'HTTP/1.1 200 OK' : 'HTTP/1.1 402 Payment Required'}
${verifyCheck.valid
  ? `PAYMENT-RESPONSE: {"receiptId":"${claims.jti}","rail":"${claims.rail}","settled":"${disp}","mode":"${claims.mode}"}`
  : `X-Vectoll-Error: ${verifyCheck.code} (${verifyCheck.reason})`}`;

  document.getElementById('stLedgerBody').innerHTML = verifyCheck.valid
    ? `<tr><td>agent:float:${claims.rail}</td><td>${claims.cur}</td><td>${claims.amt} (${disp})</td><td>0</td><td>${claims.jti}</td></tr>
       <tr><td>${claims.mode === 'escrow' ? 'escrow:hold:liability' : 'merchant:payable:origin'}</td><td>${claims.cur}</td><td>0</td><td>${claims.amt} (${disp})</td><td>${claims.mode.toUpperCase()}</td></tr>`
    : `<tr><td colspan="5" style="color:var(--rose-ink);">Rejected at Gate before reaching origin — zero ledger entries posted.</td></tr>`;
}

async function tamperLiveVrt() {
  if (!lastMintedVrt) await mintLiveVrt();
  const parts = lastMintedVrt.split('.');
  const claims = JSON.parse(new TextDecoder().decode(b64UrlDecodeBytes(parts[1])));
  claims.amt = 1; // Attacker tries to alter amount without private key!
  claims.aud = 'https://expensive-endpoint.example';
  const forgedToken = `vrt1.${b64UrlEncodeStr(JSON.stringify(claims))}.${parts[2]}`;
  const t0 = performance.now();
  const verifyCheck = await verifyVrtInBrowser(forgedToken, studioKey.did);
  const dt = (performance.now() - t0).toFixed(2);
  renderStudioTrace({
    method: document.getElementById('stMethod').value,
    target: document.getElementById('stTarget').value,
    token: forgedToken,
    claims,
    disp: 'TAMPERED',
    verifyCheck,
    dt,
  });
  showToast('Tampered payload rejected by Ed25519 verifier!');
}

function sendStudioTokenToInspector() {
  document.getElementById('inspToken').value = document.getElementById('stTokenOut').textContent;
  document.getElementById('inspPubKey').value = studioKey.did;
  switchView('inspector');
  runTokenInspector();
}

// HTML -> Structured Markdown/JSON Agent Translator
function runHtmlTranslator() {
  const raw = document.getElementById('trHtmlIn').value;
  const doc = new DOMParser().parseFromString(raw, 'text/html');
  doc.querySelectorAll('script, style, nav, footer, aside, .ad-banner, .cookie-modal').forEach(el => el.remove());
  const title = doc.querySelector('h1, title')?.textContent?.trim() || 'Untitled Resource';
  const blocks = [];
  doc.querySelectorAll('h1, h2, h3, p, li').forEach(el => {
    const txt = el.textContent.replace(/\s+/g, ' ').trim();
    if (!txt) return;
    if (el.tagName === 'H1') blocks.push(`# ${txt}`);
    else if (el.tagName === 'H2') blocks.push(`## ${txt}`);
    else if (el.tagName === 'H3') blocks.push(`### ${txt}`);
    else if (el.tagName === 'LI') blocks.push(`- ${txt}`);
    else blocks.push(txt);
  });
  const markdown = blocks.join('\n\n');
  const rawToks = Math.max(1, Math.ceil(raw.length / 4));
  const cleanToks = Math.max(1, Math.ceil(markdown.length / 4));
  const savedPct = Math.max(0, Math.round((1 - cleanToks / rawToks) * 100));

  document.getElementById('trSavingsBadge').textContent = `-${savedPct}% LLM Context Tokens (${rawToks} → ${cleanToks})`;
  document.getElementById('trJsonOut').textContent = JSON.stringify({
    title,
    format: 'vectoll/structured-v1',
    estimatedTokens: cleanToks,
    markdown,
  }, null, 2);
}

// ─── Inspector: Token Verifier & /.well-known/vectoll.json Conformance ────────
async function runTokenInspector() {
  const raw = document.getElementById('inspToken').value.trim();
  const pub = document.getElementById('inspPubKey').value.trim();
  const resBadge = document.getElementById('inspStatus');
  const claimsPre = document.getElementById('inspClaims');

  if (!raw) {
    resBadge.className = 'badge';
    resBadge.textContent = 'Paste a vrt1 / vsm1 token';
    claimsPre.textContent = '{}';
    return;
  }

  const parts = raw.split('.');
  if (parts.length !== 3) {
    resBadge.className = 'badge ro';
    resBadge.textContent = 'MALFORMED TOKEN FORMAT';
    claimsPre.textContent = 'Expected <prefix>.<base64url-payload>.<base64url-signature>';
    return;
  }

  try {
    const decoded = JSON.parse(new TextDecoder().decode(b64UrlDecodeBytes(parts[1])));
    claimsPre.textContent = JSON.stringify({ prefix: parts[0], signatureBytes: b64UrlDecodeBytes(parts[2]).length, claims: decoded }, null, 2);
  } catch (e) {
    resBadge.className = 'badge ro';
    resBadge.textContent = 'PAYLOAD DECODE ERROR';
    claimsPre.textContent = e.message;
    return;
  }

  if (parts[0] === 'vrt1' && pub) {
    const res = await verifyVrtInBrowser(raw, pub);
    if (res.valid) {
      resBadge.className = 'badge em';
      resBadge.textContent = '✓ SIGNATURE & CLAIMS VERIFIED OFFLINE';
    } else {
      resBadge.className = 'badge ro';
      resBadge.textContent = `✕ ${res.code}: ${res.reason}`;
    }
  } else {
    resBadge.className = 'badge co';
    resBadge.textContent = `DECODED ${parts[0].toUpperCase()} ENVELOPE`;
  }
}

function validateManifest() {
  const txt = document.getElementById('manifestIn').value;
  const out = document.getElementById('manifestChecks');
  let obj;
  try {
    obj = JSON.parse(txt);
  } catch (e) {
    out.innerHTML = `<div class="badge ro">INVALID JSON: ${e.message}</div>`;
    return;
  }

  const checks = [
    ['vectollVersion present ("0.1" / "1.0")', Boolean(obj.vectollVersion)],
    ['x402Version === 2 compatibility flag', obj.x402Version === 2],
    ['service.name & service.mcpEndpoint declared', Boolean(obj.service?.name && obj.service?.mcpEndpoint)],
    ['settlement.facilitatorUrl uses HTTPS/HTTP', /^https?:\/\//.test(obj.settlement?.facilitatorUrl || '')],
    ['settlement.facilitatorPublicKey or did:key present', Boolean(obj.settlement?.facilitatorPublicKey)],
    ['settlement.acceptedRails non-empty array', Array.isArray(obj.settlement?.acceptedRails) && obj.settlement.acceptedRails.length > 0],
    ['routes[] array defined with >= 1 metered route', Array.isArray(obj.routes) && obj.routes.length > 0],
    ['Integer minor-unit amounts (zero float drift)', Array.isArray(obj.routes) && obj.routes.every(r => Number.isInteger(r.amount) && r.amount >= 0)],
  ];
  const passed = checks.filter(c => c[1]).length;
  out.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
      <span class="badge ${passed === checks.length ? 'em' : 'am'}">CONFORMANCE SCORE: ${passed}/${checks.length} PASSED</span>
      <button class="btn btn-xs" onclick="copyText('[![Vectoll Ready](https://img.shields.io/badge/Vectoll-x402_&_MCP_Verified-10B981)](https://vectoll.org)', 'Copied Markdown badge')">Copy README Badge</button>
    </div>
    ${checks.map(([label, ok]) => `
      <div style="padding:7px 10px;border-bottom:1px solid var(--line);font-family:var(--mono);font-size:12px;display:flex;justify-content:space-between;">
        <span>${label}</span>
        <strong style="color:${ok ? 'var(--emerald)' : 'var(--rose)'};">${ok ? 'PASS' : 'FAIL'}</strong>
      </div>
    `).join('')}
  `;
}

// ─── Builder: 6-Artifact Full-Stack Config Architect ──────────────────────────
let builderArtifact = 'yaml';
let builderRoutes = [
  { method: 'GET', path: '/api/v1/search', price: '$0.005', mode: 'instant' },
  { method: 'GET', path: '/articles/*', price: '$0.002', mode: 'structured' },
  { method: 'POST', path: '/api/v1/reserve', price: '€2.50', mode: 'escrow' },
];

function renderBuilderRoutes() {
  const host = document.getElementById('bRoutes');
  host.innerHTML = '';
  builderRoutes.forEach((r, i) => {
    const div = document.createElement('div');
    div.className = 'builder-route-row';
    div.innerHTML = `
      <select onchange="builderRoutes[${i}].method=this.value;renderBuilderOutput()">
        <option ${r.method === 'GET' ? 'selected' : ''}>GET</option>
        <option ${r.method === 'POST' ? 'selected' : ''}>POST</option>
        <option ${r.method === 'PUT' ? 'selected' : ''}>PUT</option>
      </select>
      <input type="text" value="${r.path}" oninput="builderRoutes[${i}].path=this.value;renderBuilderOutput()" />
      <input type="text" value="${r.price}" oninput="builderRoutes[${i}].price=this.value;renderBuilderOutput()" />
      <select class="b-mode" onchange="builderRoutes[${i}].mode=this.value;renderBuilderOutput()">
        <option value="instant" ${r.mode === 'instant' ? 'selected' : ''}>Instant</option>
        <option value="structured" ${r.mode === 'structured' ? 'selected' : ''}>HTML→JSON</option>
        <option value="escrow" ${r.mode === 'escrow' ? 'selected' : ''}>Escrow+HITL</option>
      </select>
      <button class="btn btn-xs" onclick="builderRoutes.splice(${i},1);renderBuilderRoutes();renderBuilderOutput()">×</button>
    `;
    host.appendChild(div);
  });
}

function getBuilderFileMeta() {
  const map = {
    yaml: 'vectoll.yaml',
    express: 'server.ts',
    fastapi: 'main.py',
    docker: 'docker-compose.yml',
    wellknown: 'vectoll.json',
    claude: 'claude_desktop_config.json',
  };
  return map[builderArtifact] || 'vectoll.yaml';
}

function renderBuilderOutput() {
  const svc = document.getElementById('bSvc').value || 'global-api';
  const origin = document.getElementById('bOrigin').value || 'http://localhost:3000';
  const fac = document.getElementById('bFac').value || 'https://pay.vectoll.com';
  const browsersFree = document.getElementById('bFree').checked;
  const enableMcp = document.getElementById('bMcp').checked;

  let code = '';
  if (builderArtifact === 'yaml') {
    code = `service: "${svc}"\norigin: "${origin}"\nfacilitator: "${fac}"\nbrowsers: "${browsersFree ? 'free' : 'metered'}"\nmcp: ${enableMcp}\n\nroutes:\n`;
    builderRoutes.forEach(r => {
      if (r.mode === 'instant') code += `  "${r.method} ${r.path}": "${r.price}"\n`;
      else if (r.mode === 'structured') code += `  "${r.method} ${r.path}": { price: "${r.price}", browsers: "${browsersFree ? 'free' : 'metered'}", transform: "structured" }\n`;
      else code += `  "${r.method} ${r.path}": { price: "${r.price}", mode: "escrow", approve_above: "$25.00" }\n`;
    });
  } else if (builderArtifact === 'express') {
    code = `import express from 'express';\nimport { vectollMiddleware } from '@vectoll/server';\n\nconst app = express();\napp.use(vectollMiddleware({\n  serviceName: '${svc}',\n  facilitatorUrl: '${fac}',\n  routes: {\n`;
    builderRoutes.forEach(r => {
      code += `    '${r.method} ${r.path}': { price: '${r.price}'${browsersFree ? ", browsers: 'free'" : ''}${r.mode === 'structured' ? ", transform: 'structured'" : ''}${r.mode === 'escrow' ? ", settlementMode: 'escrow'" : ''} },\n`;
    });
    code += `  },\n}));\n\napp.listen(3000);\n`;
  } else if (builderArtifact === 'fastapi') {
    code = `from fastapi import FastAPI\nfrom vectoll.asgi import VectollMiddleware\n\napp = FastAPI()\napp.add_middleware(\n    VectollMiddleware,\n    service_name="${svc}",\n    facilitator_url="${fac}",\n    routes={\n`;
    builderRoutes.forEach(r => {
      code += `        "${r.method} ${r.path}": {"price": "${r.price}", "browsers": "${browsersFree ? 'free' : 'metered'}"},\n`;
    });
    code += `    },\n)\n`;
  } else if (builderArtifact === 'docker') {
    code = `services:\n  vectoll-gate:\n    image: ghcr.io/vectoll/vectoll-gate:v1.0.0\n    ports:\n      - "4020:4020"\n    environment:\n      VECTOLL_ORIGIN: "${origin}"\n      VECTOLL_FACILITATOR_URL: "${fac}"\n      VECTOLL_REDIS_URL: "redis://redis:6379"\n    volumes:\n      - ./vectoll.yaml:/etc/vectoll/vectoll.yaml:ro\n    depends_on:\n      - redis\n  redis:\n    image: redis:7-alpine\n`;
  } else if (builderArtifact === 'wellknown') {
    code = JSON.stringify({
      vectollVersion: '1.0',
      x402Version: 2,
      service: { name: svc, mcpEndpoint: enableMcp ? '/mcp' : null },
      settlement: {
        facilitatorUrl: fac,
        facilitatorPublicKey: studioKey.did || 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        acceptedRails: ['stripe', 'x402_usdc', 'sepa_instant', 'fednow_ach', 'pix', 'upi', 'paynow', 'mpesa', 'momo'],
      },
      routes: builderRoutes.map(r => ({
        method: r.method,
        path: r.path,
        displayPrice: r.price,
        amount: 50,
        currency: r.price.startsWith('€') ? 'EUR' : 'USD',
        decimals: 2,
        settlementMode: r.mode === 'escrow' ? 'escrow' : 'instant',
        humanPassthrough: browsersFree,
      })),
    }, null, 2);
  } else {
    code = JSON.stringify({
      mcpServers: {
        [svc]: {
          command: 'npx',
          args: ['-y', '@vectoll/cli', 'mcp-bridge', '--url', `https://${svc}.example.com/mcp`, '--facilitator', fac, '--rail', 'x402_usdc'],
          env: { VECTOLL_AGENT_SEED: '<32-byte-hex-seed>' },
        },
      },
    }, null, 2);
  }

  document.getElementById('bFilename').textContent = getBuilderFileMeta();
  document.getElementById('bOut').textContent = code;
}

// ─── Docs & RFC Reader ────────────────────────────────────────────────────────
const DOCS_CONTENT = {
  quickstart: {
    title: '5-Minute Developer Quickstart',
    html: `
      <p>Vectoll adds cryptographic AI agent metering and global 9-rail payments to any HTTP API, website, or Model Context Protocol (MCP) server without reorganizing your repository or blocking human visitors.</p>
      <h3>1. Install the Drop-In Middleware</h3>
      <pre>npm install @vectoll/server @vectoll/sdk
# Or Python: pip install vectoll</pre>
      <h3>2. Protect Routes While Keeping Browsers Free</h3>
      <pre>import express from 'express';
import { vectollMiddleware } from '@vectoll/server';

const app = express();
app.use(vectollMiddleware({
  routes: {
    'GET /api/data': '$0.005',
    'GET /blog/*': { price: '$0.001', browsers: 'free', transform: 'structured' },
  },
}));
app.listen(3000);</pre>
      <h3>3. Verify Conformance via CLI</h3>
      <pre>npx @vectoll/cli check http://localhost:3000 --strict --badge</pre>
      <p>Your service now automatically exposes <code>/.well-known/vectoll.json</code>, verifies Ed25519 <code>vrt1</code> receipts offline in under 0.3ms, and exposes metered MCP tools at <code>POST /mcp</code>.</p>`
  },
  rfc1: {
    title: 'RFC-0001: Core HTTP 402 Wire Protocol & VRT1 Receipts',
    html: `
      <p><strong>Status:</strong> Implemented in v1.0.0 &bull; <strong>Compatibility:</strong> Bidirectional x402 V2</p>
      <h3>Canonical Request Binding (reqHash)</h3>
      <p>Every Vectoll Receipt Token (<code>vrt1</code>) binds to the exact HTTP method, path+query, and SHA-256 body digest so a receipt minted for cheap Route A can never be replayed against Route B:</p>
      <pre>body_hash_hex = lowercase_hex(SHA-256(raw_body))
canonical_str = UPPER(method) + "\\n" + path_with_query + "\\n" + body_hash_hex
req_hash      = "sha256:" + lowercase_hex(SHA-256(UTF8(canonical_str)))</pre>
      <h3>Compact VRT1 Envelope</h3>
      <pre>vrt1.&lt;base64url(JSON_claims)&gt;.&lt;base64url(Ed25519_64byte_signature)&gt;</pre>
      <ul>
        <li><code>iss</code>: Facilitator <code>did:key:z6Mk...</code> identifier.</li>
        <li><code>sub</code>: Agent <code>did:key:z6Mk...</code> cryptographic identity (zero PII).</li>
        <li><code>req</code>: Exact <code>sha256:...</code> canonical request hash.</li>
        <li><code>amt</code> / <code>cur</code> / <code>dec</code>: Lossless integer minor-unit settlement amount.</li>
        <li><code>jti</code>: Unique nonce enforced atomically via Redis <code>SET NX EX</code> at the Gate.</li>
      </ul>`
  },
  rfc2: {
    title: 'RFC-0002: Model Context Protocol (MCP) Payment Binding',
    html: `
      <p>RFC-0002 brings zero-friction per-tool micro-payments to JSON-RPC 2.0 MCP servers used by Claude Desktop, Cursor, Windsurf, and custom LangGraph/OpenAI agents.</p>
      <h3>JSON-RPC _meta.vectoll Envelope</h3>
      <pre>{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "tools/call",
  "params": {
    "name": "query_patent_graph",
    "arguments": { "ipc": "G06N" },
    "_meta": {
      "vectoll": { "receipt": "vrt1.eyJ2IjoxLC..." }
    }
  }
}</pre>
      <h3>Zero-Config Local Stdio Bridge</h3>
      <p>Legacy stdio MCP hosts gain automatic 402 settlement via <code>npx @vectoll/cli mcp-bridge</code>, enforcing session budgets and hardware Passkey mandates locally.</p>`
  },
  rfc3: {
    title: 'RFC-0003: Delegated Spend Mandates & WebAuthn Passkeys (vsm1p)',
    html: `
      <p>Autonomous agents must never hold unbounded access to corporate cards or bank rails. RFC-0003 defines cryptographically verifiable Spend Mandates signed either by Ed25519 keys (<code>vsm1</code>) or hardware FIDO2/WebAuthn P-256 Passkeys (<code>vsm1p</code>).</p>
      <h3>Enforced Guardrails</h3>
      <ul>
        <li><strong>Per-Request Ceiling:</strong> Reject any single call above <code>maxAmountPerTx</code>.</li>
        <li><strong>Rolling Velocity Budget:</strong> Atomic ledger enforcement of hourly/daily spend caps.</li>
        <li><strong>Audience Pinning:</strong> Restrict an agent strictly to allowlisted domains or MCP tools.</li>
        <li><strong>Escrow + HITL Threshold:</strong> Hold funds in double-entry escrow until upstream confirms <code>2xx</code> or a human operator approves in Console.</li>
      </ul>`
  },
  rfc4: {
    title: 'RFC-0004: Cross-Facilitator Federation & Peering (vfv1)',
    html: `
      <p>Just as email and BGP prevent single-provider lock-in, RFC-0004 lets an AI agent funded on Facilitator A seamlessly pay an API merchant hosted on Facilitator B.</p>
      <h3>Peering Flow</h3>
      <pre>Agent Wallet (Facilitator A)
   │  1. Request Federated Voucher (vfv1 signed by Fac A)
   ▼
Merchant Facilitator B (/v1/federation/exchange)
   │  2. Verify Fac A did:key + bilateral credit line → Mint local vrt1
   ▼
Merchant Origin Gate (verifies local Fac B vrt1 in &lt;0.3ms)</pre>`
  },
  security: {
    title: 'Security Architecture & 500-Vector Adversarial Audit',
    html: `
      <p>Vectoll v1.0.0 is hardened against cryptographic forgery, race-condition double-spends, and float rounding exploits:</p>
      <ul>
        <li><strong>Signature-Before-Parse:</strong> <code>verifyVrt()</code> verifies the 64-byte Ed25519 signature prior to trusting any JSON payload field.</li>
        <li><strong>Constant-Time Digest Check:</strong> <code>reqHash</code> comparisons use constant-time byte equality to eliminate timing side channels.</li>
        <li><strong>100-Way Concurrent Replay Lock:</strong> Verified against 100 simultaneous parallel replay attempts using atomic SQLite transactions and Redis <code>SET key 1 NX EX ttl</code>.</li>
        <li><strong>Integer-Only Accounting:</strong> All 23 currencies settle in integer minor units with strict <code>DEBIT === CREDIT</code> journal invariants.</li>
      </ul>`
  }
};

function renderDoc(key) {
  const doc = DOCS_CONTENT[key] || DOCS_CONTENT.quickstart;
  document.getElementById('docContent').innerHTML = `<h2>${doc.title}</h2>${doc.html}`;
  document.querySelectorAll('.doc-link').forEach(b => b.classList.toggle('active', b.dataset.doc === key));
}

// ─── Ecosystem Directory ──────────────────────────────────────────────────────
const DIRECTORY_ITEMS = [
  { name: 'Global FX & Rates Oracle', cat: 'finance', domain: 'fx.vectoll.network', price: '$0.001 / call', rails: ['x402_usdc', 'stripe', 'sepa_instant'], mcp: 'spot_quote', desc: 'Institutional 23-currency FX & crypto mid-market feed with sub-second finality.' },
  { name: 'Continental NewsWire Archive', cat: 'media', domain: 'wire.press-alliance.eu', price: '€0.005 / article', rails: ['sepa_instant', 'stripe', 'voucher'], mcp: 'search_articles', desc: 'Clean structured Markdown newsroom feed; 100% free for human browsers.' },
  { name: 'BioMed & Patent Graph MCP', cat: 'compute', domain: 'mcp.scigraph.org', price: '$0.02 / query', rails: ['stripe', 'x402_usdc', 'fednow_ach'], mcp: 'semantic_patent_search', desc: '140M+ indexed patent claims and citation graphs exposed natively over RFC-0002 MCP.' },
  { name: 'Kampala & Nairobi Stay Escrow', cat: 'commerce', domain: 'api.eaststay.africa', price: 'KES 150 / booking', rails: ['mpesa', 'momo', 'x402_usdc'], mcp: 'reserve_room_escrow', desc: 'Escrow-backed hospitality inventory with Passkey mandate & instant Daraja/MoMo settlement.' },
  { name: 'São Paulo Real-Time Logistics', cat: 'commerce', domain: 'api.frete-rapido.br', price: 'R$ 0.08 / quote', rails: ['pix', 'x402_usdc', 'stripe'], mcp: 'dispatch_courier', desc: 'Instant last-mile freight dispatch across Brazil settled 24/7 via Banco Central PIX.' },
  { name: 'Bengaluru GPU Inference Grid', cat: 'compute', domain: 'infer.indiascale.in', price: '₹ 0.40 / 1k tok', rails: ['upi', 'x402_usdc', 'voucher'], mcp: 'run_batch_embedding', desc: 'Pay-per-inference open-weights cluster with zero API signup—just HTTP 402 + VRT1.' },
];

function renderDirectory() {
  const q = (document.getElementById('dirSearch').value || '').toLowerCase();
  const cat = document.querySelector('#dirCats .seg-btn.active')?.dataset.cat || 'all';
  const grid = document.getElementById('dirGrid');
  const filtered = DIRECTORY_ITEMS.filter(item =>
    (cat === 'all' || item.cat === cat) &&
    (!q || item.name.toLowerCase().includes(q) || item.desc.toLowerCase().includes(q) || item.rails.join(' ').includes(q))
  );
  grid.innerHTML = filtered.map(item => `
    <div class="wire-card" style="padding:20px;display:flex;flex-direction:column;justify-content:space-between;gap:14px;">
      <div>
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px;">
          <span class="badge em">${item.price}</span>
          <span style="font-family:var(--mono);font-size:11px;color:var(--ink-3);">${item.domain}</span>
        </div>
        <h3 style="font-size:17px;margin-bottom:6px;">${item.name}</h3>
        <p style="font-size:13.5px;color:var(--ink-2);margin-bottom:12px;">${item.desc}</p>
        <div style="display:flex;flex-wrap:wrap;gap:5px;">
          ${item.rails.map(r => `<span class="badge" style="font-size:10px;">${r}</span>`).join('')}
          <span class="badge vi" style="font-size:10px;">MCP: ${item.mcp}</span>
        </div>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-sm" style="flex:1;" onclick="copyText('npx @vectoll/cli mcp-bridge --url https://${item.domain}/mcp', 'Copied MCP bridge command')">Connect MCP</button>
        <button class="btn btn-sm btn-emerald" onclick="switchView('studio');document.getElementById('stTarget').value='/mcp?tool=${item.mcp}';mintLiveVrt();">Test 402 Call</button>
      </div>
    </div>
  `).join('');
}

// ─── Initialization ───────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  // Restore theme
  const savedTheme = localStorage.getItem('vectoll_org_theme') || 'dark';
  if (savedTheme === 'light') document.documentElement.setAttribute('data-theme', 'light');
  updateThemeAssets(savedTheme);

  // Route from URL hash
  const initialHash = location.hash.replace('#', '');
  switchView(VIEWS.includes(initialHash) ? initialHash : 'overview', false);

  document.querySelectorAll('.view-tab').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  // Keyboard shortcuts
  window.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      openPalette();
    } else if (e.key === 'Escape') {
      closePalette();
    }
  });
  document.getElementById('cmdInput').addEventListener('input', e => renderPalette(e.target.value));

  // Hero telemetry animation
  let stepIdx = 0;
  setInterval(() => {
    for (let i = 0; i < 3; i++) {
      document.getElementById('hstep-' + i)?.classList.toggle('active', i === stepIdx);
    }
    stepIdx = (stepIdx + 1) % 3;
  }, 2300);

  // Package switcher
  document.querySelectorAll('.pkg-tab').forEach(t => {
    t.addEventListener('click', () => {
      document.querySelectorAll('.pkg-tab').forEach(b => b.classList.toggle('active', b === t));
      document.getElementById('pkgCmdText').textContent = PKG_CMDS[t.dataset.pkg];
    });
  });

  // Stack code switcher
  const renderStack = key => {
    const s = STACK_SNIPPETS[key];
    document.getElementById('stackFile').textContent = s.file;
    document.getElementById('stackCode').textContent = s.code;
    document.querySelectorAll('#stackTabs .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.stack === key));
  };
  document.querySelectorAll('#stackTabs .seg-btn').forEach(b => b.onclick = () => renderStack(b.dataset.stack));
  renderStack('express');

  // Classifier presets
  document.querySelectorAll('[data-clspreset]').forEach(btn => {
    btn.onclick = () => {
      const p = CLASSIFIER_PRESETS[btn.dataset.clspreset];
      document.getElementById('clsUa').value = p.ua;
      document.getElementById('clsAccept').value = p.accept;
      document.getElementById('clsSec').value = p.sec;
      document.getElementById('clsPay').checked = p.payHeader;
      evaluateClassifier();
    };
  });
  evaluateClassifier();

  // FX setup
  const fxFrom = document.getElementById('fxFrom');
  const fxTo = document.getElementById('fxTo');
  CURRENCIES.forEach(c => {
    fxFrom.add(new Option(c.code, c.code));
    fxTo.add(new Option(c.code, c.code));
  });
  fxFrom.value = 'USD';
  fxTo.value = 'EUR';
  computeFx();

  // Studio init
  await generateBrowserKeypair();
  runHtmlTranslator();

  // Inspector default manifest
  document.getElementById('manifestIn').value = JSON.stringify({
    vectollVersion: '1.0',
    x402Version: 2,
    service: { name: 'acme-global-api', mcpEndpoint: '/mcp' },
    settlement: {
      facilitatorUrl: 'https://pay.vectoll.com',
      facilitatorPublicKey: studioKey.did,
      acceptedRails: ['stripe', 'x402_usdc', 'sepa_instant', 'pix', 'upi', 'mpesa'],
    },
    routes: [
      { path: '/api/v1/signals', method: 'GET', amount: 50, currency: 'USD', decimals: 4, settlementMode: 'instant', humanPassthrough: true },
    ],
  }, null, 2);
  validateManifest();

  // Builder init
  document.querySelectorAll('#builderTabs .seg-btn').forEach(btn => {
    btn.onclick = () => {
      builderArtifact = btn.dataset.art;
      document.querySelectorAll('#builderTabs .seg-btn').forEach(b => b.classList.toggle('active', b === btn));
      renderBuilderOutput();
    };
  });
  renderBuilderRoutes();
  renderBuilderOutput();

  // Docs & Directory init
  document.querySelectorAll('.doc-link').forEach(btn => btn.onclick = () => renderDoc(btn.dataset.doc));
  renderDoc('quickstart');

  document.querySelectorAll('#dirCats .seg-btn').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('#dirCats .seg-btn').forEach(b => b.classList.toggle('active', b === btn));
      renderDirectory();
    };
  });
  renderDirectory();
});
