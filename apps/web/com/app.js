// Vectoll.com — Managed Cloud Platform, Live Sandbox Console, WebAuthn Passkey Studio & Treasury Router

function showToast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => el.classList.remove('show'), 2300);
}

async function copyText(text, label = 'Copied to clipboard') {
  try {
    await navigator.clipboard.writeText(text);
    showToast('✓ ' + label);
  } catch {
    showToast('Copy ready');
  }
}

function downloadFile(filename, content, mime = 'text/csv;charset=utf-8') {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast(`Exported ${filename}`);
}

function randHex(n = 12) {
  const arr = new Uint8Array(Math.ceil(n / 2));
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, n);
}

function b64UrlEncodeBytes(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64UrlEncodeStr(str) {
  return b64UrlEncodeBytes(new TextEncoder().encode(str));
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── View Navigation & Theme ──────────────────────────────────────────────────
const VIEWS = ['platform', 'console', 'passkeys', 'treasury', 'pricing'];

function switchView(viewId, updateHash = true) {
  if (!VIEWS.includes(viewId)) viewId = 'platform';
  VIEWS.forEach(v => document.getElementById('view-' + v)?.classList.toggle('active', v === viewId));
  document.querySelectorAll('.view-tab').forEach(b => b.classList.toggle('active', b.dataset.view === viewId));
  if (updateHash) history.replaceState(null, '', '#' + viewId);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', cur === 'light' ? 'light' : '');
  localStorage.setItem('vectoll_com_theme', cur);
  updateThemeAssets(cur);
}

function updateThemeAssets(theme) {
  const btn = document.getElementById('themeBtn');
  if (btn) btn.textContent = theme === 'light' ? '☾ Dark' : '☀ Light';
  const wm = document.getElementById('heroWordmark');
  if (wm) wm.src = theme === 'light' ? '/brand/logo-wordmark-light.svg' : '/brand/logo-wordmark-dark.svg';
}

// ─── Command Palette ──────────────────────────────────────────────────────────
const COMMANDS = [
  { label: 'Platform Overview & CFO ROI Modeler', hint: '#platform', run: () => switchView('platform') },
  { label: 'Open Live Interactive Cloud Console', hint: '#console', run: () => switchView('console') },
  { label: 'Simulate +5 Live AI Agent Settlements', hint: 'Console', run: () => { switchView('console'); simulateAgentBurst(5); } },
  { label: 'Mint Scoped vk_live_* API Key', hint: 'RBAC', run: () => { switchView('console'); mintApiKey(); } },
  { label: 'Open Hardware Passkey Mandate Studio (vsm1p)', hint: '#passkeys', run: () => switchView('passkeys') },
  { label: 'Sign Mandate with WebAuthn / P-256', hint: 'FIDO2', run: () => { switchView('passkeys'); signPasskeyMandate(); } },
  { label: 'Global 9-Rail Treasury & Federation Router', hint: '#treasury', run: () => switchView('treasury') },
  { label: 'Pricing, SLA & Cloud Onboarding', hint: '#pricing', run: () => switchView('pricing') },
  { label: 'Toggle Light / Dark Extruded Theme', hint: 'Theme', run: () => toggleTheme() },
  { label: 'Open Open-Source Protocol Hub (vectoll.org)', hint: 'External', run: () => window.open('https://vectoll.org', '_blank') },
];

function openPalette() {
  document.getElementById('cmdModal').classList.add('open');
  const inp = document.getElementById('cmdInput');
  inp.value = '';
  renderPalette('');
  setTimeout(() => inp.focus(), 30);
}
function closePalette() { document.getElementById('cmdModal').classList.remove('open'); }
function renderPalette(q) {
  const norm = q.trim().toLowerCase();
  const items = COMMANDS.filter(c => !norm || c.label.toLowerCase().includes(norm) || c.hint.toLowerCase().includes(norm));
  const list = document.getElementById('cmdList');
  list.innerHTML = items.map((c, i) => `<button class="palette-item" data-i="${i}"><span>${c.label}</span><span class="badge">${c.hint}</span></button>`).join('');
  list.querySelectorAll('.palette-item').forEach((el, idx) => {
    el.onclick = () => { closePalette(); items[idx].run(); };
  });
}

// ─── View 1: CFO Multi-Segment Revenue & Compute-Offset Modeler ───────────────
const INDUSTRY_PRESETS = {
  api: { reqs: 8000000, price: 0.005 },
  publisher: { reqs: 25000000, price: 0.002 },
  mcp: { reqs: 3500000, price: 0.015 },
  marketplace: { reqs: 500000, price: 0.08 },
};

let lastRoiReportCsv = '';

function updateRoiCalc() {
  const reqs = Number(document.getElementById('roiReqs').value);
  const priceUsd = Number(document.getElementById('roiPrice').value);
  const [code, sym, rateStr] = document.getElementById('roiCur').value.split('|');
  const rate = Number(rateStr);

  document.getElementById('lblRoiReqs').textContent = reqs.toLocaleString('en-US') + ' calls/mo';
  document.getElementById('lblRoiPrice').textContent = '$' + priceUsd.toFixed(4).replace(/0+$/, '').replace(/\.$/, '');

  const gross = reqs * priceUsd * rate;
  const cloudFee = gross * 0.015;
  const netMonthly = gross - cloudFee;
  const netAnnual = netMonthly * 12;
  const fmt = v => sym + Math.round(v).toLocaleString('en-US');

  document.getElementById('roiNetMonthly').textContent = fmt(netMonthly);
  document.getElementById('roiGross').textContent = fmt(gross);
  document.getElementById('roiFee').textContent = '-' + fmt(cloudFee);
  document.getElementById('roiAnnual').textContent = fmt(netAnnual);

  lastRoiReportCsv = `Metric,Currency,Amount\nMonthly AI Agent Requests,COUNT,${reqs}\nUnit Price (USD),USD,${priceUsd}\nMonthly Gross Volume,${code},${Math.round(gross)}\nVectoll Cloud 1.5% Fee,${code},${Math.round(cloudFee)}\nMonthly Net Payout,${code},${Math.round(netMonthly)}\nAnnual Net Payout,${code},${Math.round(netAnnual)}\n`;
}

// ─── View 2: Interactive Live Cloud Sandbox Console ───────────────────────────
let consoleState = {
  revenueUsdCents: 148250, // $1,482.50
  verifiedCount: 296500,
  blockedReplays: 418,
  sparkPoints: [42, 48, 46, 55, 63, 60, 74, 82, 79, 94, 108, 124],
  autoStreamTimer: null,
  hitlQueue: [
    { id: 'hitl_904a', agent: 'Claude-Desktop-MCP', route: 'POST /api/v1/flights/issue', display: '€420.00', cents: 42000, cur: 'EUR', rail: 'sepa_instant', status: 'pending' },
    { id: 'hitl_71bc', agent: 'Devin-Infra-Bot', route: 'POST /api/v1/gpu/reserve-8xh100', display: '$185.00', cents: 18500, cur: 'USD', rail: 'x402_usdc', status: 'pending' },
    { id: 'hitl_38fe', agent: 'SafariStay-Concierge', route: 'POST /api/v1/hotels/book-nairobi', display: 'KES 18,500', cents: 14300, cur: 'KES', rail: 'mpesa', status: 'pending' },
  ],
  ledger: [
    { id: 'jrn_1004', account: 'agent:float:x402_usdc', cur: 'USDC', debit: '0.0250', credit: '0.0000', memo: 'MCP tools/call semantic_search' },
    { id: 'jrn_1004', account: 'merchant:payable:live', cur: 'USDC', debit: '0.0000', credit: '0.0250', memo: 'Instant settlement (vrt_8f21a)' },
    { id: 'jrn_1003', account: 'agent:float:pix', cur: 'BRL', debit: '0.50', credit: '0.00', memo: 'GET /api/v1/logistics/quote' },
    { id: 'jrn_1003', account: 'merchant:payable:live', cur: 'BRL', debit: '0.00', credit: '0.50', memo: 'Instant PIX settlement' },
  ],
  apiKeys: [
    { id: 'key_prod_01', prefix: 'vk_live_98f2...e41a', hash: 'sha256:4a91c0...88b2', scopes: 'gate:verify, ledger:read, escrow:capture', created: 'Active' },
  ],
};

const SAMPLE_EVENTS = [
  { agent: 'Cursor-Agent', rail: 'x402_usdc', cur: 'USDC', disp: '0.0150', usdCents: 2, memo: 'POST /mcp (query_codegraph)' },
  { agent: 'Perplexity-RAG', rail: 'stripe', cur: 'USD', disp: '0.02', usdCents: 2, memo: 'GET /articles/semiconductors (structured)' },
  { agent: 'LangGraph-Fin', rail: 'sepa_instant', cur: 'EUR', disp: '0.05', usdCents: 5, memo: 'GET /api/v1/fx-matrix' },
  { agent: 'Mumbai-Quant', rail: 'upi', cur: 'INR', disp: '2.00', usdCents: 3, memo: 'GET /api/v1/nse-orderbook' },
  { agent: 'SaoPaulo-Bot', rail: 'pix', cur: 'BRL', disp: '0.25', usdCents: 4, memo: 'POST /api/v1/freight-quote' },
  { agent: 'Nairobi-Scout', rail: 'mpesa', cur: 'KES', disp: '5.00', usdCents: 4, memo: 'GET /api/v1/agri-prices' },
];

function renderSparkline() {
  const pts = consoleState.sparkPoints;
  const max = Math.max(...pts, 1);
  const min = Math.min(...pts, 0);
  const w = 360;
  const h = 64;
  const coords = pts.map((v, i) => {
    const x = Math.round((i / (pts.length - 1)) * w);
    const y = Math.round(h - 8 - ((v - min) / Math.max(1, max - min)) * (h - 16));
    return `${x},${y}`;
  }).join(' ');
  document.getElementById('conSparkSvg').innerHTML = `
    <polyline fill="none" stroke="#10B981" stroke-width="2.5" points="${coords}" />
  `;
}

function renderConsole() {
  const pendingCount = consoleState.hitlQueue.filter(h => h.status === 'pending').length;
  document.getElementById('kpiRev').textContent = '$' + (consoleState.revenueUsdCents / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  document.getElementById('kpiCalls').textContent = consoleState.verifiedCount.toLocaleString('en-US');
  document.getElementById('kpiBlocked').textContent = consoleState.blockedReplays.toLocaleString('en-US');
  document.getElementById('kpiEscrow').textContent = String(pendingCount);

  renderSparkline();

  // HITL Table
  document.getElementById('hitlBody').innerHTML = consoleState.hitlQueue.map((h, i) => `
    <tr>
      <td><code>${h.id}</code></td>
      <td>${h.agent}<div style="color:var(--ink-3);font-size:10.5px;">${h.route}</div></td>
      <td><strong>${h.display}</strong> <span class="badge" style="font-size:10px;">${h.rail}</span></td>
      <td><span class="badge ${h.status === 'pending' ? 'am' : h.status === 'captured' ? 'em' : 'ro'}">${h.status.toUpperCase()}</span></td>
      <td>
        ${h.status === 'pending'
          ? `<button class="btn btn-xs btn-emerald" onclick="resolveHitl(${i}, 'captured')">Approve</button>
             <button class="btn btn-xs btn-rose" onclick="resolveHitl(${i}, 'refunded')">Refund</button>`
          : `<span style="color:var(--ink-3);">Settled</span>`}
      </td>
    </tr>
  `).join('');

  // Ledger Table
  document.getElementById('conLedgerBody').innerHTML = consoleState.ledger.slice(0, 10).map(l => `
    <tr>
      <td><code>${l.id}</code></td>
      <td>${l.account}</td>
      <td>${l.cur}</td>
      <td style="color:${l.debit !== '0.00' && l.debit !== '0.0000' ? 'var(--emerald-ink)' : 'var(--ink-3)'};">${l.debit}</td>
      <td style="color:${l.credit !== '0.00' && l.credit !== '0.0000' ? 'var(--cobalt-ink)' : 'var(--ink-3)'};">${l.credit}</td>
      <td>${l.memo}</td>
    </tr>
  `).join('');

  // API Keys
  document.getElementById('apiKeysBody').innerHTML = consoleState.apiKeys.map((k, idx) => `
    <tr>
      <td><code>${k.prefix}</code></td>
      <td><code>${k.hash}</code></td>
      <td>${k.scopes}</td>
      <td><span class="badge ${k.created === 'Revoked' ? 'ro' : 'em'}">${k.created}</span></td>
      <td>${k.created !== 'Revoked' ? `<button class="btn btn-xs btn-rose" onclick="consoleState.apiKeys[${idx}].created='Revoked';renderConsole();showToast('API Key revoked');">Revoke</button>` : '—'}</td>
    </tr>
  `).join('');
}

function simulateAgentBurst(count = 5) {
  for (let i = 0; i < count; i++) {
    const ev = SAMPLE_EVENTS[Math.floor(Math.random() * SAMPLE_EVENTS.length)];
    const jid = 'jrn_' + (1005 + consoleState.ledger.length);
    consoleState.revenueUsdCents += ev.usdCents * 10;
    consoleState.verifiedCount += 12;
    if (Math.random() > 0.65) consoleState.blockedReplays += 1;
    consoleState.ledger.unshift(
      { id: jid, account: 'merchant:payable:live', cur: ev.cur, debit: '0.00', credit: ev.disp, memo: `${ev.agent} → ${ev.memo}` },
      { id: jid, account: `agent:float:${ev.rail}`, cur: ev.cur, debit: ev.disp, credit: '0.00', memo: `VRT1 verified (${ev.rail})` }
    );
  }
  const last = consoleState.sparkPoints[consoleState.sparkPoints.length - 1];
  consoleState.sparkPoints.push(last + 6 + Math.floor(Math.random() * 14));
  if (consoleState.sparkPoints.length > 16) consoleState.sparkPoints.shift();
  renderConsole();
}

function toggleAutoStream() {
  const btn = document.getElementById('streamBtn');
  if (consoleState.autoStreamTimer) {
    clearInterval(consoleState.autoStreamTimer);
    consoleState.autoStreamTimer = null;
    btn.textContent = '▶ Start Live Stream';
    btn.classList.remove('btn-emerald');
  } else {
    simulateAgentBurst(2);
    consoleState.autoStreamTimer = setInterval(() => simulateAgentBurst(1), 1500);
    btn.textContent = '⏸ Streaming Live...';
    btn.classList.add('btn-emerald');
  }
}

function resolveHitl(idx, action) {
  const item = consoleState.hitlQueue[idx];
  item.status = action;
  const jid = 'jrn_esc_' + randHex(4);
  if (action === 'captured') {
    consoleState.revenueUsdCents += item.cents;
    consoleState.ledger.unshift(
      { id: jid, account: 'merchant:payable:live', cur: item.cur, debit: '0.00', credit: item.display, memo: `HITL Approved ${item.id}` },
      { id: jid, account: 'escrow:hold:liability', cur: item.cur, debit: item.display, credit: '0.00', memo: `Release escrow ${item.id}` }
    );
    showToast(`✓ Approved & captured ${item.display}`);
  } else {
    consoleState.ledger.unshift(
      { id: jid, account: `agent:float:${item.rail}`, cur: item.cur, debit: '0.00', credit: item.display, memo: `HITL Refunded ${item.id}` },
      { id: jid, account: 'escrow:hold:liability', cur: item.cur, debit: item.display, credit: '0.00', memo: `Void escrow ${item.id}` }
    );
    showToast(`Refunded ${item.display} back to agent wallet`);
  }
  renderConsole();
}

async function mintApiKey() {
  const scopeSel = document.getElementById('newKeyScope').value;
  const rawSecret = `vk_live_${randHex(24)}`;
  const hash = 'sha256:' + (await sha256Hex(rawSecret)).slice(0, 14);
  consoleState.apiKeys.unshift({
    id: 'key_' + randHex(4),
    prefix: rawSecret.slice(0, 12) + '...' + rawSecret.slice(-4),
    hash,
    scopes: scopeSel,
    created: 'Active',
  });
  document.getElementById('mintedKeyBanner').style.display = 'flex';
  document.getElementById('mintedKeyVal').textContent = rawSecret;
  renderConsole();
  showToast('Minted scoped vk_live_* API key');
}

function exportLedgerCsv() {
  const rows = ['journal_id,account,currency,debit,credit,memo'];
  consoleState.ledger.forEach(l => rows.push(`${l.id},${l.account},${l.cur},${l.debit},${l.credit},"${l.memo}"`));
  downloadFile('vectoll-double-entry-ledger.csv', rows.join('\n'));
}

// ─── View 3: Hardware WebAuthn Passkey Mandate Studio (vsm1p) ─────────────────
async function signPasskeyMandate(useHardwareWebAuthn = false) {
  const maxTx = document.getElementById('pkMaxTx').value;
  const daily = document.getElementById('pkDaily').value;
  const hitl = document.getElementById('pkHitl').value;
  const domains = document.getElementById('pkDomains').value.split(',').map(s => s.trim()).filter(Boolean);
  const rail = document.getElementById('pkRail').value;

  const now = Math.floor(Date.now() / 1000);
  const claims = {
    v: 1,
    typ: 'vsm1p',
    alg: 'ES256-WebAuthn',
    jti: 'vsm_' + randHex(10),
    sub: 'did:key:z6MkAgent' + randHex(14),
    maxPerTx: maxTx,
    dailyCap: daily,
    hitlAbove: hitl,
    allowedDomains: domains,
    preferredRail: rail,
    iat: now,
    exp: now + 86400 * 30,
  };

  let authenticatorMode = 'WebCrypto P-256 (ES256)';
  let sigB64 = '';

  if (useHardwareWebAuthn && window.PublicKeyCredential && navigator.credentials?.create) {
    try {
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { name: 'Vectoll Cloud Mandate Vault' },
          user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'treasury@vectoll.com', displayName: 'Vectoll Operator' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          timeout: 25000,
          attestation: 'none',
        },
      });
      if (cred) {
        authenticatorMode = 'Hardware FIDO2 / WebAuthn Passkey';
        sigB64 = b64UrlEncodeBytes(new Uint8Array(cred.rawId));
      }
    } catch {
      authenticatorMode = 'WebCrypto P-256 Fallback (Passkey Prompt Cancelled/Sandboxed)';
    }
  }

  if (!sigB64) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const payloadB64 = b64UrlEncodeStr(JSON.stringify(claims));
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, new TextEncoder().encode(`vsm1p.${payloadB64}`));
    sigB64 = b64UrlEncodeBytes(new Uint8Array(sig));
  }

  const token = `vsm1p.${b64UrlEncodeStr(JSON.stringify(claims))}.${sigB64}`;
  document.getElementById('pkAuthBadge').textContent = `✓ Signed via ${authenticatorMode}`;
  document.getElementById('pkTokenOut').textContent = token;
  document.getElementById('pkClaimsOut').textContent = JSON.stringify(claims, null, 2);
}

// ─── View 4: Global 9-Rail Treasury Router & Prometheus / Webhook Lab ─────────
function runTreasuryRoute() {
  const [srcRail, srcCur, srcRegion, srcRate] = document.getElementById('trSrc').value.split('|');
  const [dstRail, dstCur, dstRate] = document.getElementById('trDst').value.split('|');
  const usdVol = Number(document.getElementById('trAmt').value) || 1000;

  const srcAmt = (usdVol * Number(srcRate)).toLocaleString('en-US', { maximumFractionDigits: 2 });
  const netUsd = usdVol * 0.985;
  const dstAmt = (netUsd * Number(dstRate)).toLocaleString('en-US', { maximumFractionDigits: 2 });
  const vfv = `vfv1.${b64UrlEncodeStr(JSON.stringify({ iss: 'did:key:z6MkFacOrigin', aud: 'did:key:z6MkFacDest', srcRail, dstRail, netMinor: Math.round(netUsd * 100), cur: dstCur }))}.${randHex(32)}`;

  document.getElementById('trSummary').innerHTML = `
    <div class="grid-3" style="gap:12px;margin-bottom:14px;">
      <div class="wire-flat" style="padding:12px;">
        <div style="font-size:10.5px;color:var(--ink-3);font-family:var(--mono);">1. AGENT INGRESS (${srcRegion})</div>
        <div style="font-size:18px;font-weight:800;margin-top:4px;font-family:var(--mono);">${srcAmt} ${srcCur}</div>
        <div style="font-size:12px;color:var(--emerald);">${srcRail}</div>
      </div>
      <div class="wire-flat" style="padding:12px;">
        <div style="font-size:10.5px;color:var(--ink-3);font-family:var(--mono);">2. INTEGER FX + CLEARING</div>
        <div style="font-size:18px;font-weight:800;margin-top:4px;font-family:var(--mono);">$${netUsd.toFixed(2)} eq.</div>
        <div style="font-size:12px;color:var(--cobalt-ink);">1.5% Managed Treasury</div>
      </div>
      <div class="wire-flat" style="padding:12px;">
        <div style="font-size:10.5px;color:var(--ink-3);font-family:var(--mono);">3. MERCHANT PAYOUT SWEEP</div>
        <div style="font-size:18px;font-weight:800;margin-top:4px;font-family:var(--mono);">${dstAmt} ${dstCur}</div>
        <div style="font-size:12px;color:var(--violet-ink);">${dstRail}</div>
      </div>
    </div>
  `;
  document.getElementById('trPeeringOut').textContent = vfv;
}

async function fireWebhookTest(eventType) {
  const payload = JSON.stringify({
    id: 'evt_' + randHex(10),
    type: eventType,
    created: new Date().toISOString(),
    data: {
      merchantId: 'mrc_acme_global',
      receiptId: 'vrt_' + randHex(8),
      amountMinor: 2500,
      currency: 'EUR',
      rail: 'sepa_instant',
      ledgerBalanced: true,
    },
  }, null, 2);
  const sig = await sha256Hex('whsec_vectoll_live:' + payload);
  document.getElementById('whOut').textContent =
`POST https://api.yourcompany.com/webhooks/vectoll HTTP/1.1
Content-Type: application/json
X-Vectoll-Signature: t=${Math.floor(Date.now()/1000)},v1=${sig}

${payload}`;
  showToast(`Dispatched ${eventType} webhook`);
}

// ─── Initialization ───────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  const savedTheme = localStorage.getItem('vectoll_com_theme') || 'dark';
  if (savedTheme === 'light') document.documentElement.setAttribute('data-theme', 'light');
  updateThemeAssets(savedTheme);

  const initialHash = location.hash.replace('#', '');
  switchView(VIEWS.includes(initialHash) ? initialHash : 'platform', false);

  document.querySelectorAll('.view-tab').forEach(b => b.onclick = () => switchView(b.dataset.view));

  window.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      openPalette();
    } else if (e.key === 'Escape') {
      closePalette();
    }
  });
  document.getElementById('cmdInput').addEventListener('input', e => renderPalette(e.target.value));

  // Industry presets
  document.querySelectorAll('[data-ind]').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('[data-ind]').forEach(b => b.classList.toggle('active', b === btn));
      const p = INDUSTRY_PRESETS[btn.dataset.ind];
      document.getElementById('roiReqs').value = p.reqs;
      document.getElementById('roiPrice').value = p.price;
      updateRoiCalc();
    };
  });
  updateRoiCalc();

  renderConsole();
  signPasskeyMandate(false);
  runTreasuryRoute();
  fireWebhookTest('escrow.captured');
});
