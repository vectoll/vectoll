import http from 'node:http';
import {
  computeRequestHash,
  createSpendMandate,
  decodePaymentHeader,
  generateKeyPair,
  getCurrencyDecimals,
  signAgentHttpHeaders,
  signClearingIntent,
  type PaymentChallenge,
} from '@vectoll/core';
import { VectollAgentClient } from '@vectoll/sdk';

export interface ConsoleServerOptions {
  facilitatorUrl: string;
  gateUrl?: string;
}

interface ManifestRoute {
  path: string;
  method: string;
  amount: number;
  currency: string;
  decimals: number;
  settlementMode: 'instant' | 'escrow';
  requireMandate: boolean;
  hitlThreshold: number | null;
  mcpTool: { name: string; description: string } | null;
}

export function renderConsoleHtml(opts: ConsoleServerOptions): string {
  const facUrl = opts.facilitatorUrl.replace(/\/$/, '');
  const gateUrl = (opts.gateUrl ?? 'http://127.0.0.1:4020').replace(/\/$/, '');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Vectoll Console — Global Agentic Metering, Multi-Rail Settlement & Guardrails</title>
  <style>
    :root {
      --bg: #070b14;
      --panel: #101726;
      --panel-alt: #0c1220;
      --border: #1e293b;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #10b981;
      --sky: #38bdf8;
      --violet: #a78bfa;
      --amber: #f59e0b;
      --danger: #ef4444;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --sans: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font-family: var(--sans); line-height: 1.5; }
    header {
      border-bottom: 1px solid var(--border);
      padding: 15px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #0a101d;
      flex-wrap: wrap;
      gap: 12px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .mark {
      width: 34px; height: 34px;
      background: var(--text); color: var(--bg);
      font-family: var(--mono); font-weight: 900; font-size: 19px;
      display: grid; place-items: center;
      clip-path: polygon(12% 0, 88% 0, 100% 18%, 50% 100%, 0 18%);
    }
    .badge {
      font-family: var(--mono); font-size: 11.5px;
      padding: 4px 10px; border-radius: 4px;
      background: rgba(16,185,129,0.14); color: var(--accent);
      border: 1px solid rgba(16,185,129,0.38);
    }
    main { max-width: 1400px; margin: 0 auto; padding: 22px 28px 48px; display: grid; gap: 20px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 15px; }
    .two-col { display: grid; grid-template-columns: 1.35fr 1fr; gap: 18px; }
    @media (max-width: 980px) { .two-col { grid-template-columns: 1fr; } }
    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 18px 20px; }
    .card h3 { margin: 0 0 6px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
    .kpi-val { font-family: var(--mono); font-size: 24px; font-weight: 700; }
    .kpi-sub { font-size: 12px; color: var(--muted); margin-top: 5px; font-family: var(--mono); word-break: break-all; }
    h2 { margin: 0 0 12px; font-size: 14.5px; display: flex; justify-content: space-between; align-items: center; gap: 10px; }
    table { width: 100%; border-collapse: collapse; font-size: 12.5px; font-family: var(--mono); }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; font-size: 10.5px; text-transform: uppercase; }
    select, input {
      background: var(--panel-alt); color: var(--text); border: 1px solid var(--border);
      border-radius: 5px; padding: 7px 10px; font-family: var(--mono); font-size: 12px;
    }
    button, .btn {
      font-family: var(--mono); font-size: 12px; cursor: pointer;
      padding: 7px 12px; border-radius: 5px; border: 1px solid var(--border);
      background: #1e293b; color: var(--text); text-decoration: none;
      transition: opacity 0.15s;
    }
    button:hover, .btn:hover { opacity: 0.9; }
    button.primary { background: var(--accent); border-color: var(--accent); color: #04130d; font-weight: 700; }
    button.approve { background: rgba(16,185,129,0.18); border-color: var(--accent); color: var(--accent); }
    button.reject { background: rgba(239,68,68,0.18); border-color: var(--danger); color: var(--danger); }
    button.sky { background: rgba(56,189,248,0.16); border-color: var(--sky); color: var(--sky); }
    .rails { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    .rail-pill { font-family: var(--mono); font-size: 11px; padding: 2px 7px; border: 1px solid var(--border); border-radius: 4px; color: var(--muted); }
    .controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 12px; }
    pre {
      margin: 0; background: #050811; border: 1px solid var(--border);
      border-radius: 6px; padding: 12px; font-family: var(--mono); font-size: 12px;
      color: #a7f3d0; max-height: 220px; overflow: auto;
    }
    a.nav-link { color: var(--sky); font-family: var(--mono); font-size: 12px; text-decoration: none; }
    a.nav-link:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="mark">V</div>
      <div>
        <div style="font-weight:700; letter-spacing:0.04em;">VECTOLL GLOBAL CONSOLE</div>
        <div style="display:flex; gap:14px; flex-wrap:wrap; margin-top:2px;">
          <a class="nav-link" href="${gateUrl}" target="_blank">Origin Portal (:4020)</a>
          <a class="nav-link" href="${gateUrl}/.well-known/vectoll.json" target="_blank">/.well-known/vectoll.json</a>
          <a class="nav-link" href="${gateUrl}/mcp" target="_blank">MCP Inspector (:4020/mcp)</a>
          <a class="nav-link" href="${facUrl}" target="_blank">Facilitator Explorer (:4021)</a>
        </div>
      </div>
    </div>
    <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
      <span id="integrity-badge" class="badge">LEDGER: VERIFYING...</span>
      <a class="btn" href="${facUrl}/v1/ledger/export?format=csv" target="_blank">Export CSV</a>
      <a class="btn" href="${facUrl}/v1/ledger/export?format=json" target="_blank">Export JSON</a>
      <button onclick="refreshTelemetry()">Refresh</button>
    </div>
  </header>

  <main>
    <section class="kpi-grid">
      <div class="card">
        <h3>Facilitator Identity (Ed25519)</h3>
        <div id="kpi-kid" class="kpi-val">—</div>
        <div id="kpi-did" class="kpi-sub">—</div>
      </div>
      <div class="card">
        <h3>Pending HITL Guardrails</h3>
        <div id="kpi-hitl" class="kpi-val">0</div>
        <div class="kpi-sub">High-value global actions paused for approval</div>
      </div>
      <div class="card">
        <h3>Merchant Payables</h3>
        <div id="kpi-payables" class="kpi-val">0</div>
        <div id="kpi-payables-sub" class="kpi-sub">Ready for instant multi-rail payout</div>
      </div>
      <div class="card">
        <h3>Global Rails & FX Assets</h3>
        <div id="kpi-rails-count" class="kpi-val">0</div>
        <div id="kpi-rails" class="rails"></div>
      </div>
    </section>

    <section class="two-col">
      <div class="card">
        <h2>
          <span>Interactive Global Agent & MCP Simulator</span>
          <span style="font-size:11.5px; color:var(--muted); font-family:var(--mono);">Real Ed25519 + x402 + SQLite Clearing</span>
        </h2>
        <div class="controls">
          <select id="sim-preset">
            <option value="x402_usdc:USDC">x402 Stablecoin (USDC — Global)</option>
            <option value="stripe:USD">Stripe Agentic Token (USD — Global)</option>
            <option value="sepa_instant:EUR">SEPA Instant (EUR — Europe)</option>
            <option value="sepa_instant:GBP">Faster Payments (GBP — UK)</option>
            <option value="ach_fednow:USD">FedNow / Treasury ACH (USD — US)</option>
            <option value="pix_upi:BRL">PIX Instant (BRL — Brazil)</option>
            <option value="pix_upi:INR">UPI Instant (INR — India)</option>
            <option value="pix_upi:SGD">PayNow (SGD — Singapore)</option>
            <option value="pix_upi:JPY">Instant Bank (JPY — Japan)</option>
            <option value="mpesa:KES">M-Pesa (KES — Kenya)</option>
            <option value="momo:GHS">MTN MoMo (GHS — Ghana)</option>
            <option value="voucher:USD">Enterprise Voucher (USD — B2B)</option>
          </select>
          <select id="sim-scenario">
            <option value="instant">1. Instant HTTP 402 API Call (&lt;15ms)</option>
            <option value="mcp">2. Metered MCP Tool Call (/mcp)</option>
            <option value="hitl_escrow">3. High-Value Escrow + HITL Guardrail</option>
          </select>
          <button class="primary" onclick="runPlayground()">Run Live Agent Flow</button>
        </div>
        <pre id="sim-output">// Click "Run Live Agent Flow" to execute a live cryptographic HTTP 402 or MCP transaction across any global payment rail.</pre>
      </div>

      <div class="card">
        <h2>
          <span>Global Integer FX Quoting Engine</span>
          <span style="font-size:11.5px; color:var(--muted); font-family:var(--mono);">Zero Float Rounding</span>
        </h2>
        <div class="controls">
          <input id="fx-amount" type="number" value="10000" min="1" style="width:115px" title="Target minor units" />
          <select id="fx-target">
            <option value="USD">Target: USD (micro)</option>
            <option value="EUR">Target: EUR (micro)</option>
            <option value="GBP">Target: GBP (micro)</option>
            <option value="BRL">Target: BRL (cents)</option>
            <option value="INR">Target: INR (paise)</option>
            <option value="JPY">Target: JPY (yen)</option>
            <option value="KES">Target: KES (cents)</option>
          </select>
          <select id="fx-source">
            <option value="EUR">Pay In: EUR</option>
            <option value="USDC">Pay In: USDC</option>
            <option value="USD">Pay In: USD</option>
            <option value="GBP">Pay In: GBP</option>
            <option value="JPY">Pay In: JPY</option>
            <option value="BRL">Pay In: BRL</option>
            <option value="INR">Pay In: INR</option>
            <option value="SGD">Pay In: SGD</option>
            <option value="KES">Pay In: KES</option>
          </select>
          <button class="sky" onclick="runFxQuote()">Quote FX</button>
        </div>
        <pre id="fx-output">// Quotes exact source minor units with ceiling solvency protection across 23 global currencies.</pre>
      </div>
    </section>

    <section class="card">
      <h2>
        <span>Human-in-the-Loop (HITL) Approval Queue</span>
        <span style="font-size:12px; color:var(--muted); font-family:var(--mono);">Slack / WhatsApp / Console One-Tap Guardrail</span>
      </h2>
      <table>
        <thead>
          <tr><th>Approval ID</th><th>Service & Route</th><th>Amount</th><th>Rail</th><th>Status</th><th>Action</th></tr>
        </thead>
        <tbody id="hitl-tbody"><tr><td colspan="6">Loading...</td></tr></tbody>
      </table>
    </section>

    <section class="card">
      <h2>
        <span>Escrow Contracts (Non-Atomic High-Value Commerce)</span>
        <span style="font-size:12px; color:var(--muted); font-family:var(--mono);">AUTHORIZED → SETTLED / REFUNDED</span>
      </h2>
      <table>
        <thead>
          <tr><th>Escrow ID</th><th>Service</th><th>Agent DID</th><th>Locked Amount</th><th>Rail</th><th>Status</th><th>Action</th></tr>
        </thead>
        <tbody id="escrow-tbody"><tr><td colspan="7">Loading...</td></tr></tbody>
      </table>
    </section>

    <section class="card">
      <h2>
        <span>Double-Entry Immutable Audit Ledger</span>
        <span style="font-size:12px; color:var(--muted); font-family:var(--mono);">Integer Minor Units (sum(debit) === sum(credit))</span>
      </h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Tx Kind</th><th>Account Code</th><th>Currency</th><th>Debit</th><th>Credit</th><th>Description</th></tr>
        </thead>
        <tbody id="ledger-tbody"><tr><td colspan="7">Loading...</td></tr></tbody>
      </table>
    </section>
  </main>

  <script>
    const FAC_URL = ${JSON.stringify(facUrl)};

    function formatUnits(amt, cur, dec) {
      if (dec === 0) return Number(amt).toLocaleString() + ' ' + cur;
      const val = Number(amt) / Math.pow(10, dec);
      return val.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: dec > 4 ? 6 : dec }) + ' ' + cur;
    }

    async function runPlayground() {
      const outEl = document.getElementById('sim-output');
      outEl.textContent = 'Running cryptographic HTTP 402 / MCP negotiation...';
      const [rail, currency] = document.getElementById('sim-preset').value.split(':');
      const scenario = document.getElementById('sim-scenario').value;
      const res = await fetch('/api/playground/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rail, currency, scenario })
      });
      const data = await res.json();
      outEl.textContent = JSON.stringify(data, null, 2);
      await refreshTelemetry();
    }

    async function runFxQuote() {
      const targetAmount = document.getElementById('fx-amount').value;
      const targetCurrency = document.getElementById('fx-target').value;
      const sourceCurrency = document.getElementById('fx-source').value;
      const res = await fetch(FAC_URL + '/v1/fx/quote?targetAmount=' + encodeURIComponent(targetAmount) +
        '&targetCurrency=' + encodeURIComponent(targetCurrency) +
        '&sourceCurrency=' + encodeURIComponent(sourceCurrency));
      const q = await res.json();
      document.getElementById('fx-output').textContent = JSON.stringify({
        ...q,
        formattedTarget: formatUnits(q.targetAmount, q.targetCurrency, q.targetDecimals),
        formattedSource: formatUnits(q.sourceAmount, q.sourceCurrency, q.sourceDecimals)
      }, null, 2);
    }

    async function decideHitl(id, decision) {
      const res = await fetch('/api/playground/hitl-decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approvalId: id, decision })
      });
      const out = await res.json();
      document.getElementById('sim-output').textContent = JSON.stringify(out, null, 2);
      await refreshTelemetry();
    }

    async function settleEscrow(escrowId, action) {
      const url = FAC_URL + '/v1/escrow/' + encodeURIComponent(escrowId) + '/' + action;
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fulfillmentRef: 'CONF-' + Date.now(), reason: 'operator_refund' })
      });
      document.getElementById('sim-output').textContent = JSON.stringify(await res.json(), null, 2);
      await refreshTelemetry();
    }

    async function refreshTelemetry() {
      try {
        const res = await fetch(FAC_URL + '/v1/telemetry/summary');
        const data = await res.json();
        document.getElementById('kpi-kid').textContent = data.facilitatorKid;
        document.getElementById('kpi-did').textContent = data.facilitatorDid;
        document.getElementById('kpi-hitl').textContent = String(data.hitlPendingCount);

        const badge = document.getElementById('integrity-badge');
        badge.textContent = data.ledgerIntegrity?.balanced
          ? 'LEDGER: BALANCED (DEBIT == CREDIT)'
          : 'LEDGER: IMBALANCE ALERT';

        const payables = data.merchantPayables || [];
        document.getElementById('kpi-payables').textContent = payables.length
          ? payables.map(p => formatUnits(p.balance, p.currency, p.decimals)).join(' | ')
          : '0.00 USD';

        const rails = data.supportedRails || [];
        document.getElementById('kpi-rails-count').textContent =
          rails.length + ' Rails · ' + (data.fxCurrencies?.length || 0) + ' Assets';
        document.getElementById('kpi-rails').innerHTML = rails
          .map(r => '<span class="rail-pill" title="' + r.displayName + '">' + r.railId + '</span>')
          .join('');

        const hitlRows = (data.hitlApprovals || []).map(h => {
          const actions = h.status === 'PENDING_HITL'
            ? '<button class="approve" onclick="decideHitl(\\'' + h.approvalId + '\\', \\'approve\\')">Approve &amp; Complete</button> ' +
              '<button class="reject" onclick="decideHitl(\\'' + h.approvalId + '\\', \\'reject\\')">Reject</button>'
            : '—';
          return '<tr>' +
            '<td>' + h.approvalId + '</td>' +
            '<td>' + h.service + ' ' + h.method + ' ' + h.resource + '</td>' +
            '<td>' + formatUnits(h.amount, h.currency, h.decimals) + '</td>' +
            '<td>' + h.rail + '</td>' +
            '<td>' + h.status + '</td>' +
            '<td>' + actions + '</td>' +
            '</tr>';
        });
        document.getElementById('hitl-tbody').innerHTML = hitlRows.length
          ? hitlRows.join('')
          : '<tr><td colspan="6" style="color:var(--muted)">No HITL requests yet — select "3. High-Value Escrow + HITL Guardrail" above to test!</td></tr>';

        const escrowRows = (data.escrows || []).map(e => {
          const act = e.status === 'AUTHORIZED'
            ? '<button class="approve" onclick="settleEscrow(\\'' + e.escrowId + '\\', \\'fulfill\\')">Fulfill &amp; Release</button> ' +
              '<button class="reject" onclick="settleEscrow(\\'' + e.escrowId + '\\', \\'refund\\')">Refund Agent</button>'
            : (e.fulfillmentRef || '—');
          return '<tr>' +
            '<td>' + e.escrowId + '</td>' +
            '<td>' + e.service + '</td>' +
            '<td>' + e.agentId.slice(0, 24) + '…</td>' +
            '<td>' + e.amount + ' ' + e.currency + '</td>' +
            '<td>' + e.rail + '</td>' +
            '<td>' + e.status + '</td>' +
            '<td>' + act + '</td>' +
            '</tr>';
        });
        document.getElementById('escrow-tbody').innerHTML = escrowRows.length
          ? escrowRows.join('')
          : '<tr><td colspan="7" style="color:var(--muted)">No escrow locks yet.</td></tr>';

        const entries = (data.recentEntries || []).map(e =>
          '<tr>' +
          '<td>' + e.id + '</td>' +
          '<td>' + e.txKind + '</td>' +
          '<td>' + e.accountCode + '</td>' +
          '<td>' + e.currency + '</td>' +
          '<td>' + formatUnits(e.debit, e.currency, e.decimals) + '</td>' +
          '<td>' + formatUnits(e.credit, e.currency, e.decimals) + '</td>' +
          '<td>' + e.description + '</td>' +
          '</tr>'
        );
        document.getElementById('ledger-tbody').innerHTML = entries.length
          ? entries.join('')
          : '<tr><td colspan="7" style="color:var(--muted)">No journal entries yet — click "Run Live Agent Flow" above!</td></tr>';
      } catch (err) {
        document.getElementById('integrity-badge').textContent = 'FACILITATOR OFFLINE';
      }
    }

    refreshTelemetry();
    runFxQuote();
    setInterval(refreshTelemetry, 4000);
  </script>
</body>
</html>`;
}

export function createConsoleServer(opts: ConsoleServerOptions): http.Server {
  const facUrl = opts.facilitatorUrl.replace(/\/$/, '');
  const gateUrl = (opts.gateUrl ?? 'http://127.0.0.1:4020').replace(/\/$/, '');
  const html = renderConsoleHtml(opts);

  // Store pending HITL requests initiated by the Console Playground so clicking "Approve & Complete"
  // automatically replays the minted VRT against Gate to complete the full end-to-end Escrow cycle!
  const pendingGateCalls = new Map<
    string,
    { url: string; method: string; bodyStr: string; agentHeaders: Record<string, string> }
  >();

  return http.createServer(async (req, res) => {
    try {
      if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', service: 'vectoll-console' }));
        return;
      }

      if (req.method === 'POST' && req.url === '/api/playground/run') {
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
        const input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as {
          rail?: string;
          currency?: string;
          scenario?: 'instant' | 'mcp' | 'hitl_escrow';
        };
        const rail = input.rail ?? 'x402_usdc';
        const walletCurrency = (input.currency ?? 'USDC').toUpperCase();
        const scenario = input.scenario ?? 'instant';
        const walletDec = getCurrencyDecimals(walletCurrency);

        // Fetch Gate discovery manifest to dynamically discover configured routes
        const discRes = await fetch(`${gateUrl}/.well-known/vectoll.json`);
        const manifest = (await discRes.json()) as {
          service: { name: string };
          routes: ManifestRoute[];
        };

        const principal = generateKeyPair();
        const agent = generateKeyPair();
        // Generous funding (~$1,000 equivalent across any global currency)
        const fundUnits =
          walletDec === 6
            ? 1_000_000_000
            : walletDec === 2
              ? 500_000_00
              : 2_000_000;

        const mandate = createSpendMandate({
          principalKeyPair: principal,
          agentId: agent.did,
          currency: walletCurrency,
          decimals: walletDec,
          maxPerCall: fundUnits,
          maxDaily: fundUnits * 5,
          allowedServices: ['*'],
          allowedRails: ['*'],
        });

        const client = new VectollAgentClient({
          agentKeyPair: agent,
          facilitatorUrl: facUrl,
          preferredRail: rail,
          walletCurrency,
          mandateToken: mandate.token,
        });

        await client.topUp({ amount: fundUnits, currency: walletCurrency, decimals: walletDec, rail });

        if (scenario === 'mcp') {
          const mcpRoute = manifest.routes.find((r) => r.mcpTool && !r.hitlThreshold) ?? manifest.routes[0];
          const toolName = mcpRoute?.mcpTool?.name;
          if (!toolName) throw new Error('No MCP tool configured on Gate');
          const mcpOut = await client.callMcpTool(`${gateUrl}/mcp`, toolName, { region: 'global' });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              scenario: 'MCP_TOOL_CALL',
              agentDid: agent.did,
              rail,
              walletCurrency,
              toolName,
              ...mcpOut,
            }),
          );
          return;
        }

        if (scenario === 'hitl_escrow') {
          const escRoute =
            manifest.routes.find((r) => r.settlementMode === 'escrow' || r.hitlThreshold) ??
            manifest.routes[manifest.routes.length - 1];
          if (!escRoute) throw new Error('No routes configured on Gate');

          const bodyStr = escRoute.method === 'POST' ? JSON.stringify({ plan: 'enterprise-global', seats: 25 }) : '';
          const reqHash = computeRequestHash(escRoute.method, escRoute.path, bodyStr);
          const agentHeaders = signAgentHttpHeaders(reqHash, agent);

          const chgRes = await fetch(`${gateUrl}${escRoute.path}`, {
            method: escRoute.method,
            headers: {
              'User-Agent': 'VectollAgent/0.1',
              ...(bodyStr ? { 'Content-Type': 'application/json' } : {}),
              ...agentHeaders,
            },
            body: bodyStr || undefined,
          });
          const payHdr = chgRes.headers.get('payment-required');
          const challenge = payHdr
            ? decodePaymentHeader<PaymentChallenge>(payHdr)
            : ((await chgRes.json()) as PaymentChallenge);

          const now = Math.floor(Date.now() / 1000);
          const sig = signClearingIntent(
            {
              agentId: agent.did,
              challengeId: challenge.challengeId,
              reqHash: challenge.reqHash,
              maxAcceptedAmount: Number.MAX_SAFE_INTEGER,
              rail,
              timestamp: now,
            },
            agent,
          );

          const clearRes = await fetch(`${facUrl}/v1/clear`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              challenge,
              agentId: agent.did,
              rail,
              walletCurrency,
              maxAcceptedAmount: Number.MAX_SAFE_INTEGER,
              timestamp: now,
              agentSignature: sig,
              mandateToken: mandate.token,
            }),
          });
          const clearJson = (await clearRes.json()) as {
            status: string;
            approvalId?: string;
            vrt?: string;
          };

          if (clearJson.status === 'PENDING_HITL' && clearJson.approvalId) {
            pendingGateCalls.set(clearJson.approvalId, {
              url: `${gateUrl}${escRoute.path}`,
              method: escRoute.method,
              bodyStr,
              agentHeaders,
            });
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              scenario: 'HIGH_VALUE_ESCROW_HITL',
              agentDid: agent.did,
              rail,
              walletCurrency,
              nextStep:
                clearJson.status === 'PENDING_HITL'
                  ? 'Click "Approve & Complete" in the HITL Approval Queue below!'
                  : 'Settled directly',
              facilitatorResponse: clearJson,
            }),
          );
          return;
        }

        // Default: Instant HTTP 402 flow
        const instRoute =
          manifest.routes.find((r) => r.settlementMode === 'instant' && !r.hitlThreshold) ??
          manifest.routes[0];
        if (!instRoute) throw new Error('No routes configured on Gate');

        const { response, telemetry } = await client.fetchWithTelemetry(`${gateUrl}${instRoute.path}`, {
          method: instRoute.method,
        });
        const bodyData = await response.json().catch(() => ({}));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            scenario: 'INSTANT_HTTP_402',
            agentDid: agent.did,
            rail,
            walletCurrency,
            httpStatus: response.status,
            telemetry,
            originData: bodyData,
          }),
        );
        return;
      }

      if (req.method === 'POST' && req.url === '/api/playground/hitl-decide') {
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
        const { approvalId, decision } = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as {
          approvalId: string;
          decision: 'approve' | 'reject';
        };
        const decRes = await fetch(`${facUrl}/v1/hitl/${encodeURIComponent(approvalId)}/decide`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ decision }),
        });
        const decJson = (await decRes.json()) as { status: string; vrt?: string; escrowId?: string };

        let originCompletion: unknown = null;
        const savedCall = pendingGateCalls.get(approvalId);
        if (decision === 'approve' && decJson.vrt && savedCall) {
          pendingGateCalls.delete(approvalId);
          const paidRes = await fetch(savedCall.url, {
            method: savedCall.method,
            headers: {
              'User-Agent': 'VectollAgent/0.1',
              ...(savedCall.bodyStr ? { 'Content-Type': 'application/json' } : {}),
              ...savedCall.agentHeaders,
              'PAYMENT-SIGNATURE': decJson.vrt,
            },
            body: savedCall.bodyStr || undefined,
          });
          originCompletion = await paidRes.json().catch(() => null);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ hitlDecision: decJson, originCompletion }));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
    }
  });
}
