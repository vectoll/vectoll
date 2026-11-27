#!/usr/bin/env node
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import readline from 'node:readline';
import {
  createSpendMandate,
  decodePaymentHeader,
  decodeVrtUnsafe,
  formatMinorAmount,
  generateKeyPair,
  getCurrencyDecimals,
  keyPairFromSeed,
  loadVectollConfigFile,
  parseVectollConfig,
  signVrt,
  toPublicJwk,
  type PaymentChallenge,
  type VectollConfig,
} from '@vectoll/core';
import { VectollFacilitator } from '@vectoll/facilitator';
import { createNodeGateServer } from '@vectoll/edge';
import { VectollAgentClient } from '@vectoll/sdk';
import { createConsoleServer } from '@vectoll/console';

function parseFlags(argv: string[]): { cmd: string; positional: string[]; flags: Record<string, string> } {
  const [cmd = 'help', ...rest] = argv;
  const positional: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]!;
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = rest[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = 'true';
      }
    } else {
      positional.push(arg);
    }
  }
  return { cmd, positional, flags };
}

function listen(server: http.Server, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const addr = server.address();
      resolve(addr && typeof addr === 'object' ? addr.port : port);
    });
  });
}

function isPortListening(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    socket.setTimeout(400);
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    const onFail = () => {
      socket.destroy();
      resolve(false);
    };
    socket.once('error', onFail);
    socket.once('timeout', onFail);
  });
}

export function createBuiltinOriginServer(
  cfg: VectollConfig,
  urls: { gateUrl: string; facilitatorUrl: string; consoleUrl: string },
): http.Server {
  return http.createServer(async (req, res) => {
    const reqUrl = new URL(req.url ?? '/', 'http://localhost');
    const accept = req.headers.accept ?? '';
    const isVerifiedAgent = req.headers['x-vectoll-verified'] === 'true';

    // Serve human-friendly Global Origin Portal on GET / or HTML browser visits
    if (!isVerifiedAgent && accept.includes('text/html')) {
      const routeCards = cfg.routes
        .map((r) => {
          const cur = r.currency ?? cfg.settlement.default_currency;
          const priceStr = formatMinorAmount(r.price, cur, r.decimals);
          return `<tr>
            <td><code>${r.method} ${r.path}</code></td>
            <td>${priceStr}</td>
            <td>${r.settlement_mode ?? 'instant'}${r.hitl_threshold ? ' + HITL' : ''}</td>
            <td>${r.human_passthrough ? '<span style="color:#10b981">Free Browser Access</span>' : '<span style="color:#f59e0b">Agent / Paid Only</span>'}</td>
            <td><code>${r.mcp_tool ?? '—'}</code></td>
          </tr>`;
        })
        .join('');

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><title>${cfg.service.name} — Protected by Vectoll</title>
<style>
  body{margin:0;background:#070b14;color:#f8fafc;font-family:Inter,system-ui,sans-serif;padding:30px;}
  .wrap{max-width:1120px;margin:0 auto;display:grid;gap:18px;}
  .card{background:#101726;border:1px solid #1e293b;border-radius:8px;padding:22px;}
  .pill{font-family:monospace;font-size:12px;padding:4px 10px;border-radius:4px;background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.4);}
  table{width:100%;border-collapse:collapse;font-family:ui-monospace,monospace;font-size:12.5px;margin-top:12px;}
  th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #1e293b;}
  th{color:#94a3b8;font-size:11px;text-transform:uppercase;}
  a.btn{display:inline-block;padding:8px 14px;border-radius:5px;background:#1e293b;color:#38bdf8;text-decoration:none;font-family:monospace;font-size:12px;border:1px solid #334155;margin-right:8px;}
  a.btn.primary{background:#10b981;color:#04130d;border-color:#10b981;font-weight:700;}
</style></head><body><div class="wrap">
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
      <h1 style="margin:0;font-size:21px;">${cfg.service.name}</h1>
      <span class="pill">HUMAN BROWSER PASSTHROUGH · 0 FEES</span>
    </div>
    <p style="color:#94a3b8;font-size:14px;margin:10px 0 16px;">${cfg.service.description ?? 'Global agent-ready service protected by Vectoll.'} Human visitors browse freely; autonomous AI agents and MCP clients authenticate and settle across <strong>${cfg.settlement.accepted_rails.join(', ')}</strong>.</p>
    <div>
      <a class="btn primary" href="${urls.consoleUrl}">Open Interactive Console (${urls.consoleUrl})</a>
      <a class="btn" href="${urls.gateUrl}/.well-known/vectoll.json">Discovery Manifest</a>
      <a class="btn" href="${urls.gateUrl}/mcp">MCP Gateway Inspector</a>
      <a class="btn" href="${urls.facilitatorUrl}">Facilitator Explorer</a>
    </div>
  </div>
  <div class="card">
    <strong style="font-size:14px;">Metered Endpoints &amp; Auto-Wrapped MCP Tools</strong>
    <table><thead><tr><th>Route</th><th>Agent Price</th><th>Clearing Mode</th><th>Browser Policy</th><th>MCP Tool</th></tr></thead><tbody>${routeCards}</tbody></table>
  </div>
</div></body></html>`);
      return;
    }

    // Structured JSON payload for verified AI agents, MCP calls, and programmatic endpoints
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    const reqBody = Buffer.concat(chunks).toString('utf8');

    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(
      JSON.stringify({
        service: cfg.service.name,
        endpoint: reqUrl.pathname + reqUrl.search,
        method: req.method,
        verifiedByVectollGate: isVerifiedAgent,
        receiptId: req.headers['x-vectoll-receipt-id'] ?? null,
        agentDid: req.headers['x-vectoll-agent-id'] ?? null,
        paidAmount: req.headers['x-vectoll-paid-amount'] ?? null,
        settlementRail: req.headers['x-vectoll-rail'] ?? null,
        escrowId: req.headers['x-vectoll-escrow-id'] ?? null,
        timestamp: new Date().toISOString(),
        data: {
          globalFeed: [
            { region: 'North America', hub: 'us-east', status: 'optimal', index: 104.82 },
            { region: 'Europe & UK', hub: 'eu-central', status: 'optimal', index: 102.41 },
            { region: 'Asia-Pacific', hub: 'ap-southeast', status: 'optimal', index: 108.15 },
            { region: 'LATAM & MEA', hub: 'global-edge', status: 'optimal', index: 106.09 },
          ],
          requestEcho: reqBody ? JSON.parse(reqBody) : Object.fromEntries(reqUrl.searchParams.entries()),
        },
      }),
    );
  });
}

function defaultCurrencyForRail(rail: string): string {
  switch (rail) {
    case 'x402_usdc':
      return 'USDC';
    case 'sepa_instant':
      return 'EUR';
    case 'pix_upi':
      return 'BRL';
    case 'mpesa':
      return 'KES';
    case 'momo':
      return 'GHS';
    case 'airtel_money':
      return 'INR';
    default:
      return 'USD';
  }
}

export async function runSimulation(rail = 'x402_usdc'): Promise<{
  status: number;
  clearingMs: number;
  totalMs: number;
  receiptId: string;
  balanced: boolean;
}> {
  const origin = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        service: 'vectoll-global-intelligence',
        endpoint: req.url,
        verifiedByGate: req.headers['x-vectoll-verified'] === 'true',
        receiptId: req.headers['x-vectoll-receipt-id'],
        paidAmount: req.headers['x-vectoll-paid-amount'],
        rail: req.headers['x-vectoll-rail'],
        markets: [
          { symbol: 'GLOBAL-AI-INDEX', priceUsd: '412.80', region: 'Global' },
          { symbol: 'COMPUTE-H200-SPOT', priceUsd: '2.45/hr', region: 'Multi-Region' },
        ],
      }),
    );
  });
  const originPort = await listen(origin, 0);

  const fac = new VectollFacilitator({ dbPath: ':memory:', feeBps: 150 });
  const facServer = fac.createHttpServer();
  const facPort = await listen(facServer, 0);
  fac.issuerUrl = `http://127.0.0.1:${facPort}`;

  const walletCurrency = defaultCurrencyForRail(rail);
  const walletDec = getCurrencyDecimals(walletCurrency);

  const cfg = parseVectollConfig(`
version: "1.0"
service:
  name: "vectoll-global-intelligence"
  origin: "http://127.0.0.1:${originPort}"
  enable_mcp: true
settlement:
  facilitator_url: "http://127.0.0.1:${facPort}"
  facilitator_kid: "${fac.keyPair.kid}"
  default_currency: "USD"
  default_decimals: 6
  accepted_rails:
    - "x402_usdc"
    - "stripe"
    - "sepa_instant"
    - "ach_fednow"
    - "pix_upi"
    - "mpesa"
    - "momo"
    - "airtel_money"
    - "voucher"
routes:
  - path: "/api/v1/intel/global-markets"
    method: "GET"
    price: 5000
    currency: "USD"
    decimals: 6
    human_passthrough: true
    mcp_tool: "query_global_markets"
`);

  const gate = createNodeGateServer({ config: cfg });
  const gatePort = await listen(gate, 0);

  try {
    const principal = generateKeyPair();
    const agent = generateKeyPair();
    const topupAmount = walletDec === 6 ? 10_000_000 : walletDec === 2 ? 100_000 : 100_000;

    const mandate = createSpendMandate({
      principalKeyPair: principal,
      agentId: agent.did,
      currency: walletCurrency,
      decimals: walletDec,
      maxPerCall: topupAmount,
      maxDaily: topupAmount * 5,
      allowedServices: ['vectoll-global-intelligence'],
      allowedRails: [rail],
    });

    const client = new VectollAgentClient({
      agentKeyPair: agent,
      facilitatorUrl: `http://127.0.0.1:${facPort}`,
      preferredRail: rail,
      walletCurrency,
      mandateToken: mandate.token,
    });

    await client.topUp({ amount: topupAmount, currency: walletCurrency, decimals: walletDec, rail });

    const { response, telemetry } = await client.fetchWithTelemetry(
      `http://127.0.0.1:${gatePort}/api/v1/intel/global-markets?region=all`,
    );
    const data = await response.json();
    const integrity = fac.ledger.verifyIntegrity();

    console.log('\n┌────────────────────────────────────────────────────────────────────────┐');
    console.log('│             VECTOLL GLOBAL HTTP 402 SIMULATION REPORT                  │');
    console.log('└────────────────────────────────────────────────────────────────────────┘');
    console.log(`  Agent DID         : ${agent.did}`);
    console.log(`  Selected Rail     : ${rail} (Wallet: ${walletCurrency} -> Route Price: 0.005 USD)`);
    console.log(`  HTTP Status       : 402 Challenge -> ${response.status} OK`);
    console.log(`  Receipt ID (JTI)  : ${telemetry.receiptId}`);
    console.log(
      `  Debited From Float: ${formatMinorAmount(telemetry.debitedAmount ?? 0, telemetry.debitedCurrency ?? walletCurrency)}`,
    );
    console.log(`  Facilitator Clear : ${telemetry.clearingMs} ms`);
    console.log(`  End-to-End 402 RTT: ${telemetry.totalMs} ms`);
    console.log(`  Ledger Integrity  : ${integrity.balanced ? 'BALANCED (sum(debit) == sum(credit))' : 'ERROR'}`);
    console.log(`  Origin Payload    : ${JSON.stringify(data)}\n`);

    return {
      status: response.status,
      clearingMs: telemetry.clearingMs ?? 0,
      totalMs: telemetry.totalMs,
      receiptId: telemetry.receiptId ?? '',
      balanced: integrity.balanced,
    };
  } finally {
    gate.close();
    facServer.close();
    origin.close();
    fac.ledger.close();
  }
}

function detectProjectStack(cwd: string): { framework: string; defaultOrigin: string; snippet: string } {
  const pkgPath = path.join(cwd, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps.next) {
        return {
          framework: 'Next.js',
          defaultOrigin: 'http://127.0.0.1:3000',
          snippet: `// app/api/search/route.ts
import { withVectoll } from '@vectoll/server';
export const GET = withVectoll('$0.005', async (req, receipt) => Response.json({ ok: true, paidBy: receipt?.sub }));`,
        };
      }
      if (deps.hono) {
        return {
          framework: 'Hono / Edge',
          defaultOrigin: 'http://127.0.0.1:8787',
          snippet: `import { withVectoll } from '@vectoll/server';
app.get('/api/data', (c) => withVectoll('$0.005', async () => c.json({ ok: true }))(c.req.raw));`,
        };
      }
      return {
        framework: 'Node.js / Express',
        defaultOrigin: 'http://127.0.0.1:3000',
        snippet: `import { vectollMiddleware } from '@vectoll/server';
app.use(vectollMiddleware({ routes: { 'GET /api/data': '$0.005', 'GET /blog/*': { price: '$0.001', browsers: 'free' } } }));`,
      };
    } catch {
      // ignore malformed package.json
    }
  }
  if (fs.existsSync(path.join(cwd, 'pyproject.toml')) || fs.existsSync(path.join(cwd, 'requirements.txt'))) {
    return {
      framework: 'Python (FastAPI / ASGI)',
      defaultOrigin: 'http://127.0.0.1:8000',
      snippet: `from vectoll.asgi import VectollMiddleware
app.add_middleware(VectollMiddleware, routes={"GET /api/predict": "$0.01"})`,
    };
  }
  return {
    framework: 'HTTP / Web Service',
    defaultOrigin: 'http://127.0.0.1:8080',
    snippet: `vectoll dev --config vectoll.yaml`,
  };
}

function parseCliRouteArgs(rawArgs: string[]): Record<string, { price: string; browsers?: 'free' }> {
  const routes: Record<string, { price: string; browsers?: 'free' }> = {};
  for (const item of rawArgs) {
    const eqIdx = item.indexOf('=');
    if (eqIdx === -1) {
      throw new Error(`Invalid --route "${item}". Expected format: "GET /api/*=$0.005" or "GET /blog/*=$0.001:free"`);
    }
    const routeKey = item.slice(0, eqIdx).trim();
    const rhs = item.slice(eqIdx + 1).trim();
    if (rhs.endsWith(':free')) {
      routes[routeKey] = { price: rhs.slice(0, -':free'.length), browsers: 'free' };
    } else {
      routes[routeKey] = { price: rhs };
    }
  }
  return routes;
}

export async function handleMcpStdioLine(
  line: string,
  remoteMcpUrl: string,
  agentClient: VectollAgentClient,
): Promise<string | null> {
  const trimmed = line.trim();
  if (!trimmed) return null;

  let rpc: { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> };
  try {
    rpc = JSON.parse(trimmed);
  } catch {
    return JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }

  // Notifications without id require no response
  if (rpc.id === undefined && rpc.method?.startsWith('notifications/')) {
    return null;
  }

  const { response } = await agentClient.fetchWithTelemetry(remoteMcpUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(rpc),
  });
  return await response.text();
}

async function main() {
  const rawArgv = process.argv.slice(2);
  // Collect repeatable --route flags cleanly for `vectoll proxy`
  const routeList: string[] = [];
  const filteredArgv: string[] = [];
  for (let i = 0; i < rawArgv.length; i++) {
    if (rawArgv[i] === '--route' && rawArgv[i + 1]) {
      routeList.push(rawArgv[i + 1]!);
      i++;
    } else {
      filteredArgv.push(rawArgv[i]!);
    }
  }
  const { cmd, positional, flags } = parseFlags(filteredArgv);

  if (cmd === 'init') {
    const outPath = path.resolve(flags.out ?? 'vectoll.yaml');
    if (fs.existsSync(outPath) && flags.force !== 'true') {
      console.error(`File already exists: ${outPath} (pass --force to overwrite)`);
      process.exit(1);
    }
    const detected = detectProjectStack(process.cwd());
    const sample = `# Vectoll Project Configuration (Simple Shorthand)
origin: "${detected.defaultOrigin}"

routes:
  GET /api/data: "$0.005"
  POST /api/action: "$0.02"
  GET /articles/*:
    price: "$0.001"
    browsers: "free"
`;
    fs.writeFileSync(outPath, sample, 'utf8');
    console.log(`Created ${outPath} (detected: ${detected.framework})\n`);
    console.log(`Option A — Run zero-code proxy in front of your app:\n  npx @vectoll/cli dev\n`);
    console.log(`Option B — Or drop 2 lines of middleware directly into your ${detected.framework} code:\n${detected.snippet}\n`);
    return;
  }

  if (cmd === 'proxy') {
    const originTarget = positional[0] ?? flags.origin ?? 'http://127.0.0.1:3000';
    const routesMap =
      routeList.length > 0
        ? parseCliRouteArgs(routeList)
        : { 'GET /api/*': { price: '$0.005' }, 'POST /api/*': { price: '$0.01' } };

    const gatePort = Number(flags.port ?? 4020);
    const facPort = Number(flags['facilitator-port'] ?? 4021);
    const consolePort = Number(flags['console-port'] ?? 4022);
    const gateUrl = `http://127.0.0.1:${gatePort}`;
    const facUrl = `http://127.0.0.1:${facPort}`;
    const consoleUrl = `http://127.0.0.1:${consolePort}`;

    const cfg = parseVectollConfig(
      JSON.stringify({
        name: flags.name ?? 'proxied-app',
        origin: originTarget,
        routes: routesMap,
      }),
    );

    const fac = new VectollFacilitator({ dbPath: flags.db ?? ':memory:', issuerUrl: facUrl });
    await listen(fac.createHttpServer(), facPort);

    cfg.settlement.facilitator_url = facUrl;
    cfg.settlement.facilitator_kid = fac.keyPair.kid;
    cfg.settlement.facilitator_public_key = fac.keyPair.publicKeyBase64Url;

    await listen(
      createNodeGateServer({ config: cfg, facilitatorPublicKey: fac.keyPair.publicKeyBase64Url }),
      gatePort,
    );
    await listen(createConsoleServer({ facilitatorUrl: facUrl, gateUrl }), consolePort);

    console.log(`Vectoll Zero-Config Proxy Active:`);
    console.log(`  • Protecting Origin : ${originTarget}`);
    console.log(`  • Public Gate URL   : ${gateUrl}`);
    console.log(`  • MCP Server        : ${gateUrl}/mcp`);
    console.log(`  • Live Console      : ${consoleUrl}`);
    return;
  }

  if (cmd === 'keygen') {
    const kp = generateKeyPair(flags.kid);
    console.log(
      JSON.stringify(
        {
          kid: kp.kid,
          did: kp.did,
          seedHex: kp.seedHex,
          publicKeyBase64Url: kp.publicKeyBase64Url,
          jwk: toPublicJwk(kp),
        },
        null,
        2,
      ),
    );
    return;
  }

  if (cmd === 'inspect') {
    const token = positional[0];
    if (!token) {
      console.error('Usage: vectoll inspect <vrt1-token>');
      process.exit(1);
    }
    console.log(JSON.stringify(decodeVrtUnsafe(token), null, 2));
    return;
  }

  if (cmd === 'mcp-bridge') {
    const remoteBase = (positional[0] ?? flags.url ?? 'http://127.0.0.1:4020').replace(/\/$/, '');
    const remoteMcpUrl = remoteBase.endsWith('/mcp') ? remoteBase : `${remoteBase}/mcp`;
    const rail = flags.rail ?? process.env.VECTOLL_RAIL ?? 'x402_usdc';
    const seed = flags.seed ?? process.env.VECTOLL_AGENT_SEED;
    const kp = seed ? keyPairFromSeed(seed) : generateKeyPair();

    const agentClient = new VectollAgentClient({
      agentKeyPair: kp,
      facilitatorUrl: flags.facilitator ?? process.env.VECTOLL_FACILITATOR_URL,
      preferredRail: rail,
      walletCurrency: flags.currency ?? process.env.VECTOLL_CURRENCY,
      maxPricePerCall: flags['max-per-call'] ?? '$0.10',
      mandateToken: flags.mandate ?? process.env.VECTOLL_MANDATE_TOKEN,
    });

    if (flags['auto-topup'] && (flags.facilitator ?? process.env.VECTOLL_FACILITATOR_URL)) {
      await agentClient.topUp({
        amount: flags['auto-topup'],
        rail,
        facilitatorUrl: flags.facilitator ?? process.env.VECTOLL_FACILITATOR_URL,
      });
    }

    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    for await (const line of rl) {
      const reply = await handleMcpStdioLine(line, remoteMcpUrl, agentClient);
      if (reply !== null) {
        process.stdout.write(reply.trim() + '\n');
      }
    }
    return;
  }

  if (cmd === 'check') {
    const targetBase = (positional[0] ?? flags.url ?? 'http://127.0.0.1:4020').replace(/\/$/, '');
    const results: Array<{ check: string; passed: boolean; detail: string }> = [];

    // Check 1: Discovery Manifest (/.well-known/vectoll.json)
    const discRes = await fetch(`${targetBase}/.well-known/vectoll.json`);
    const manifest = (await discRes.json()) as {
      vectollVersion?: string;
      service?: { name?: string };
      settlement?: { acceptedRails?: string[]; facilitatorPublicKey?: string };
      routes?: Array<{ path: string; method: string; amount: number }>;
    };
    const c1 =
      discRes.status === 200 &&
      (manifest.vectollVersion === '0.1' || manifest.vectollVersion === '1.0') &&
      Array.isArray(manifest.routes) &&
      manifest.routes.length > 0;
    results.push({
      check: '1. Discovery Manifest (/.well-known/vectoll.json)',
      passed: c1,
      detail: c1
        ? `service="${manifest.service?.name}", routes=${manifest.routes?.length}, rails=${manifest.settlement?.acceptedRails?.length}`
        : `HTTP ${discRes.status}`,
    });

    const testRoute = manifest.routes?.find((r) => r.amount > 0) ?? manifest.routes?.[0];
    if (!testRoute) {
      throw new Error('No routes found in discovery manifest to audit');
    }
    const routeUrl = `${targetBase}${testRoute.path.replace('/*', '/test-item')}`;

    // Check 2: Unpaid Agent HTTP 402 + x402 V2 PAYMENT-REQUIRED Header
    const unpaidRes = await fetch(routeUrl, {
      method: testRoute.method,
      headers: { 'User-Agent': 'GPTBot/1.0' },
    });
    const payHdr = unpaidRes.headers.get('payment-required');
    let parsedChg: PaymentChallenge | undefined;
    if (payHdr) {
      parsedChg = decodePaymentHeader<PaymentChallenge>(payHdr);
    }
    const c2 = unpaidRes.status === 402 && Boolean(parsedChg?.challengeId && parsedChg.reqHash);
    results.push({
      check: '2. HTTP 402 Challenge & x402 V2 PAYMENT-REQUIRED Header',
      passed: c2,
      detail: c2 ? `challengeId=${parsedChg?.challengeId}, amount=${parsedChg?.amount} ${parsedChg?.currency}` : `HTTP ${unpaidRes.status}`,
    });

    // Check 3: Forged Signature Rejection (adversarial key)
    const attackerKey = generateKeyPair('attacker-key');
    const forged = signVrt(
      {
        iss: 'https://evil.example',
        sub: attackerKey.did,
        aud: manifest.service?.name ?? 'unknown',
        chg: parsedChg?.challengeId ?? 'chg_fake',
        req: parsedChg?.reqHash ?? 'sha256:' + '0'.repeat(64),
        amt: testRoute.amount,
        cur: 'USD',
        dec: 6,
        rail: 'stripe',
        mode: 'instant',
      },
      attackerKey,
    );
    const forgeRes = await fetch(routeUrl, {
      method: testRoute.method,
      headers: { 'User-Agent': 'VectollAgent/0.1', 'PAYMENT-SIGNATURE': forged.token },
    });
    const c3 = forgeRes.status === 402;
    results.push({
      check: '3. Adversarial Forged Ed25519 VRT Rejection',
      passed: c3,
      detail: c3 ? 'Rejected forged receipt (HTTP 402)' : `SECURITY FAIL: HTTP ${forgeRes.status}`,
    });

    // Check 4: Spoofed X-Vectoll-Verified Header Rejection
    const spoofRes = await fetch(routeUrl, {
      method: testRoute.method,
      headers: { 'User-Agent': 'GPTBot/1.0', 'X-Vectoll-Verified': 'true' },
    });
    const c4 = spoofRes.status === 402;
    results.push({
      check: '4. Spoofed X-Vectoll-Verified Ingress Sanitization',
      passed: c4,
      detail: c4 ? 'Blocked spoofed header (HTTP 402)' : `SECURITY FAIL: HTTP ${spoofRes.status}`,
    });

    // Check 5: Malformed / Algorithm-Confusion Token Rejection
    const algNoneRes = await fetch(routeUrl, {
      method: testRoute.method,
      headers: {
        'User-Agent': 'VectollAgent/1.0',
        'PAYMENT-SIGNATURE': 'eyJhbGciOiJub25lIn0.eyJ2IjoxfQ.',
      },
    });
    const c5 = algNoneRes.status === 402;
    results.push({
      check: '5. Algorithm-Confusion & Malformed Token Rejection',
      passed: c5,
      detail: c5 ? 'Rejected non-vrt1 / alg:none token (HTTP 402)' : `SECURITY FAIL: HTTP ${algNoneRes.status}`,
    });

    // Check 6 (Optional --strict): Prometheus /metrics or /health readiness
    if (flags.strict === 'true') {
      const mRes = await fetch(`${targetBase}/metrics`);
      const hRes = mRes.ok ? mRes : await fetch(`${targetBase}/health`);
      results.push({
        check: '6. Operational Health & Prometheus Telemetry (--strict)',
        passed: hRes.ok,
        detail: hRes.ok ? `Telemetry endpoint HTTP ${hRes.status}` : `HTTP ${hRes.status}`,
      });
    }

    console.log(`\nVectoll v1.0 Conformance & Security Audit — ${targetBase}`);
    for (const r of results) {
      console.log(`  [${r.passed ? 'PASS' : 'FAIL'}] ${r.check} -> ${r.detail}`);
    }
    const allPassed = results.every((r) => r.passed);
    if (allPassed && flags.badge) {
      const badgePath = path.resolve(flags.badge);
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="176" height="20" role="img" aria-label="Vectoll: v1.0 Verified">
  <rect width="68" height="20" fill="#0f172a" rx="3"/>
  <rect x="68" width="108" height="20" fill="#10b981" rx="3"/>
  <text x="34" y="14" fill="#f8fafc" font-family="monospace" font-size="11" text-anchor="middle" font-weight="bold">VECTOLL</text>
  <text x="122" y="14" fill="#04130d" font-family="monospace" font-size="11" text-anchor="middle" font-weight="bold">v1.0 VERIFIED</text>
</svg>\n`;
      fs.writeFileSync(badgePath, svg, 'utf8');
      console.log(`  [BADGE] Wrote conformance badge -> ${badgePath}`);
    }
    if (!allPassed) {
      process.exit(1);
    }
    return;
  }

  if (cmd === 'simulate') {
    await runSimulation(flags.rail ?? 'x402_usdc');
    return;
  }

  if (cmd === 'dev') {
    const fallbackExample = path.resolve('examples/global-cloud-ai/vectoll.yaml');
    const cfgPath = path.resolve(
      flags.config ?? (fs.existsSync('vectoll.yaml') ? 'vectoll.yaml' : fallbackExample),
    );
    const cfg = loadVectollConfigFile(cfgPath);
    const gatePort = Number(flags.port ?? 4020);
    const facPort = Number(flags['facilitator-port'] ?? 4021);
    const consolePort = Number(flags['console-port'] ?? 4022);

    const gateUrl = `http://127.0.0.1:${gatePort}`;
    const facUrl = `http://127.0.0.1:${facPort}`;
    const consoleUrl = `http://127.0.0.1:${consolePort}`;

    // Auto-provision built-in Global Origin if configured upstream is not already listening
    const originParsed = new URL(cfg.service.origin);
    const originHost = originParsed.hostname;
    const originPort = Number(originParsed.port || (originParsed.protocol === 'https:' ? 443 : 80));
    let builtinOriginMode = false;

    if (
      (originHost === '127.0.0.1' || originHost === 'localhost') &&
      !(await isPortListening(originHost, originPort))
    ) {
      const originSrv = createBuiltinOriginServer(cfg, {
        gateUrl,
        facilitatorUrl: facUrl,
        consoleUrl,
      });
      await listen(originSrv, originPort);
      builtinOriginMode = true;
    }

    const fac = new VectollFacilitator({
      dbPath: flags.db ?? './data/vectoll-dev.sqlite',
      issuerUrl: facUrl,
    });
    const facSrv = fac.createHttpServer();
    await listen(facSrv, facPort);

    cfg.settlement.facilitator_url = facUrl;
    cfg.settlement.facilitator_kid = fac.keyPair.kid;
    cfg.settlement.facilitator_public_key = fac.keyPair.publicKeyBase64Url;

    const gateSrv = createNodeGateServer({
      config: cfg,
      facilitatorPublicKey: fac.keyPair.publicKeyBase64Url,
    });
    await listen(gateSrv, gatePort);

    const consoleSrv = createConsoleServer({
      facilitatorUrl: facUrl,
      gateUrl,
    });
    await listen(consoleSrv, consolePort);

    console.log(`Vectoll Global Dev Stack Ready (${cfg.service.name}):`);
    console.log(
      `  • Upstream Origin  : ${cfg.service.origin} (${builtinOriginMode ? 'Built-in Global Demo Origin active' : 'Connected to external origin'})`,
    );
    console.log(`  • Gate & Portal    : ${gateUrl}`);
    console.log(`  • Discovery JSON   : ${gateUrl}/.well-known/vectoll.json`);
    console.log(`  • MCP Inspector    : ${gateUrl}/mcp`);
    console.log(`  • Facilitator UI   : ${facUrl}`);
    console.log(`  • Global Console   : ${consoleUrl}`);
    return;
  }

  console.log(`Vectoll CLI v0.1.0 — Add AI Agent Metering & Payments to Any Project
Commands:
  vectoll init                                         Auto-detect project & create 6-line vectoll.yaml
  vectoll proxy <origin> --route "GET /api/*=$0.005"   Zero-file sidecar proxy in front of any app
  vectoll dev [--config vectoll.yaml]                  Launch local Gate + Facilitator + Console
  vectoll check [http://localhost:4020]                Audit live endpoint security & protocol compliance
  vectoll mcp-bridge <remote-url> [--rail x402_usdc]   Local stdio MCP bridge for Claude Desktop & Cursor
  vectoll simulate [--rail x402_usdc|stripe|sepa_instant|pix_upi|mpesa|momo]
  vectoll keygen [--kid my-key-1]                      Generate Ed25519 keypair + did:key + JWK
  vectoll inspect <vrt1-token>                         Decode VRT receipt claims`);
}

const isDirectRun =
  process.argv[1] &&
  (process.argv[1].endsWith('/bin.js') || process.argv[1].endsWith('\\bin.js'));

if (isDirectRun) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
