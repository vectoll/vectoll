import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createSpendMandate, extractStructuredDocument, generateKeyPair, parseVectollConfig } from '@vectoll/core';
import { createNodeGateServer } from '@vectoll/edge';
import { VectollFacilitator } from '@vectoll/facilitator';
import { VectollAgentClient } from '@vectoll/sdk';
import {
  createMeteredMcpServer,
  vectollMiddleware,
  verifyWebhookSignature,
  withVectoll,
  type VectollAugmentedRequest,
} from '../index.js';

describe('@vectoll/server single-port Node/Express middleware & Next.js/Fetch withVectoll', () => {
  it('runs single-port embedded Express/Node middleware with human-readable "$0.005" pricing', async () => {
    const mw = vectollMiddleware({
      name: 'my-single-port-app',
      routes: {
        'GET /api/weather': '$0.005',
        'GET /blog/*': { price: '$0.002', browsers: 'free' },
      },
    });

    const appServer = http.createServer((req: VectollAugmentedRequest, res) => {
      mw(req, res, () => {
        if (req.url?.startsWith('/api/weather')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ tempC: 22, paidBy: req.vectoll?.sub }));
          return;
        }
        if (req.url?.startsWith('/blog/')) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<h1>Free Blog Post for Browsers</h1>');
          return;
        }
        res.writeHead(404).end();
      });
    });

    await new Promise<void>((r) => appServer.listen(0, '127.0.0.1', r));
    const port = (appServer.address() as { port: number }).port;
    const appUrl = `http://127.0.0.1:${port}`;

    try {
      // 1. Discovery manifest auto-served on the exact same port!
      const disc = await fetch(`${appUrl}/.well-known/vectoll.json`);
      assert.equal(disc.status, 200);

      // 2. Browser accesses /blog/hello for free!
      const humanRes = await fetch(`${appUrl}/blog/hello`, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
          Accept: 'text/html',
        },
      });
      assert.equal(humanRes.status, 200);

      // 3. AI Agent funds wallet & pays single-port app with human-readable "$1.00" top-up!
      const agent = generateKeyPair();
      const client = new VectollAgentClient({
        agentKeyPair: agent,
        facilitatorUrl: `${appUrl}/_vectoll`,
        preferredRail: 'stripe',
        walletCurrency: 'USD',
      });
      await client.topUp({ amount: '$1.00', rail: 'stripe' });

      const paidRes = await client.fetch(`${appUrl}/api/weather?city=London`);
      assert.equal(paidRes.status, 200);
      const body = (await paidRes.json()) as { tempC: number; paidBy: string };
      assert.equal(body.tempC, 22);
      assert.equal(body.paidBy, agent.did);
    } finally {
      appServer.close();
    }
  });

  it('protects Web Fetch / Next.js Route Handlers with 1-line withVectoll()', async () => {
    const fac = new VectollFacilitator({ dbPath: ':memory:' });
    const facSrv = fac.createHttpServer();
    await new Promise<void>((r) => facSrv.listen(0, '127.0.0.1', r));
    const facPort = (facSrv.address() as { port: number }).port;
    const facUrl = `http://127.0.0.1:${facPort}`;
    fac.issuerUrl = facUrl;

    const GET = withVectoll(
      {
        price: '$0.01',
        service: 'nextjs-route-demo',
        facilitatorUrl: facUrl,
        facilitatorPublicKey: fac.keyPair.publicKeyBase64Url,
      },
      async (_req, receipt) => Response.json({ answer: 42, receiptId: receipt?.jti }),
    );

    const webSrv = http.createServer(async (req, res) => {
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === 'string') headers.set(k, v);
      }
      const out = await GET(new Request(`http://127.0.0.1${req.url}`, { method: req.method, headers }));
      const outHdrs: Record<string, string> = {};
      out.headers.forEach((v, k) => (outHdrs[k] = v));
      res.writeHead(out.status, outHdrs);
      res.end(await out.text());
    });
    await new Promise<void>((r) => webSrv.listen(0, '127.0.0.1', r));
    const webPort = (webSrv.address() as { port: number }).port;

    try {
      const agent = generateKeyPair();
      const client = new VectollAgentClient({
        agentKeyPair: agent,
        facilitatorUrl: facUrl,
        preferredRail: 'x402_usdc',
        walletCurrency: 'USDC',
      });
      await client.topUp({ amount: '$2.00', currency: 'USDC', rail: 'x402_usdc' });

      const res = await client.fetch(`http://127.0.0.1:${webPort}/api/answer`);
      assert.equal(res.status, 200);
      const data = (await res.json()) as { answer: number; receiptId: string };
      assert.equal(data.answer, 42);
      assert.ok(data.receiptId.startsWith('vrt_'));
    } finally {
      webSrv.close();
      facSrv.close();
      fac.ledger.close();
    }
  });

  it('builds a standalone 5-line MeteredMcpServer, translates legacy HTML to JSON, verifies webhooks & enforces mandate revocation', async () => {
    // A. Standalone MeteredMcpServer on a single port
    const mcp = createMeteredMcpServer({ name: 'global-patent-mcp' });
    mcp.tool<{ query: string }>(
      'search_patents',
      { price: '$0.01', description: 'Search global patent database' },
      async (args, receipt) => ({
        query: args.query,
        patents: ['WO-2026-99102'],
        paidBy: receipt?.sub,
      }),
    );

    const mcpSrv = mcp.createNodeServer();
    await new Promise<void>((r) => mcpSrv.listen(0, '127.0.0.1', r));
    const mcpPort = (mcpSrv.address() as { port: number }).port;
    const mcpBase = `http://127.0.0.1:${mcpPort}`;

    // B. HTML-to-Structured JSON Agent Translator on Gate
    const legacyHtmlOrigin = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!DOCTYPE html><html><head><title>Global Supply Chain Report</title>
        <meta name="description" content="Q4 semiconductor lead times"/>
        <script type="application/ld+json">{"@type":"Report","headline":"Supply Chain Q4"}</script>
        <script>window.analytics = { noisy: "${'x'.repeat(800)}" };</script>
        <style>.ad-banner { display: block; }</style></head>
        <body><nav>Menu Home About</nav>
        <article><h1>Semiconductor Lead Times Drop 14%</h1><p>Global wafer capacity expanded in <strong>Q4 2026</strong>. See <a href="/data.csv">raw dataset</a>.</p></article>
        <footer>Copyright 2026</footer></body></html>`);
    });
    await new Promise<void>((r) => legacyHtmlOrigin.listen(0, '127.0.0.1', r));
    const htmlOriginPort = (legacyHtmlOrigin.address() as { port: number }).port;

    const fac = mcp.facilitator!;
    const gateCfg = parseVectollConfig(`
name: "legacy-publisher"
origin: "http://127.0.0.1:${htmlOriginPort}"
facilitator: "${mcpBase}/_vectoll"
routes:
  GET /reports/*: { price: "$0.005", browsers: "free", transform: "structured" }
`);
    const gateSrv = createNodeGateServer({
      config: gateCfg,
      facilitatorPublicKey: fac.keyPair.publicKeyBase64Url,
    });
    await new Promise<void>((r) => gateSrv.listen(0, '127.0.0.1', r));
    const gatePort = (gateSrv.address() as { port: number }).port;

    try {
      const principal = generateKeyPair();
      const agent = generateKeyPair();
      const mandate = createSpendMandate({
        principalKeyPair: principal,
        agentId: agent.did,
        currency: 'USD',
        decimals: 6,
        maxPerCall: 5_000_000,
        maxDaily: 20_000_000,
      });

      const client = new VectollAgentClient({
        agentKeyPair: agent,
        facilitatorUrl: `${mcpBase}/_vectoll`,
        preferredRail: 'stripe',
        mandateToken: mandate.token,
      });
      await client.topUp({ amount: '$5.00', rail: 'stripe' });

      // 1. Call standalone paid MCP tool!
      const mcpOut = await client.callMcpTool<{ patents: string[]; paidBy: string }>(
        `${mcpBase}/mcp`,
        'search_patents',
        { query: 'photonics' },
      );
      assert.deepEqual(mcpOut.data.patents, ['WO-2026-99102']);
      assert.equal(mcpOut.data.paidBy, agent.did);

      // 2. Paying agent hits HTML page -> receives clean structured JSON + Markdown + JSON-LD!
      const htmlAgentRes = await client.fetch(`http://127.0.0.1:${gatePort}/reports/q4-chips`);
      assert.equal(htmlAgentRes.status, 200);
      const structured = (await htmlAgentRes.json()) as ReturnType<typeof extractStructuredDocument> & {
        receiptId: string;
      };
      assert.equal(structured.title, 'Global Supply Chain Report');
      assert.equal(structured.description, 'Q4 semiconductor lead times');
      assert.equal(structured.jsonLd.length, 1);
      assert.match(structured.markdown, /# Semiconductor Lead Times Drop 14%/);
      assert.ok(structured.estimatedTokenSavingsPct > 50);

      // 3. Verify Facilitator signed webhook helper!
      const signedHook = fac.signWebhookPayload('payment.cleared', { receiptId: structured.receiptId });
      const hookCheck = verifyWebhookSignature(
        signedHook.body,
        signedHook.headers,
        fac.keyPair.publicKeyBase64Url,
      );
      assert.equal(hookCheck.valid, true);
      assert.equal(hookCheck.event?.type, 'payment.cleared');

      // 4. Revoke Spend Mandate -> subsequent agent spend MUST fail with ERR_MANDATE_REVOKED!
      fac.revokeSpendMandate({
        mandateId: mandate.claims.mandateId,
        principalId: principal.did,
        reason: 'project_completed',
      });
      await assert.rejects(
        () => client.fetch(`http://127.0.0.1:${gatePort}/reports/q4-chips-2`),
        /ERR_MANDATE_REVOKED/,
      );
    } finally {
      gateSrv.close();
      legacyHtmlOrigin.close();
      mcpSrv.close();
      fac.ledger.close();
    }
  });
});
