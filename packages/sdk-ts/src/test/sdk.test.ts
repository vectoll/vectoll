import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  createPasskeySpendMandate,
  createSpendMandate,
  generateKeyPair,
  generatePasskeyKeyPair,
  parseVectollConfig,
  verifySpendMandate,
} from '@vectoll/core';
import { VectollFacilitator } from '@vectoll/facilitator';
import { createNodeGateServer } from '@vectoll/edge';
import { VectollAgentClient } from '../index.js';

function listenEphemeral(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') resolve(addr.port);
      else reject(new Error('Failed to get port'));
    });
  });
}

describe('@vectoll/sdk + @vectoll/edge + @vectoll/facilitator end-to-end integration', () => {
  it('handles human passthrough, 402 auto-payment, replay rejection, MCP tools, and HITL escrow', async () => {
    // 1. Mock Origin server
    const originServer = http.createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (url.pathname === '/api/v1/rooms/availability') {
        if ((req.headers.accept ?? '').includes('text/html')) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><h1>Kampala Grand Hotel - Rooms Available</h1></body></html>');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            hotel: 'Kampala Grand',
            verifiedByVectoll: req.headers['x-vectoll-verified'] === 'true',
            receiptId: req.headers['x-vectoll-receipt-id'],
            rooms: [{ type: 'Deluxe', nightlyUgx: 350_000 }],
          }),
        );
        return;
      }
      if (url.pathname === '/api/v1/rooms/book' && req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            bookingRef: 'BK-2026-881',
            escrowId: req.headers['x-vectoll-escrow-id'],
          }),
        );
        return;
      }
      res.writeHead(404).end();
    });
    const originPort = await listenEphemeral(originServer);

    // 2. Facilitator server
    const fac = new VectollFacilitator({ dbPath: ':memory:', feeBps: 100 });
    const facServer = fac.createHttpServer();
    const facPort = await listenEphemeral(facServer);
    fac.issuerUrl = `http://127.0.0.1:${facPort}`;

    // 3. Edge/Node Gate proxy
    const cfg = parseVectollConfig(`
version: "1.0"
service:
  name: "kampala-grand-hotel"
  origin: "http://127.0.0.1:${originPort}"
  enable_mcp: true
settlement:
  facilitator_url: "http://127.0.0.1:${facPort}"
  facilitator_kid: "${fac.keyPair.kid}"
  default_currency: "UGX"
  accepted_rails:
    - "momo"
    - "x402_usdc"
routes:
  - path: "/api/v1/rooms/availability"
    method: "GET"
    price: 50
    human_passthrough: true
    mcp_tool: "check_room_availability"
  - path: "/api/v1/rooms/book"
    method: "POST"
    price: 550000
    settlement_mode: "escrow"
    require_mandate: true
    hitl_threshold: 500000
    mcp_tool: "book_room"
`);
    const gateServer = createNodeGateServer({ config: cfg });
    const gatePort = await listenEphemeral(gateServer);
    const gateUrl = `http://127.0.0.1:${gatePort}`;

    try {
      // A. Human browser visits availability page -> 200 OK free of charge!
      const browserRes = await fetch(`${gateUrl}/api/v1/rooms/availability`, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
          Accept: 'text/html,application/xhtml+xml',
        },
      });
      assert.equal(browserRes.status, 200);
      assert.match(await browserRes.text(), /Kampala Grand Hotel/);

      // B. Unpaid scraper / bot hits same route -> 402 Payment Required!
      const botRes = await fetch(`${gateUrl}/api/v1/rooms/availability`, {
        headers: { 'User-Agent': 'GPTBot/1.0' },
      });
      assert.equal(botRes.status, 402);
      assert.ok(botRes.headers.get('payment-required'));

      // C. VectollAgentClient funds wallet via MoMo and queries REST + MCP automatically!
      const principal = generateKeyPair();
      const agent = generateKeyPair();
      const mandate = createSpendMandate({
        principalKeyPair: principal,
        agentId: agent.did,
        currency: 'UGX',
        decimals: 0,
        maxPerCall: 600_000,
        maxDaily: 1_000_000,
        allowedServices: ['kampala-grand-hotel'],
        allowedRails: ['momo'],
        hitlThreshold: 500_000,
      });

      const client = new VectollAgentClient({
        agentKeyPair: agent,
        facilitatorUrl: `http://127.0.0.1:${facPort}`,
        preferredRail: 'momo',
        mandateToken: mandate.token,
        hitlPollIntervalMs: 50,
      });

      await client.topUp({ amount: 700_000, currency: 'UGX', rail: 'momo' });

      const { response, telemetry } = await client.fetchWithTelemetry(
        `${gateUrl}/api/v1/rooms/availability?adults=2`,
      );
      assert.equal(response.status, 200);
      assert.equal(telemetry.challenged, true);
      assert.equal(telemetry.debitedAmount, 50);
      const availJson = (await response.json()) as { verifiedByVectoll: boolean };
      assert.equal(availJson.verifiedByVectoll, true);

      // D. Paid MCP tool call (/mcp -> check_room_availability)
      const mcpResult = await client.callMcpTool<{ hotel: string }>(
        `${gateUrl}/mcp`,
        'check_room_availability',
        { adults: 2 },
      );
      assert.equal(mcpResult.data.hotel, 'Kampala Grand');
      assert.equal(mcpResult.telemetry.challenged, true);

      // E. High-value booking triggers HITL pause -> Asynchronous approval -> Escrow lock -> Verified 200!
      setTimeout(() => {
        const summary = fac.getTelemetrySummary();
        const pending = summary.hitlApprovals[0] as { approvalId?: string } | undefined;
        if (pending?.approvalId) {
          fac.decideHitl(pending.approvalId, 'approve');
        }
      }, 120);

      const bookRes = await client.fetch(`${gateUrl}/api/v1/rooms/book`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomType: 'Deluxe', nights: 1 }),
      });
      assert.equal(bookRes.status, 200);
      const bookJson = (await bookRes.json()) as { bookingRef: string; escrowId: string };
      assert.equal(bookJson.bookingRef, 'BK-2026-881');
      assert.ok(bookJson.escrowId.startsWith('esc_'));

      // Verify ledger remains strictly balanced!
      assert.equal(fac.ledger.verifyIntegrity().balanced, true);
    } finally {
      gateServer.close();
      facServer.close();
      originServer.close();
      fac.ledger.close();
    }
  });

  it('verifies M4 WebAuthn Passkey Mandates (vsm1p), Multi-Tenant vk_live_* isolation & EU->Tokyo Federated Clearing', async () => {
    // 1. Verify W3C WebAuthn P-256 Passkey Spend Mandate (vsm1p)
    const passkey = generatePasskeyKeyPair('yubikey-bio-01');
    const agent = generateKeyPair();
    const pkMandate = createPasskeySpendMandate({
      passkey,
      agentId: agent.did,
      origin: 'https://console.vectoll.org',
      currency: 'EUR',
      decimals: 6,
      maxPerCall: 5_000_000,
      maxDaily: 25_000_000,
      allowedServices: ['tokyo-robotics-api'],
      allowedRails: ['sepa_instant'],
    });
    assert.ok(pkMandate.token.startsWith('vsm1p.'));
    const checkPk = verifySpendMandate(pkMandate.token, {
      expectedAgentId: agent.did,
      service: 'tokyo-robotics-api',
      rail: 'sepa_instant',
      debitAmountInMandateCurrency: 10_000,
    });
    assert.equal(checkPk.valid, true);

    // 2. Boot Origin + TWO Federated Facilitators: facEU (Frankfurt) & facTokyo (Tokyo)
    const origin = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          telemetry: 'Tokyo Robotics Sensor Stream',
          verifiedByGate: req.headers['x-vectoll-verified'] === 'true',
          receiptId: req.headers['x-vectoll-receipt-id'],
        }),
      );
    });
    const originPort = await listenEphemeral(origin);

    const facEU = new VectollFacilitator({ dbPath: ':memory:', facilitatorKid: 'fac-eu-1', feeBps: 100 });
    const facTokyo = new VectollFacilitator({ dbPath: ':memory:', facilitatorKid: 'fac-tokyo-1', feeBps: 150 });
    const euSrv = facEU.createHttpServer();
    const tokyoSrv = facTokyo.createHttpServer();
    const euPort = await listenEphemeral(euSrv);
    const tokyoPort = await listenEphemeral(tokyoSrv);
    facEU.issuerUrl = `http://127.0.0.1:${euPort}`;
    facTokyo.issuerUrl = `http://127.0.0.1:${tokyoPort}`;

    // Register bilateral federation peering between Frankfurt & Tokyo
    facEU.registerPeerFacilitator({
      peerId: 'tokyo-node',
      issuerUrl: facTokyo.issuerUrl,
      kid: facTokyo.keyPair.kid,
      publicKeyBase64Url: facTokyo.keyPair.publicKeyBase64Url,
      creditLimitUsdMicro: 500_000_000,
    });
    facTokyo.registerPeerFacilitator({
      peerId: 'frankfurt-node',
      issuerUrl: facEU.issuerUrl,
      kid: facEU.keyPair.kid,
      publicKeyBase64Url: facEU.keyPair.publicKeyBase64Url,
      creditLimitUsdMicro: 500_000_000,
    });

    // Register Multi-Tenant Merchants on Tokyo Facilitator
    const mchTokyo = facTokyo.registerMerchant({
      orgName: 'Tokyo Robotics Corp',
      serviceName: 'tokyo-robotics-api',
    });
    const mchOther = facTokyo.registerMerchant({
      orgName: 'Other Rival Corp',
      serviceName: 'other-rival-api',
    });
    const readOnlyKey = facTokyo.issueMerchantApiKey(mchTokyo.merchantId, ['ledger:read']);

    // Gate trusts Tokyo Facilitator ONLY — knows nothing directly about Frankfurt!
    const gateCfg = parseVectollConfig(`
name: "tokyo-robotics-api"
origin: "http://127.0.0.1:${originPort}"
facilitator: "${facTokyo.issuerUrl}"
routes:
  GET /api/sensors: "$0.01"
`);
    const gateSrv = createNodeGateServer({
      config: gateCfg,
      facilitatorPublicKey: facTokyo.keyPair.publicKeyBase64Url,
    });
    const gatePort = await listenEphemeral(gateSrv);

    try {
      // Agent is funded ONLY on Frankfurt Facilitator (EUR via SEPA Instant) with Passkey Mandate!
      const euAgentClient = new VectollAgentClient({
        agentKeyPair: agent,
        facilitatorUrl: facEU.issuerUrl, // Points to Home Facilitator in Frankfurt!
        preferredRail: 'sepa_instant',
        walletCurrency: 'EUR',
        mandateToken: pkMandate.token,
      });

      await euAgentClient.topUp({ amount: '€5.00', currency: 'EUR', rail: 'sepa_instant' });

      // Agent calls Tokyo Gate -> gets Tokyo 402 challenge -> clears via Frankfurt -> settles inbound on Tokyo -> 200 OK!
      const res = await euAgentClient.fetch(`http://127.0.0.1:${gatePort}/api/sensors`);
      assert.equal(res.status, 200);
      const data = (await res.json()) as { verifiedByGate: boolean; receiptId: string };
      assert.equal(data.verifiedByGate, true);
      assert.ok(data.receiptId.startsWith('vrt_'));

      // Verify bilateral federation positions & mathematical balance on BOTH Facilitators!
      const euPos = facEU.getFederationPositions();
      const tokyoPos = facTokyo.getFederationPositions();
      assert.equal(euPos.positions[0]?.balance, 10_000);     // 10,000 micro-USD ($0.01) payable to Tokyo
      assert.equal(tokyoPos.positions[0]?.balance, 10_000);  // 10,000 micro-USD ($0.01) receivable from Frankfurt
      assert.equal(facEU.ledger.verifyIntegrity().balanced, true);
      assert.equal(facTokyo.ledger.verifyIntegrity().balanced, true);

      // 3. Verify Multi-Tenant Scoped API Key Isolation on Payouts!
      // a) Missing key -> 401
      const pNoAuth = await fetch(`${facTokyo.issuerUrl}/v1/payouts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service: 'tokyo-robotics-api', destinationAccount: 'acct_1', rail: 'stripe', currency: 'USD' }),
      });
      assert.equal(pNoAuth.status, 401);

      // b) Rival tenant's valid vk_live_* key -> 403 ERR_TENANT_FORBIDDEN
      const pWrongTenant = await fetch(`${facTokyo.issuerUrl}/v1/payouts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mchOther.apiKey}` },
        body: JSON.stringify({ service: 'tokyo-robotics-api', destinationAccount: 'acct_1', rail: 'stripe', currency: 'USD' }),
      });
      assert.equal(pWrongTenant.status, 403);

      // c) Tokyo's read-only key -> 403 ERR_INSUFFICIENT_SCOPE
      const pWrongScope = await fetch(`${facTokyo.issuerUrl}/v1/payouts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${readOnlyKey.apiKey}` },
        body: JSON.stringify({ service: 'tokyo-robotics-api', destinationAccount: 'acct_1', rail: 'stripe', currency: 'USD' }),
      });
      assert.equal(pWrongScope.status, 403);

      // d) Tokyo's authorized payouts:write vk_live_* key -> 200 OK!
      const pAuthorized = await fetch(`${facTokyo.issuerUrl}/v1/payouts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mchTokyo.apiKey}` },
        body: JSON.stringify({ service: 'tokyo-robotics-api', destinationAccount: 'acct_tokyo_1', rail: 'stripe', currency: 'USD' }),
      });
      assert.equal(pAuthorized.status, 200);
      assert.equal(facTokyo.ledger.verifyIntegrity().balanced, true);
    } finally {
      gateSrv.close();
      euSrv.close();
      tokyoSrv.close();
      origin.close();
      facEU.ledger.close();
      facTokyo.ledger.close();
    }
  });
});
