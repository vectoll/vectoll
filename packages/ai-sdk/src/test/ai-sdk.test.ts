import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { generateKeyPair, parseVectollConfig } from '@vectoll/core';
import { createNodeGateServer } from '@vectoll/edge';
import { VectollFacilitator } from '@vectoll/facilitator';
import { VectollAgentClient } from '@vectoll/sdk';
import { VectollToolkit } from '../index.js';

function listenEphemeral(srv: http.Server): Promise<number> {
  return new Promise((resolve) => {
    srv.listen(0, '127.0.0.1', () => resolve((srv.address() as { port: number }).port));
  });
}

describe('@vectoll/ai-sdk Global Discovery Search, Tool Adapters & Session Budget Guard', () => {
  it('discovers unknown APIs from registry search, emits OpenAI/Anthropic/Gemini/Vercel/LangChain tools, pays automatically & enforces session budget', async () => {
    const origin = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          forecast: 'Solar Flare Class M2',
          verified: req.headers['x-vectoll-verified'] === 'true',
        }),
      );
    });
    const originPort = await listenEphemeral(origin);

    const fac = new VectollFacilitator({ dbPath: ':memory:' });
    const facSrv = fac.createHttpServer();
    const facPort = await listenEphemeral(facSrv);
    fac.issuerUrl = `http://127.0.0.1:${facPort}`;

    const gateCfg = parseVectollConfig(`
name: "space-weather-oracle"
origin: "http://127.0.0.1:${originPort}"
facilitator: "${fac.issuerUrl}"
routes:
  GET /api/solar:
    price: "$0.01"
    mcp: "get_solar_forecast"
    description: "Real-time space weather & geomagnetic telemetry"
`);
    const gateSrv = createNodeGateServer({
      config: gateCfg,
      facilitatorPublicKey: fac.keyPair.publicKeyBase64Url,
    });
    const gatePort = await listenEphemeral(gateSrv);
    const gateUrl = `http://127.0.0.1:${gatePort}`;

    try {
      // 1. Index the domain into the Facilitator's Global Discovery Registry
      const idxRes = await fetch(`${fac.issuerUrl}/v1/discovery/index`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: gateUrl }),
      });
      assert.equal(idxRes.status, 200);

      // 2. Agent searches Global Discovery Registry for "geomagnetic" tools <= $0.05
      const agent = generateKeyPair();
      const client = new VectollAgentClient({
        agentKeyPair: agent,
        facilitatorUrl: fac.issuerUrl,
        preferredRail: 'x402_usdc',
        walletCurrency: 'USDC',
      });
      await client.topUp({ amount: '$1.00', currency: 'USDC', rail: 'x402_usdc' });

      const toolkit = await VectollToolkit.fromDiscoverySearch(
        fac.issuerUrl,
        { query: 'geomagnetic', rail: 'x402_usdc', maxPriceUsd: '$0.05' },
        { client, maxSessionBudget: '$0.025' }, // Allows 2 calls ($0.01 each), blocks 3rd ($0.03 > $0.025)!
      );

      // 3. Verify OpenAI, Anthropic, Gemini, Vercel AI & LangChain tool shapes
      assert.equal(toolkit.toOpenAiTools().length, 1);
      assert.equal(toolkit.toAnthropicTools().length, 1);
      assert.equal(toolkit.toGeminiFunctionDeclarations().length, 1);
      assert.equal(toolkit.toLangChainTools().length, 1);

      const vercelTools = toolkit.toVercelAiTools();
      const toolKey = Object.keys(vercelTools)[0]!;
      assert.match(toolKey, /space-weather-oracle_get_solar_forecast/);

      // 4. Execute Call #1 and Call #2 via Vercel AI tool wrapper -> both succeed!
      const out1 = (await vercelTools[toolKey]!.execute({ sector: 'earth-orbit' })) as {
        forecast: string;
        verified: boolean;
      };
      assert.equal(out1.verified, true);

      const out2 = await toolkit.toLangChainTools()[0]!.invoke({ sector: 'mars' });
      assert.ok(out2);
      assert.equal(toolkit.getSpendSummary().callCount, 2);

      // 5. Call #3 exceeds $0.025 session budget -> blocked BEFORE spending!
      await assert.rejects(
        () => vercelTools[toolKey]!.execute({ sector: 'jupiter' }),
        /ERR_SESSION_BUDGET_EXCEEDED/,
      );
    } finally {
      gateSrv.close();
      facSrv.close();
      origin.close();
      fac.ledger.close();
    }
  });
});
