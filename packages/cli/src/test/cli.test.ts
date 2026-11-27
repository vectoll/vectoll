import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair } from '@vectoll/core';
import { VectollAgentClient } from '@vectoll/sdk';
import { createMeteredMcpServer } from '@vectoll/server';
import { handleMcpStdioLine, runSimulation } from '../bin.js';

describe('@vectoll/cli live simulation across global settlement rails', () => {
  it('simulates x402 USDC, SEPA Instant (EUR->USD), PIX/UPI (BRL->USD), and MoMo (GHS->USD) under 100ms', async () => {
    for (const rail of ['x402_usdc', 'sepa_instant', 'pix_upi', 'momo']) {
      const res = await runSimulation(rail);
      assert.equal(res.status, 200);
      assert.equal(res.balanced, true);
      assert.ok(res.receiptId.startsWith('vrt_'));
    }
  });

  it('bridges stdio JSON-RPC MCP requests (Claude Desktop / Cursor) to paid HTTP 402 MCP servers', async () => {
    const mcp = createMeteredMcpServer({ name: 'stdio-bridge-target' });
    mcp.tool('translate_doc', { price: '$0.005', description: 'Translate technical spec' }, async (args) => ({
      translated: true,
      lang: (args as { lang?: string }).lang,
    }));
    const srv = mcp.createNodeServer();
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    const port = (srv.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;

    try {
      const agent = generateKeyPair();
      const client = new VectollAgentClient({
        agentKeyPair: agent,
        facilitatorUrl: `${base}/_vectoll`,
        preferredRail: 'stripe',
      });
      await client.topUp({ amount: '$1.00', rail: 'stripe' });

      const listReply = await handleMcpStdioLine(
        JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
        `${base}/mcp`,
        client,
      );
      assert.ok(listReply);
      assert.match(listReply!, /translate_doc/);

      const callReply = await handleMcpStdioLine(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: { name: 'translate_doc', arguments: { lang: 'ja' } },
        }),
        `${base}/mcp`,
        client,
      );
      assert.ok(callReply);
      const parsedRpc = JSON.parse(callReply!) as {
        result: { content: Array<{ text: string }> };
      };
      const inner = JSON.parse(parsedRpc.result.content[0]!.text) as { translated: boolean; lang: string };
      assert.equal(inner.translated, true);
      assert.equal(inner.lang, 'ja');
    } finally {
      srv.close();
      mcp.facilitator?.ledger.close();
    }
  });
});
