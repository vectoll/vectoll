import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, loadVectollConfigFile } from '@vectoll/core';
import { VectollFacilitator } from '@vectoll/facilitator';
import { createNodeGateServer } from '@vectoll/edge';
import { VectollAgentClient } from '@vectoll/sdk';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const origin = http.createServer((_req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      corridor: 'Mombasa -> Kampala',
      equipment: '40ft High Cube',
      spotRateKes: 285_000,
      transitDays: 4,
    }),
  );
});

await new Promise((r) => origin.listen(0, '127.0.0.1', r));
const originPort = origin.address().port;

const fac = new VectollFacilitator({ dbPath: ':memory:' });
const facSrv = fac.createHttpServer();
await new Promise((r) => facSrv.listen(0, '127.0.0.1', r));
const facPort = facSrv.address().port;
fac.issuerUrl = `http://127.0.0.1:${facPort}`;

const cfg = loadVectollConfigFile(path.join(__dirname, 'vectoll.yaml'));
cfg.service.origin = `http://127.0.0.1:${originPort}`;
cfg.settlement.facilitator_url = `http://127.0.0.1:${facPort}`;
cfg.settlement.facilitator_kid = fac.keyPair.kid;

const gate = createNodeGateServer({ config: cfg, facilitatorPublicKey: fac.keyPair.publicKeyBase64Url });
await new Promise((r) => gate.listen(0, '127.0.0.1', r));
const gatePort = gate.address().port;

const agent = generateKeyPair();
const client = new VectollAgentClient({
  agentKeyPair: agent,
  facilitatorUrl: `http://127.0.0.1:${facPort}`,
  preferredRail: 'mpesa',
  walletCurrency: 'KES',
});

await client.topUp({ amount: 50_000, currency: 'KES', rail: 'mpesa' }); // 500.00 KES
const mcpOut = await client.callMcpTool(`http://127.0.0.1:${gatePort}/mcp`, 'quote_freight_lane', {
  origin: 'Mombasa',
  destination: 'Kampala',
});
console.log('Logistics Corridor MCP Sandbox:', mcpOut);

gate.close();
facSrv.close();
origin.close();
fac.ledger.close();
