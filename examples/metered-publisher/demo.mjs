import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, loadVectollConfigFile } from '@vectoll/core';
import { VectollFacilitator } from '@vectoll/facilitator';
import { createNodeGateServer } from '@vectoll/edge';
import { VectollAgentClient } from '@vectoll/sdk';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const origin = http.createServer((req, res) => {
  if ((req.headers.accept ?? '').includes('text/html')) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><article><h1>Coffee Export Surge Q4 2026</h1></article></body></html>');
    return;
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      slug: req.url,
      headline: 'Coffee Export Surge Q4 2026',
      licensedToAgent: req.headers['x-vectoll-agent-id'],
      receiptId: req.headers['x-vectoll-receipt-id'],
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
  preferredRail: 'x402_usdc',
  walletCurrency: 'USDC',
});

await client.topUp({ amount: 1_000_000, currency: 'USDC', rail: 'x402_usdc' }); // $1.00 USDC
const { response, telemetry } = await client.fetchWithTelemetry(
  `http://127.0.0.1:${gatePort}/articles/coffee-exports-q4-2026`,
);
console.log('Metered Publisher Sandbox:', await response.json(), telemetry);

gate.close();
facSrv.close();
origin.close();
fac.ledger.close();
