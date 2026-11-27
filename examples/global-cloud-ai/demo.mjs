import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSpendMandate, generateKeyPair, loadVectollConfigFile } from '@vectoll/core';
import { VectollFacilitator } from '@vectoll/facilitator';
import { createNodeGateServer } from '@vectoll/edge';
import { VectollAgentClient } from '@vectoll/sdk';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const origin = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      service: 'vectoll-global-cloud-gateway',
      endpoint: req.url,
      verified: req.headers['x-vectoll-verified'] === 'true',
      paidAmount: req.headers['x-vectoll-paid-amount'],
      regions: ['us-east', 'eu-central', 'ap-northeast', 'sa-east', 'af-south'],
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

// European AI agent funded via SEPA Instant (EUR) seamlessly paying a USD-priced global endpoint!
const principal = generateKeyPair();
const agent = generateKeyPair();
const mandate = createSpendMandate({
  principalKeyPair: principal,
  agentId: agent.did,
  currency: 'EUR',
  decimals: 6,
  maxPerCall: 5_000_000, // 5.00 EUR
  maxDaily: 50_000_000,  // 50.00 EUR
});

const client = new VectollAgentClient({
  agentKeyPair: agent,
  facilitatorUrl: `http://127.0.0.1:${facPort}`,
  preferredRail: 'sepa_instant',
  walletCurrency: 'EUR',
  mandateToken: mandate.token,
});

await client.topUp({ amount: 10_000_000, currency: 'EUR', rail: 'sepa_instant' });
const { response, telemetry } = await client.fetchWithTelemetry(
  `http://127.0.0.1:${gatePort}/api/v1/intel/global-markets`,
);
console.log('Global Cloud AI Gateway (EUR SEPA -> USD):', await response.json(), telemetry);

gate.close();
facSrv.close();
origin.close();
fac.ledger.close();
