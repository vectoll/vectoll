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
      hotel: 'Nakasero Heights Kampala',
      verified: req.headers['x-vectoll-verified'] === 'true',
      rooms: [{ type: 'Executive', ugxPerNight: 550_000, available: 3 }],
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

const principal = generateKeyPair();
const agent = generateKeyPair();
const mandate = createSpendMandate({
  principalKeyPair: principal,
  agentId: agent.did,
  currency: 'UGX',
  decimals: 0,
  maxPerCall: 600_000,
  maxDaily: 1_200_000,
});

const client = new VectollAgentClient({
  agentKeyPair: agent,
  facilitatorUrl: `http://127.0.0.1:${facPort}`,
  preferredRail: 'momo',
  mandateToken: mandate.token,
});

await client.topUp({ amount: 100_000, currency: 'UGX', rail: 'momo' });
const { response, telemetry } = await client.fetchWithTelemetry(
  `http://127.0.0.1:${gatePort}/api/v1/rooms/availability`,
);
console.log('Hospitality Kampala Sandbox:', await response.json(), telemetry);

gate.close();
facSrv.close();
origin.close();
fac.ledger.close();
