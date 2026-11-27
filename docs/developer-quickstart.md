# 5-Minute Developer Quickstart

Get from zero to a live, cryptographically metered API + autonomous paying AI agent in under five minutes.

---

## 1. Install & Build Workspace

```bash
git clone https://github.com/vectoll/vectoll.git
cd vectoll
pnpm install
pnpm build
```

*(Optional Go binary build for bare-metal `vectoll-gate`):*
```bash
cd services/gate && go build -o ../../bin/vectoll-gate ./cmd/vectoll-gate && cd ../..
```

---

## 2. Run the Live End-to-End Simulation in One Command

```bash
node packages/cli/dist/bin.js simulate --rail momo
```

This boots an ephemeral Origin, Facilitator (SQLite double-entry ledger), and Gate, tops up an Agent Wallet with **MTN Mobile Money (`UGX`)**, triggers an `HTTP 402` challenge, clears a `vrt1` receipt in `< 5 ms`, verifies the Ed25519 signature at the Gate, and prints the latency breakdown and balanced ledger entries.

---

## 3. Protect Any API or Website (`vectoll.yaml`)

Initialize a gateway config in your project directory:
```bash
npx @vectoll/cli init
npx @vectoll/cli dev --config vectoll.yaml
```

* Gate Proxy: `http://localhost:4020`
* Discovery Manifest: `http://localhost:4020/.well-known/vectoll.json`
* Metered MCP Server: `http://localhost:4020/mcp`
* Facilitator API: `http://localhost:4021`
* Observability & HITL Console: `http://localhost:4022`

---

## 4. Consume Metered APIs from an AI Agent

### TypeScript (`@vectoll/sdk`)
```typescript
import { generateKeyPair, createSpendMandate } from '@vectoll/core';
import { VectollAgentClient } from '@vectoll/sdk';

const principal = generateKeyPair();
const agent = generateKeyPair();

// Principal delegates bounded spending authority to the Agent
const mandate = createSpendMandate({
  principalKeyPair: principal,
  agentId: agent.did,
  currency: 'UGX',
  decimals: 0,
  maxPerCall: 100_000,
  maxDaily: 500_000,
  allowedServices: ['*'],
  allowedRails: ['momo', 'x402_usdc'],
});

const client = new VectollAgentClient({
  agentKeyPair: agent,
  facilitatorUrl: 'http://localhost:4021',
  preferredRail: 'momo',
  mandate,
});

// Top up agent float via MTN MoMo sandbox
await client.topUp({ amount: 50_000, currency: 'UGX', decimals: 0, rail: 'momo' });

// Automatically handles HTTP 402 -> Mandate Check -> VRT Receipt -> Verified 200 OK!
const res = await client.fetch('http://localhost:4020/api/v1/rooms/availability?city=Kampala');
console.log(await res.json());
```

### Python (`vectoll`)
```python
from vectoll import AgentWallet, SpendMandate, VectollClient

principal = AgentWallet.generate()
agent = AgentWallet.generate()

mandate = SpendMandate.issue(
    principal=principal,
    agent_did=agent.did,
    currency="UGX",
    decimals=0,
    max_per_call=100_000,
    max_daily=500_000,
)

client = VectollClient(
    wallet=agent,
    facilitator_url="http://localhost:4021",
    preferred_rail="momo",
    mandate=mandate,
)

client.top_up(amount=50_000, currency="UGX", decimals=0, rail="momo")
data = client.get_json("http://localhost:4020/api/v1/rooms/availability")
print(data)
```

---

## 5. Authoring a Custom Payment Rail Adapter

Implement `VectollRailAdapter` from `@vectoll/adapters` (`quote`, `authorize`, `settle`, `payout`) and register it on your Facilitator instance with `facilitator.registerAdapter(new MyRegionalBankAdapter())`. Every route listing your rail ID in `accepted_rails` immediately supports it.
