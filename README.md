<div align="center">

```text
██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██╗     ██╗     
██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██║     ██║     
██║   ██║█████╗  ██║        ██║   ██║   ██║██║     ██║     
╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██║     ██║     
 ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝███████╗███████╗
  ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚══════╝╚══════╝
```

# Vectoll

**Add AI Agent Metering & Global Payments to Any API, Website, or MCP Server in 3 Lines**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-0F172A.svg)](./LICENSE)
[![Release: v1.0.0](https://img.shields.io/badge/Release-v1.0.0-10B981.svg)](./CHANGELOG.md)
[![x402 Compatible](https://img.shields.io/badge/x402-V2_Compatible-2563EB.svg)](./docs/spec/RFC-0001-core-protocol.md)
[![MCP Native](https://img.shields.io/badge/MCP-Auto--Wrapper-7C3AED.svg)](./docs/integration-guide.md)

[**Integration Guide**](./docs/integration-guide.md) · [**5-Minute Quickstart**](./docs/developer-quickstart.md) · [**Configuration**](./docs/configuration-and-deployment.md) · [**Architecture**](./docs/architecture.md) · [**Protocol RFCs**](./docs/spec/RFC-0001-core-protocol.md)

</div>

---

## What is Vectoll?

AI agents scrape websites and hammer APIs without seeing ads or completing human checkouts. **Vectoll** lets you keep your website **100% free for human browsers** while charging autonomous AI agents and MCP clients per request (`"$0.005"`, `"€0.02"`, `"¥5"`) across **Stripe, USDC (`x402`), SEPA Instant, FedNow/ACH, PIX, UPI, PayNow, M-Pesa, MTN MoMo, and Enterprise Vouchers**.

You do **not** need to reorganize your project. Integrate Vectoll in whichever way matches your stack:

---

## Add Vectoll to Your Project in 60 Seconds

### Option 1: Node.js / Express Middleware (Runs on Your Existing Port)
```typescript
import express from 'express';
import { vectollMiddleware } from '@vectoll/server';

const app = express();

app.use(vectollMiddleware({
  routes: {
    'GET /api/search': '$0.005',
    'GET /blog/*': { price: '$0.001', browsers: 'free' }, // Humans browse free; AI bots pay $0.001
  },
}));

app.get('/api/search', (req, res) => res.json({ results: ['...'] }));
app.listen(3000);
```

### Option 2: Next.js / Hono / Cloudflare Workers (1-Line Wrapper)
```typescript
import { withVectoll } from '@vectoll/server';

export const GET = withVectoll('$0.005', async (req, receipt) => {
  return Response.json({ data: 'Verified output', paidBy: receipt?.sub });
});
```

### Option 3: Python FastAPI / Starlette (ASGI Middleware)
```python
from fastapi import FastAPI
from vectoll.asgi import VectollMiddleware

app = FastAPI()
app.add_middleware(
    VectollMiddleware,
    facilitator_url="http://localhost:4021",
    routes={"GET /api/predict": "$0.01", "GET /docs/*": {"price": "$0.001", "browsers": "free"}},
)
```

### Option 4: Zero-Code Proxy for *Any* App (Go, Rust, PHP, Rails, WordPress, Docker)
Drop a **6-line `vectoll.yaml`** in your project (or run `npx @vectoll/cli proxy http://localhost:3000 --route "GET /api/*=$0.005"` with zero files):

```yaml
origin: "http://localhost:3000"

routes:
  GET /api/search: "$0.005"
  POST /api/summarize: "$0.02"
  GET /articles/*: { price: "$0.001", browsers: "free" }
```
*(Every route is also automatically exposed as a metered **MCP Tool** at `/mcp`!)*

---

## Consume Any Vectoll API from an AI Agent (3 Lines)

```typescript
import { generateKeyPair } from '@vectoll/core';
import { VectollAgentClient } from '@vectoll/sdk';

const agent = new VectollAgentClient({ agentKeyPair: generateKeyPair(), preferredRail: 'x402_usdc' });
await agent.topUp({ amount: '$5.00', facilitatorUrl: 'http://localhost:4021' });

// Automatically negotiates HTTP 402 -> Ed25519 receipt -> retries in <15ms!
const res = await agent.fetch('http://localhost:4020/api/search?q=vectoll');
```

*(Full Python agent client included in [`sdks/python`](./sdks/python/) — see the [Integration Guide](./docs/integration-guide.md).)*

---

## Packages in This Monorepo

| Package | Role |
| :--- | :--- |
| [`@vectoll/server`](./packages/server/) | Drop-in middleware for **Express, Node HTTP, Next.js, Hono, Cloudflare Workers, Bun & Deno**. |
| [`@vectoll/ai-sdk`](./packages/ai-sdk/) | Turnkey AI Agent Toolkit for **OpenAI, Anthropic, Gemini, Vercel AI SDK & LangChain.js** with session budget guards. |
| [`@vectoll/sdk`](./packages/sdk-ts/) | TypeScript AI Agent & MCP client (`VectollAgentClient`) with auto-`402` retry & Spend Mandate guards. |
| [`sdks/python`](./sdks/python/) | Python `vectoll` Agent client + `vectoll.asgi.VectollMiddleware` for **FastAPI & Starlette**. |
| [`@vectoll/cli`](./packages/cli/) | CLI (`vectoll init`, `vectoll proxy`, `vectoll dev`, `vectoll simulate`, `vectoll keygen`). |
| [`services/gate`](./services/gate/) | Standalone high-throughput **Go** reverse proxy (`vectoll-gate`) & `/mcp` server (`<0.3ms` Ed25519 verify). |
| [`@vectoll/edge`](./packages/edge/) | Web-standard Fetch reverse proxy & interactive `/mcp` browser inspector. |
| [`@vectoll/facilitator`](./packages/facilitator/) | Self-hostable `node:sqlite` double-entry clearing engine, Escrow, HITL guardrails & 23-currency FX. |
| [`@vectoll/adapters`](./packages/adapters/) | 9 global payment rails (`x402_usdc`, `stripe`, `sepa_instant`, `ach_fednow`, `pix_upi`, `mpesa`, `momo`, `airtel_money`, `voucher`). |
| [`@vectoll/console`](./packages/console/) | Interactive web dashboard (`:4022`) with live 402/MCP simulator, FX calculator, Escrow & HITL approvals. |
| [`@vectoll/core`](./packages/core/) | Zero-dependency Ed25519, `did:key`, `vrt1` receipts, `vsm1` Spend Mandates, x402 V2 codec & YAML parser. |

---

## Try It Locally Right Now

```bash
pnpm install
pnpm build
pnpm test

# Run the single-port Express/Node middleware example (1 port, 0 extra servers):
node examples/express-single-port/server.mjs

# Or launch the full interactive Global Sandbox + Console UI (:4020, :4021, :4022):
pnpm dev
```

---

## Deep-Dive Documentation

* **[Integrating Into Your Project](./docs/integration-guide.md)** — Copy-paste setups for Express, Next.js, Hono, FastAPI, and Zero-Code Proxy.
* **[Configuration & Deployment](./docs/configuration-and-deployment.md)** — Simple 6-line `vectoll.yaml` up to advanced Escrow & Human-in-the-Loop guardrails.
* **[System Architecture](./docs/architecture.md)** & **[Security Threat Model](./docs/security-and-threat-model.md)**
* **[Protocol Specifications (`RFC-0001`–`0004`)](./docs/spec/RFC-0001-core-protocol.md)** & **[Open-Source Governance](./GOVERNANCE.md)**

## License

Apache License 2.0 ([`LICENSE`](./LICENSE)).
