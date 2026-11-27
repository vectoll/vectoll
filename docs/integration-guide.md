# Integrating Vectoll Into Your Project

Vectoll is designed so you can add AI agent metering and global payments to **any existing project** without restructuring your codebase or managing extra servers unless you want to.

Choose whichever pattern fits your stack:

| Stack | Integration Method | Extra Servers Needed? |
| :--- | :--- | :--- |
| **Express / Connect / Fastify / Node HTTP** | `vectollMiddleware({...})` (`@vectoll/server`) | **None** (runs on your app's own port!) |
| **Next.js / Hono / Cloudflare Workers / Bun** | `withVectoll('$0.005', handler)` (`@vectoll/server`) | Uses Hosted or Self-Hosted Facilitator URL |
| **Python (FastAPI / Starlette / Litestar)** | `VectollMiddleware` (`vectoll.asgi`) | Uses Hosted or Self-Hosted Facilitator URL |
| **Any Language / Docker / WordPress / Legacy App** | `vectoll proxy` CLI or 6-line `vectoll.yaml` | Sidecar Gate (`vectoll-gate`) |

---

## 1. Node.js & Express (Single Port — Zero Extra Servers)

Install `@vectoll/server` and mount `vectollMiddleware`. In local/single-node mode, Vectoll embeds the SQLite clearing engine directly under `/_vectoll/*` on your existing port:

```typescript
import express from 'express';
import { vectollMiddleware } from '@vectoll/server';

const app = express();

app.use(
  vectollMiddleware({
    name: 'my-saas-api',
    // Omit facilitatorUrl for embedded single-port mode, or set in production:
    // facilitatorUrl: process.env.VECTOLL_FACILITATOR_URL,
    routes: {
      'GET /api/search': '$0.005',
      'POST /api/generate': '$0.02',
      'GET /docs/*': { price: '$0.001', browsers: 'free' },
    },
  }),
);

app.get('/api/search', (req, res) => {
  res.json({ results: ['...'], paidByAgent: (req as any).vectoll?.sub });
});

app.listen(3000);
```

Your existing `http://localhost:3000` now automatically serves:
* `GET /.well-known/vectoll.json` (agent discovery manifest)
* `HTTP 402` challenges + `<0.3ms` Ed25519 receipt verification on your routes
* Free passthrough for human browsers on `browsers: 'free'` routes

---

## 2. Next.js App Router, Hono & Cloudflare Workers

Wrap any Web `Request -> Response` route handler with `withVectoll`:

```typescript
// app/api/intel/route.ts
import { withVectoll } from '@vectoll/server';

export const GET = withVectoll(
  {
    price: '$0.005',
    service: 'my-nextjs-app',
    facilitatorUrl: process.env.VECTOLL_FACILITATOR_URL!,
  },
  async (request, receipt) => {
    return Response.json({
      data: 'Verified structured output',
      paidBy: receipt?.sub,
      rail: receipt?.rail,
    });
  },
);
```

---

## 3. Python (FastAPI, Starlette, Litestar)

Add `VectollMiddleware` (`vectoll.asgi`) to any ASGI application:

```python
from fastapi import FastAPI, Request
from vectoll.asgi import VectollMiddleware

app = FastAPI()

app.add_middleware(
    VectollMiddleware,
    service_name="my-python-api",
    facilitator_url="http://localhost:4021",  # or https://facilitator.vectoll.com
    routes={
        "GET /api/predict": "$0.01",
        "GET /articles/*": {"price": "$0.002", "browsers": "free"},
    },
)

@app.get("/api/predict")
async def predict(request: Request):
    receipt = request.scope.get("vectoll_receipt")
    return {"prediction": 0.982, "paid_by": receipt["sub"] if receipt else "human"}
```

---

## 4. Zero-Code Proxy for Any App (Go, Rust, PHP, Rails, WordPress, Docker)

If you don't want to touch your application code at all:

### Option A: Zero Config Files (One CLI Command)
Point `vectoll proxy` at your running app port:
```bash
npx @vectoll/cli proxy http://localhost:3000 \
  --route "GET /api/*=$0.005" \
  --route "GET /blog/*=$0.001:free"
```

### Option B: 6-Line `vectoll.yaml`
Run `npx @vectoll/cli init` in your project folder to create a minimal `vectoll.yaml`:
```yaml
origin: "http://localhost:3000"

routes:
  GET /api/search: "$0.005"
  POST /api/generate: "$0.02"
  GET /blog/*:
    price: "$0.001"
    browsers: "free"
```
Start with `npx @vectoll/cli dev` (or run the single static Go binary `vectoll-gate --config vectoll.yaml` in production). Every route in `vectoll.yaml` is also automatically exposed as a paid **MCP Tool** at `/mcp`!

---

## 5. Calling Any Vectoll-Protected Endpoint from an AI Agent

### TypeScript (`@vectoll/sdk`)
```typescript
import { generateKeyPair } from '@vectoll/core';
import { VectollAgentClient } from '@vectoll/sdk';

const client = new VectollAgentClient({
  agentKeyPair: generateKeyPair(),
  preferredRail: 'stripe',       // or 'x402_usdc', 'sepa_instant', 'pix_upi', 'mpesa', 'momo'
  maxPricePerCall: '$0.05',      // hard safety cap per request
});

await client.topUp({ amount: '$5.00', facilitatorUrl: 'http://localhost:4021' });
const res = await client.fetch('http://localhost:4020/api/search?q=vectoll');
console.log(await res.json());
```

### Python (`vectoll`)
```python
from vectoll import AgentWallet, VectollClient

client = VectollClient(
    wallet=AgentWallet.generate(),
    preferred_rail="x402_usdc",
    facilitator_url="http://localhost:4021",
)

client.top_up("$5.00")
print(client.get_json("http://localhost:4020/api/search?q=vectoll"))
```
