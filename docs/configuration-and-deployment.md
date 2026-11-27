# Configuration Reference (`vectoll.yaml`) & Deployment Runbook

## 1. Simple Project Config (Recommended — 6 Lines)

For 95% of projects, `vectoll.yaml` only needs your app's `origin` URL and `routes` with human-readable prices:

```yaml
origin: "http://127.0.0.1:3000"

routes:
  GET /api/search: "$0.005"
  POST /api/generate: "$0.02"
  GET /articles/*:
    price: "$0.001"
    browsers: "free"   # Humans browse free; AI agents & scrapers pay $0.001
  POST /api/reserve:
    price: "$250.00"
    mode: "escrow"
    approve_above: "$200.00" # Pause for 1-tap human approval >= $200
```

Supported price formats include `"$0.005"`, `"0.02 USDC"`, `"€1.50"`, `"£0.50"`, `"₹10"`, `"¥20"`, `"50 UGX"`, `"10 KES"`, and `"free"`. All 9 global settlement rails and `/mcp` auto-wrapping are enabled automatically unless overridden.

---

## 2. Full Explicit `vectoll.yaml` Reference (Advanced)

```yaml
version: "1.0"

service:
  name: "acme-hospitality-api"            # Unique audience (`aud`) verified in VRT receipts
  description: "Kampala Hotel Availability & Instant Booking API"
  origin: "http://127.0.0.1:8080"         # Upstream service protected by vectoll-gate
  listen: ":4020"                         # Gate listen address
  discovery_path: "/.well-known/vectoll.json"
  enable_mcp: true                        # Exposes JSON-RPC 2.0 MCP server at /mcp

security:
  rate_limit_rps: 50                      # Per-IP requests per second burst protection
  max_body_bytes: 2097152                 # 2 MiB max buffered body for SHA-256 binding
  challenge_ttl_seconds: 60               # Challenge & receipt expiration window

settlement:
  facilitator_url: "http://127.0.0.1:4021"
  facilitator_kid: "fac-ed25519-dev-1"
  # Base64url raw 32-byte Ed25519 public key (or fetched automatically from facilitator JWKS)
  facilitator_public_key: ""
  default_currency: "UGX"
  default_decimals: 0
  accepted_rails:
    - "momo"
    - "airtel_money"
    - "mpesa"
    - "x402_usdc"
    - "stripe"
    - "voucher"

routes:
  - path: "/api/v1/rooms/availability"
    method: "GET"
    price: 50                             # 50 UGX minor units
    currency: "UGX"
    decimals: 0
    settlement_mode: "instant"
    human_passthrough: true               # Browsers pass free; AI agents & scrapers pay 50 UGX
    mcp_tool: "check_room_availability"
    mcp_description: "Check live hotel room availability and nightly UGX rates"

  - path: "/api/v1/rooms/book"
    method: "POST"
    price: 550000                         # 550,000 UGX reservation deposit
    currency: "UGX"
    decimals: 0
    settlement_mode: "escrow"             # Funds held in escrow until booking confirmed
    require_mandate: true                 # Requires Principal-signed vsm1 Spend Mandate
    hitl_threshold: 500000                # Triggers WhatsApp/Console human approval >= 500k UGX
    human_passthrough: false
    mcp_tool: "book_hotel_room"
    mcp_description: "Book a room with mandate-backed escrow protection"
```

---

## 2. Environment Variables

| Variable | Component | Default | Description |
| :--- | :--- | :--- | :--- |
| `VECTOLL_CONFIG` | Gate / Edge | `./vectoll.yaml` | Path to gateway configuration file. |
| `VECTOLL_GATE_PORT` | Gate | `4020` | Override HTTP listen port for `vectoll-gate`. |
| `VECTOLL_FACILITATOR_PORT` | Facilitator | `4021` | HTTP listen port for `vectoll-facilitator`. |
| `VECTOLL_CONSOLE_PORT` | Console | `4022` | HTTP listen port for `vectoll-console`. |
| `VECTOLL_DB_PATH` | Facilitator | `./data/vectoll.sqlite` | SQLite WAL ledger database path (`:memory:` for ephemeral tests). |
| `VECTOLL_FACILITATOR_SEED` | Facilitator | Auto-generated | Hex or base64url 32-byte Ed25519 private seed for deterministic signing. |
| `VECTOLL_FACILITATOR_KID` | Facilitator | `fac-key-1` | Key identifier advertised in JWKS and `vrt1` tokens. |
| `VECTOLL_FEE_BPS` | Facilitator | `150` (`1.5%`) | Facilitator clearing fee in basis points (`0` for zero-fee self-hosting). |
| `VECTOLL_ADMIN_KEY` | Facilitator | unset (dev) | Optional admin Bearer token protecting HITL decisions & payouts in prod. |
| `VECTOLL_HITL_WEBHOOK_URL` | Facilitator | unset | Outbound webhook URL (Slack, WhatsApp bridge, n8n) for HITL alerts. |

---

## 3. Production Deployment Topologies

### 3.1 Docker Compose (Recommended Self-Hosted Stack)
```bash
docker compose up --build -d
```
Starts `vectoll-facilitator` (with persistent SQLite volume), `vectoll-gate` (compiled static Go binary), `vectoll-console`, and reference origin in an isolated bridge network. Origin listens only on the internal container network so external callers cannot bypass `vectoll-gate`.

### 3.2 Bare-Metal / Systemd with Go `vectoll-gate`
```bash
cd services/gate && go build -o /usr/local/bin/vectoll-gate ./cmd/vectoll-gate
vectoll-gate --config /etc/vectoll/vectoll.yaml
```
Place TLS termination (Caddy, Nginx, or Cloudflare Tunnel) in front of `:4020`, and bind your upstream application strictly to `127.0.0.1:8080`.

### 3.3 Serverless Edge (`@vectoll/edge` on Cloudflare Workers)
Use `createVectollEdgeMiddleware` from `@vectoll/edge` to enforce `402` challenges and WebCrypto Ed25519 `vrt1` verification directly inside Cloudflare Workers, Deno Deploy, or Vercel Edge Middleware before requests ever reach your origin region.
