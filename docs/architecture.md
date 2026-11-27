# Vectoll System Architecture & Engineering Deep Dive

## 1. Design Philosophy

Vectoll is architected around four hard engineering constraints:
1. **Hot-Path Independence:** Origin access verification at `vectoll-gate` **must never** make a synchronous network round-trip to the Facilitator. Every receipt (`vrt1`) is verified locally via Ed25519 public keys in `< 0.5 ms`.
2. **Asynchronous Rail Decoupling:** Agents require `< 200 ms` end-to-end tool calls; Mobile Money (USSD/STK Push) and bank rails settle in `5–30 s`. Vectoll's Two-Tier Clearing Engine absorbs external rail latency via prepaid float accounts and asynchronous merchant batch sweeps.
3. **Zero Floating-Point Money:** Every ledger entry, FX quote, spend mandate, and receipt uses 64-bit safe integer minor units with explicit `currency` + `decimals`.
4. **Defense Against Compromised or Hallucinating Agents:** Principal-signed Spend Mandates (`vsm1`) + Human-in-the-Loop (HITL) thresholds ensure bounded autonomy even when an agent's LLM context is manipulated.

---

## 2. End-to-End Sequence Flows

### 2.1 Instant Metered API Call (`< 50 ms` Clearing)

```mermaid
sequenceDiagram
    autonumber
    participant A as Autonomous Agent (@vectoll/sdk)
    participant G as Vectoll Gate (Go / Edge)
    participant F as Vectoll Facilitator (SQLite WAL)
    participant O as Origin Service (SMB / API)

    A->>G: GET /api/v1/rooms/availability
    G->>G: Classify Agent + Compute reqHash (SHA-256)
    G-->>A: 402 Payment Required + PAYMENT-REQUIRED (challengeId, 50 UGX)
    A->>A: Verify Spend Mandate policy locally
    A->>F: POST /v1/clear (Signed Clearing Intent + Mandate)
    F->>F: Verify Agent Ed25519 Sig + Mandate Caps
    F->>F: Atomic Double-Entry Debit (Float -> Merchant Payable + Fee)
    F-->>A: 200 OK { vrt: "vrt1.<payload>.<ed25519_sig>" }
    A->>G: GET /api/v1/rooms/availability + PAYMENT-SIGNATURE: vrt1...
    G->>G: Offline Ed25519 Verify + reqHash Bind + Atomic JTI Replay Check
    G->>O: Proxy GET + X-Vectoll-Verified: true
    O-->>G: 200 OK (Structured Room Inventory JSON)
    G-->>A: 200 OK + PAYMENT-RESPONSE Header
```

### 2.2 High-Value Booking with Escrow & HITL Approval

```mermaid
sequenceDiagram
    autonumber
    participant A as Autonomous Agent
    participant G as Vectoll Gate
    participant F as Vectoll Facilitator
    participant H as Business Owner / Principal (Console / WhatsApp)
    participant O as Origin Booking Engine

    A->>G: POST /api/v1/rooms/book (550,000 UGX)
    G-->>A: 402 Payment Required (mode="escrow", hitlThreshold=500000)
    A->>F: POST /v1/clear (Signed Intent + Principal Mandate vsm1)
    F->>F: Amount >= 500,000 UGX -> Create PENDING_HITL Record
    F->>H: Dispatch Webhook / Console Alert (hitl_7c91e3a2)
    F-->>A: 202 Accepted { status: "PENDING_HITL", pollUrl }
    H->>F: POST /v1/hitl/hitl_7c91e3a2/decide { decision: "approve" }
    F->>F: Lock 550,000 UGX in liability:escrow + Mint vrt1
    A->>F: GET /v1/hitl/hitl_7c91e3a2
    F-->>A: 200 OK { status: "APPROVED", vrt: "vrt1..." }
    A->>G: Retry POST /api/v1/rooms/book + PAYMENT-SIGNATURE: vrt1...
    G->>O: Forward Verified Booking + X-Vectoll-Escrow-Id
    O->>F: POST /v1/escrow/:id/fulfill (Confirmation Code)
    F->>F: Release Escrow -> Merchant Payable + Fee (SETTLED)
    O-->>A: 200 OK (Confirmed Reservation)
```

---

## 3. Component Breakdown

### 3.1 `services/gate` (Go Reverse Proxy) & `packages/edge` (Fetch Worker)
* **Config Engine:** Parses `vectoll.yaml` (or JSON manifest), compiles route matchers `(method, pathPattern)`, and exposes `GET /.well-known/vectoll.json`.
* **Classifier:** Inspects `User-Agent`, `Accept`, `Sec-Fetch-*`, and `X-Vectoll-*` headers to allow zero-latency human browser browsing on `human_passthrough: true` routes while challenging bots, scrapers, and SDK clients.
* **Rate Limiter:** Per-IP token bucket guard rejecting volumetric floods before signature parsing or Origin forwarding.
* **Ed25519 Verifier & Replay Cache:** Validates `vrt1` signatures against configured or JWKS-fetched Facilitator public keys and records `jti` nonces in a TTL-evicted concurrent map (or Redis/Valkey in clustered deployments).
* **MCP Gateway (`POST /mcp`):** Translates `vectoll.yaml` routes annotated with `mcp_tool` into live MCP tools (`initialize`, `tools/list`, `tools/call`) with zero Origin code changes.

### 3.2 `packages/facilitator` (Node 24 + `node:sqlite` WAL)
* **Storage Engine:** Uses SQLite in Write-Ahead Logging (`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;`) with `BEGIN IMMEDIATE` serializable write transactions so concurrent clearing calls can never race-spend the same float balance.
* **Ledger Tables:** `accounts`, `journal_transactions`, `journal_entries`, `mandate_usage`, `escrows`, `hitl_approvals`, `payouts`, and `telemetry_events`.
* **Endpoints:**
  * `GET /health` & `GET /.well-known/jwks.json`
  * `POST /v1/wallets/topup` — Fund an agent wallet via any registered `VectollRailAdapter`
  * `GET /v1/wallets/:agentId` — Query multi-currency balances and 24h spend
  * `POST /v1/clear` — Verify agent signature + mandate and issue `vrt1` (or `202 PENDING_HITL`)
  * `GET /v1/hitl` & `POST /v1/hitl/:id/decide` — List and approve/reject HITL requests
  * `POST /v1/escrow/:id/fulfill` & `POST /v1/escrow/:id/refund` — Settle or refund escrow locks
  * `POST /v1/payouts` — Trigger merchant payout batch via Mobile Money, Stripe, or USDC
  * `GET /v1/ledger/entries` & `GET /v1/ledger/export?format=csv|json` — Audit & ERP export
  * `GET /v1/telemetry/summary` — Real-time metrics powering `vectoll-console`

### 3.3 `packages/adapters` (Multi-Rail & FX Layer)
* Deterministic integer FX rate table (`USD`, `USDC`, `EUR`, `UGX`, `KES`, `NGN`, `GHS`) with configurable spread/slippage basis points (`maxSlippageBps`) and live provider hook overrides.
* Pluggable registry (`AdapterRegistry`) supporting instant registration of first-party and third-party custom rails.
