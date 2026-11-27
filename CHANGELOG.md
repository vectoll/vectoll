# Changelog

All notable public releases of Vectoll are documented in this file.

## [1.0.0] - 2026-11-27

### Added
* **Prometheus / OpenMetrics Observability (`GET /metrics`):**
  * Added zero-dependency Prometheus `/metrics` exposition across `@vectoll/facilitator`, `@vectoll/edge`, and Go `vectoll-gate` tracking ledger balance invariants, pending HITL approvals, clearing latencies, and Gate traffic outcomes.
* **Adversarial Security, Fuzzing & Concurrency Audit Suite (`security-audit.test.ts`):**
  * 500+ automated adversarial tests covering single-bit token mutations across `vrt1`/`vsm1`/`vsm1p`/`vcv1`, `alg:none` and prototype-pollution payloads, request-hash collision checks, SQL parameterization, and 100-way concurrent double-spend stress testing.
* **Strict v1.0 Conformance Auditor & Badge Generator (`@vectoll/cli`):**
  * `vectoll check <url> --strict --badge ./vectoll-badge.svg` verifying 6 protocol and security invariants and generating a self-contained SVG verification badge.
* **Open-Source Technical Governance (`GOVERNANCE.md`).**

## [0.5.0] - 2026-11-27

### Added
* **`@vectoll/ai-sdk` & Python `vectoll.tools`:**
  * `VectollToolkit` auto-discovering `/.well-known/vectoll.json` or querying the Global Discovery Search API and emitting tools for OpenAI, Anthropic, Google Gemini, Vercel AI SDK, LangChain, and CrewAI with session budget guards.
* **Desktop MCP Stdio Bridge (`vectoll mcp-bridge`):**
  * Connects `stdio` JSON-RPC 2.0 MCP clients (Claude Desktop, Cursor) to paid remote HTTP 402 MCP servers.
* **Global Service Discovery Crawler & Search Index (`/v1/discovery/index` & `/v1/discovery/search`).**

## [0.4.0] - 2026-11-27

### Added
* **`RFC-0004` (`docs/spec/RFC-0004-federation-and-passkey-mandates.md`).**
* **WebAuthn / FIDO2 Hardware Passkey Spend Mandates (`vsm1p`):** NIST `P-256` (`ES256`) assertion signing and verification.
* **Multi-Tenant Merchant Isolation (`vk_live_*`):** `SHA-256`-hashed scoped API keys enforcing per-service tenant boundaries.
* **Federated Cross-Facilitator Clearing (`vfv1`) & Multi-KID JWKS.**

## [0.3.0] - 2026-11-27

### Added
* **Live Payment Rail Drivers:** `StripeLiveAdapter`, `X402EvmLiveAdapter` (Base/EVM ERC-20 `Transfer` verifier), `MpesaDarajaLiveAdapter`, `MtnMomoLiveAdapter`, `SepaInstantLiveAdapter`, `PixUpiLiveAdapter`, and HMAC/Stripe webhook verifiers.
* **Live FX Rate Oracle (`LiveFxOracle`)** with TTL cache and deviation circuit breakers.
* **Distributed HA Backends:** Zero-dependency TCP RESP2 `RedisReplayStore` (TS & Go) and `PostgresLedgerStore` (`SERIALIZABLE` DDL migration).

## [0.2.0] - 2026-11-27

### Added
* **`@vectoll/server` & Python `vectoll.asgi.VectollMiddleware`:** Single-port Express/Node middleware, `withVectoll()` Next.js/Fetch wrapper, `createMeteredMcpServer()`, and FastAPI ASGI middleware.
* **Human-Readable Pricing (`"$0.005"`) & 6-Line `vectoll.yaml`**, HTML-to-Structured JSON/Markdown agent translator, signed Facilitator webhooks, Spend Mandate revocation, and `vectoll proxy` / `vectoll check` CLI commands.

## [0.1.0] - 2026-11-27

### Added
* Core protocol specifications (`RFC-0001`–`0003`), JSON Schemas, cross-language Ed25519 test vectors, `@vectoll/core`, `@vectoll/adapters` (9 global rails, 23 currencies), `@vectoll/facilitator` (`node:sqlite` double-entry ledger), Go `vectoll-gate`, `@vectoll/edge`, `@vectoll/sdk`, Python `vectoll` SDK, `@vectoll/cli`, and `@vectoll/console`.
