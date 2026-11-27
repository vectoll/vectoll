# RFC-0001: Vectoll Core Wire Protocol & Receipt Specification (v0.1)

* **RFC ID:** RFC-0001
* **Status:** Draft Standard (Implemented in v0.1)
* **Version:** `vectoll/0.1`
* **Updated:** November 2026
* **Authors:** Vectoll Core Engineering

---

## 1. Abstract

This document specifies the normative HTTP wire protocol for **Vectoll v0.1**, defining:
1. Service and route discovery via `/.well-known/vectoll.json`.
2. Human vs. Autonomous Agent traffic classification rules.
3. Canonical HTTP request binding (`reqHash`) using `SHA-256`.
4. The `HTTP 402 Payment Required` challenge format and bidirectional compatibility with **x402 V2** headers (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`).
5. The **Vectoll Receipt Token (`vrt1`)** compact Ed25519 cryptographic token format and offline verification algorithm.
6. The **Model Context Protocol (MCP)** JSON-RPC 2.0 metering envelope exposed at `/mcp`.

---

## 2. Terminology & Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, and **MAY** in this document are to be interpreted as described in BCP 14 (RFC 2119 / RFC 8174).

* **Origin:** Upstream HTTP service, website, REST API, or MCP tool backend protected by Vectoll.
* **Gate (`vectoll-gate`):** Edge reverse proxy enforcing classification, challenge emission, local Ed25519 receipt verification, and replay prevention.
* **Facilitator (`vectoll-facilitator`):** Clearing engine managing prepaid agent floats, escrow locks, multi-rail settlement, and `vrt1` signing.
* **Agent:** Autonomous software client consuming Origin resources on behalf of a human or organization.
* **Base64url:** URL-safe Base64 encoding **without** `=` padding characters per RFC 4648 Section 5.

---

## 3. Discovery Manifest (`/.well-known/vectoll.json`)

Every Vectoll-enabled domain **MUST** serve a JSON document (`Content-Type: application/json`) at `GET /.well-known/vectoll.json` (or configured `discovery_path`) without requiring payment.

### 3.1 Normative Example
```json
{
  "vectollVersion": "0.1",
  "x402Version": 2,
  "service": {
    "name": "acme-hospitality-api",
    "description": "Real-time Kampala hotel inventory and instant booking API",
    "mcpEndpoint": "/mcp"
  },
  "settlement": {
    "facilitatorUrl": "https://facilitator.vectoll.com",
    "jwksUrl": "https://facilitator.vectoll.com/.well-known/jwks.json",
    "facilitatorPublicKey": "MCowBQYDK2VwAyEA...",
    "facilitatorKid": "fac-ed25519-1",
    "defaultCurrency": "UGX",
    "defaultDecimals": 0,
    "acceptedRails": ["momo", "airtel_money", "mpesa", "x402_usdc", "stripe", "voucher"]
  },
  "routes": [
    {
      "path": "/api/v1/rooms/availability",
      "method": "GET",
      "pricingMode": "fixed",
      "amount": 50,
      "currency": "UGX",
      "decimals": 0,
      "settlementMode": "instant",
      "requireMandate": false,
      "humanPassthrough": true,
      "mcpTool": {
        "name": "check_room_availability",
        "description": "Query live room inventory and UGX nightly rates"
      }
    }
  ]
}
```

---

## 4. Traffic Classification (Human Passthrough vs. Agent Metering)

For routes configured with `human_passthrough: true`:
1. If the request carries any Vectoll/x402 header (`PAYMENT-SIGNATURE`, `X-Vectoll-Agent-Id`, `X-Vectoll-Mode: agent`) or targets `/mcp`, the Gate **MUST** classify the caller as an **Agent**.
2. If the `User-Agent` matches known autonomous agent, crawler, headless browser, or programmatic HTTP client tokens (`GPTBot`, `ClaudeBot`, `PerplexityBot`, `Google-Extended`, `CCBot`, `VectollAgent`, `MCP-Client`, `LangChain`, `CrewAI`, `python-httpx`, `python-requests`, `curl/`, `Go-http-client`, `node`, `undici`), the Gate **MUST** classify the caller as an **Agent**.
3. A caller is granted **Human Passthrough** ONLY when **all** of the following hold:
   * `human_passthrough` is `true` on the matched route;
   * `Accept` header explicitly includes `text/html`;
   * `User-Agent` matches standard interactive browser families (`Mozilla/5.0 ...`) and contains no bot/headless markers;
   * Browser Fetch Metadata headers (`Sec-Fetch-Dest: document`, `Sec-Fetch-Mode: navigate`) or verified session cookies are present (configurable strictness: `standard` | `strict`).
4. For routes with `human_passthrough: false` (default for `/api/*` and `/mcp`), **all** unverified requests receive an `HTTP 402` challenge regardless of `User-Agent`.

---

## 5. Canonical Request Hashing (`reqHash`)

To prevent an attacker or misbehaving agent from reusing a `vrt1` token minted for cheap Route A against expensive Route B, or swapping a `POST` request body after obtaining a receipt, every challenge and receipt is cryptographically bound to `reqHash`.

### 5.1 Construction Algorithm
Given:
* `method`: Uppercase ASCII HTTP method (e.g., `"GET"`, `"POST"`).
* `target`: Exact request path plus raw query string if non-empty (e.g., `"/api/v1/rooms/availability?adults=2"`, or `"/api/v1/rooms/book"` when query is empty).
* `body`: Raw octets of the HTTP request body (empty byte sequence `""` for `GET`/`HEAD` or empty `POST`).

Compute:
```text
body_hash_hex = lowercase_hex(SHA-256(body))
canonical_str = method + "\n" + target + "\n" + body_hash_hex
req_hash      = "sha256:" + lowercase_hex(SHA-256(UTF8(canonical_str)))
```

*Note:* For an empty body (`0` bytes), `body_hash_hex` is always `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

---

## 6. HTTP `402` Challenge & x402 V2 Header Mapping

When an Agent requests a metered route without a valid `PAYMENT-SIGNATURE`, the Gate **MUST** respond with:

* **HTTP Status:** `402 Payment Required`
* **`Content-Type`:** `application/json; charset=utf-8`
* **`Cache-Control`:** `no-store`
* **`PAYMENT-REQUIRED`:** `<base64url(UTF8(JSON(challenge)))>`
* **`WWW-Authenticate`:** `Vectoll realm="<service>", challengeId="<challengeId>", facilitator="<facilitatorUrl>"`

### 6.1 Challenge Payload Schema
```json
{
  "x402Version": 2,
  "protocol": "vectoll/0.1",
  "challengeId": "chg_9f82c1e04b7d4e12a3091bc8",
  "service": "acme-hospitality-api",
  "resource": "/api/v1/rooms/availability",
  "method": "GET",
  "reqHash": "sha256:6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
  "amount": 50,
  "currency": "UGX",
  "decimals": 0,
  "settlementMode": "instant",
  "requireMandate": false,
  "hitlThreshold": null,
  "facilitatorUrl": "http://localhost:4021",
  "facilitatorKid": "fac-key-1",
  "acceptedRails": ["momo", "airtel_money", "x402_usdc", "voucher"],
  "issuedAt": 1795753800,
  "expiresAt": 1795753860
}
```

### 6.2 Monetary Integer Representation
Floating-point numbers **MUST NOT** appear in `amount` or `hitlThreshold`. All values are non-negative integers in currency minor units defined by `decimals`:
* `UGX`: `decimals = 0` (`50` = 50 UGX)
* `KES`, `NGN`, `GHS`: `decimals = 2` (`15000` = 150.00 KES)
* `USD`, `EUR`, `USDC`: `decimals = 6` (`2000` = 0.002000 USD / $0.002)

---

## 7. Vectoll Receipt Token (`vrt1`)

Upon clearing payment (instant float debit or escrow lock), the Facilitator issues a compact, offline-verifiable **Vectoll Receipt Token (`vrt1`)**.

### 7.1 Wire Format
```text
vrt1.<payload_b64url>.<signature_b64url>
```
Where:
1. `vrt1` is the fixed version/algorithm prefix pinning **Ed25519 (RFC 8032 PureEdDSA)** exclusively. Algorithms are never negotiated inside the untrusted header, eliminating JWT `alg: none` and HMAC/asymmetric key-confusion vulnerabilities.
2. `payload_b64url = base64url(UTF8(JSON(claims)))`.
3. `signing_input = ASCII("vrt1." + payload_b64url)`.
4. `signature_b64url = base64url(Ed25519.Sign(facilitator_private_key, signing_input))` (`64` raw signature bytes → `86` base64url characters).

Because the signature is computed directly over the exact ASCII bytes `"vrt1." + payload_b64url`, JSON key ordering differences across Go, Python, Rust, and TypeScript parsers **cannot** invalidate a signature.

### 7.2 Normative VRT Claims
| Claim | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `v` | `1` | **MUST** | Schema version (`1`). |
| `jti` | `string` | **MUST** | Globally unique receipt ID (`vrt_<hex>`), used for single-use replay rejection. |
| `kid` | `string` | **MUST** | Facilitator Ed25519 key identifier matching JWKS / config. |
| `iss` | `string` | **MUST** | Facilitator issuer URI or identifier. |
| `sub` | `string` | **MUST** | Paying Agent identifier (`did:key:z6Mk...`). |
| `aud` | `string` | **MUST** | Target `service.name` from `vectoll.yaml`. |
| `chg` | `string` | **MUST** | Exact `challengeId` from the `HTTP 402` challenge. |
| `req` | `string` | **MUST** | Exact `reqHash` (`sha256:...`) of the authorized HTTP request. |
| `amt` | `integer` | **MUST** | Settled integer minor units in `cur`. |
| `cur` | `string` | **MUST** | Merchant target currency code (`UGX`, `USD`, etc.). |
| `dec` | `integer` | **MUST** | Exponent (`0`–`18`) corresponding to `cur`. |
| `rail` | `string` | **MUST** | Rail adapter identifier (`momo`, `x402_usdc`, `stripe`, `voucher`, etc.). |
| `mode` | `string` | **MUST** | `"instant"` or `"escrow"`. |
| `esc` | `string` | **MAY** | Escrow record ID when `mode == "escrow"`. |
| `iat` | `integer` | **MUST** | Issuance timestamp (Unix epoch seconds). |
| `exp` | `integer` | **MUST** | Expiration timestamp (Unix epoch seconds, default `iat + 60`). |

### 7.3 Gate Verification Procedure (Normative)
When an Agent retries its request carrying `PAYMENT-SIGNATURE: vrt1.<payload>.<sig>` (or `Authorization: Vectoll vrt1.<payload>.<sig>`), the Gate **MUST** execute these steps in order:
1. Check prefix equals `"vrt1."` and split into exact 3 dot-separated segments.
2. Decode `signature_b64url` (`64` bytes). Verify `Ed25519.Verify(pubKey[kid], ASCII("vrt1." + payload_b64url), sig)`. If invalid, reject immediately with `402` (`ERR_INVALID_RECEIPT_SIGNATURE`).
3. Parse JSON claims from `base64urlDecode(payload_b64url)`.
4. Verify `claims.v === 1` and `claims.aud === config.service.name`.
5. Verify `now <= claims.exp + clockSkewSec` (default `clockSkewSec = 5`).
6. Compute `actualReqHash` on the incoming HTTP request (`method`, `target`, `body`). Verify constant-time equality `claims.req === actualReqHash`. If mismatched, reject with `402` (`ERR_REQUEST_HASH_MISMATCH`).
7. Verify `claims.amt >= routePrice` and `claims.cur === routeCurrency`.
8. Atomically check and insert `claims.jti` into the replay store with TTL `(claims.exp - now + 60)s`. If `claims.jti` already exists, reject with `402` (`ERR_RECEIPT_REPLAYED`).
9. Proxy the request to Origin with `X-Vectoll-Verified: true`, `X-Vectoll-Receipt-Id`, `X-Vectoll-Agent-Id`, `X-Vectoll-Paid-Amount`, and `X-Vectoll-Rail` (stripping any untrusted client-supplied `X-Vectoll-Verified` headers first!).
10. Return Origin's response to the Agent with header `PAYMENT-RESPONSE: <base64url(JSON(settlementSummary))>`.

---

## 8. MCP Metering Envelope (`POST /mcp`)

`vectoll-gate` natively exposes a JSON-RPC 2.0 Model Context Protocol endpoint at `/mcp`:
* `initialize` and `tools/list` are served **free of charge** so MCP clients (Claude Desktop, Cursor, LangChain, custom agents) can discover tool schemas and per-call pricing metadata (`_meta.vectollPricing`).
* `tools/call` maps the tool `name` and `arguments` to the underlying Origin HTTP route (`GET` query params or `POST` JSON body).
* For a paid tool:
  * If `PAYMENT-SIGNATURE` HTTP header (or `_meta.paymentSignature` inside JSON-RPC `params`) is absent, Gate returns `HTTP 402` with `PAYMENT-REQUIRED` computed over the exact `/mcp` request `reqHash` (or underlying tool invocation).
  * Once retried with a valid `vrt1`, Gate invokes the Origin endpoint, wraps the structured response into an MCP `CallToolResult` (`content: [{ type: "text", text: ... }]`), and attaches `PAYMENT-RESPONSE`.
