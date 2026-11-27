# Security Architecture & STRIDE Threat Model

Autonomous payment infrastructure sits directly on the boundary between untrusted network traffic, AI agents susceptible to prompt injection, and real monetary value. This document enumerates Vectoll's security invariants, STRIDE threat matrix, and operational key-rotation procedures.

---

## 1. Core Security Invariants

1. **Pinned Signature Algorithm (`Ed25519` Only):** `vrt1` receipts, `vsm1` spend mandates, and `vcv1` enterprise vouchers hardcode RFC 8032 PureEdDSA (`Ed25519`). Token headers contain no `alg` field—eliminating algorithm-downgrade (`alg: none`) and RSA/HMAC key-confusion attacks permanently.
2. **Pre-Parse Verification:** `vectoll-gate` verifies the 64-byte Ed25519 signature over `"vrt1." + payload_b64url` *before* deserializing JSON claims. Malformed or adversarial JSON payloads from unauthenticated callers never reach business logic.
3. **Request-Method, Target & Body Binding:** Every `vrt1` binds to `reqHash = SHA256(METHOD + "\n" + TARGET + "\n" + SHA256(BODY))`. Modifying a single query parameter or JSON body byte invalidates the receipt.
4. **Header Sanitization at Gate:** Before proxying any request (human or agent) to Origin, `vectoll-gate` unconditionally strips inbound `X-Vectoll-*` headers so external clients can never spoof `X-Vectoll-Verified: true`.
5. **Serializable Ledger Isolation (`BEGIN IMMEDIATE`):** Balance checks and journal postings execute atomically inside a single write-locked transaction, eliminating Time-of-Check to Time-of-Use (TOCTOU) double-spend race conditions.

---

## 2. STRIDE Threat Matrix

| Threat Category | Attack Scenario | Mitigation in Vectoll |
| :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates a funded Agent `did:key` to drain its Facilitator float. | `POST /v1/clear` requires a fresh Ed25519 signature (`±60s` timestamp window) verified against the self-certifying `did:key` public key + unique `challengeId`. |
| **Spoofing** | External client sends `X-Vectoll-Verified: true` directly to Origin or Gate. | Origin binds to `127.0.0.1` / private Docker network behind Gate; Gate strips all client-supplied `X-Vectoll-*` headers on ingress. |
| **Tampering** | Agent buys a cheap `50 UGX` receipt for `/availability` and replays it on `/book` or alters `POST` payload. | Gate recomputes `reqHash` from live method, URI, and raw body bytes (`MaxBodyBytes` bounded) and enforces constant-time match with `vrt.req` and `vrt.aud`. |
| **Repudiation** | Merchant or agent disputes whether a tool call was authorized or fulfilled. | Double-entry SQLite/Postgres ledger stores immutable `challengeId`, `vrt.jti`, `mandateId`, signed intent digest, and fulfillment reference exportable as signed audit logs. |
| **Information Disclosure** | Attacker probes Facilitator wallet balances or merchant revenue. | Admin, ledger export, and HITL decision routes require Bearer/API key authentication (`VECTOLL_ADMIN_KEY`) in production deployments. |
| **Denial of Service** | Botnet floods Origin with unpaid scraping or huge `POST` bodies. | Gate enforces per-IP token-bucket rate limits and strict body size caps (`default 2 MiB`) at the edge *before* touching Origin compute. |
| **Elevation of Privilege (Prompt Injection)** | Malicious webpage tricks an AI agent into calling a `$5,000` API endpoint. | Client SDK + Facilitator both enforce Principal-signed `vsm1` Spend Mandates (`maxPerCall`, `maxDaily`, `allowedServices`) and trigger `PENDING_HITL` human pause above `hitlThreshold`. |
| **Replay / Double-Spend** | Agent submits the same valid `vrt1` token across 50 parallel TCP connections. | Gate's mutex/atomic JTI replay store performs test-and-set in a single critical section; only the first request succeeds (`200`), and the remaining 49 receive `402 ERR_RECEIPT_REPLAYED`. |

---

## 3. Cryptographic Key Hierarchy & Rotation Runbook

| Key Role | Format | Storage | Rotation Cadence |
| :--- | :--- | :--- | :--- |
| **Facilitator Signing Key (`kid`)** | Ed25519 Keypair | KMS / HSM / Secret Env (`VECTOLL_FACILITATOR_PRIVATE_KEY`) | Every 90 days via dual-key JWKS overlap |
| **Principal Mandate Key** | Ed25519 Keypair | User hardware Passkey / Treasury Vault | Per organization policy; instant mandate revocation via `POST /v1/mandates/:id/revoke` |
| **Agent Operational Key** | Ed25519 Keypair | Ephemeral runtime secret | Every 7–30 days; zero principal custody risk due to `vsm1` ceiling |

### Zero-Downtime Facilitator Key Rotation
1. Generate new keypair (`vectoll keygen --kid fac-key-2`).
2. Add `fac-key-2` public key alongside `fac-key-1` in Facilitator JWKS (`/.well-known/jwks.json`) and Gate trust config.
3. Wait `60s` for Gate JWKS caches to refresh.
4. Switch active signing key on Facilitator to `fac-key-2`.
5. Wait `120s` (exceeding max `vrt1` `60s` TTL), then retire `fac-key-1`.
