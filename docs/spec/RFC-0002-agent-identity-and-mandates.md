# RFC-0002: Cryptographic Agent Identity, Spend Mandates & Escrow Lifecycle

* **RFC ID:** RFC-0002
* **Status:** Draft Standard (Implemented in v0.1)
* **Version:** `vectoll/0.1`
* **Updated:** November 2026

---

## 1. Abstract

Autonomous agents cannot safely hold raw bank credentials, mobile-money PINs, or unlimited API billing keys. This specification defines:
1. Self-certifying **Ed25519 Agent Identities (`did:key`)** and HTTP request authentication (RFC 9421 profile).
2. **Vectoll Spend Mandates (`vsm1`)**—AP2-aligned cryptographic delegations signed by an account Principal that enforce hard mathematical bounds on agent spending (`maxPerCall`, `maxDaily`, `allowedServices`, `allowedRails`, `hitlThreshold`).
3. The **Escrow & Human-in-the-Loop (HITL)** state machine for high-value or non-atomic commercial actions.

---

## 2. Cryptographic Agent Identity (`did:key` & JWKS)

### 2.1 Key Algorithm
All Agent and Principal identities in Vectoll v0.1 **MUST** use **Ed25519** (`32`-byte private seed, `32`-byte public key).

### 2.2 Self-Certifying `did:key` Encoding
To allow Facilitators and Gates to verify agent signatures without external central registries, Vectoll uses W3C `did:key` encoding for Ed25519 public keys:
1. Prefix the `32`-byte raw Ed25519 public key with the two-byte multicodec varint for `ed25519-pub`: `0xed, 0x01` (total `34` bytes).
2. Encode the `34`-byte buffer with **Base58-BTC** and prepend multibase prefix `z`:
   ```text
   did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
   ```
3. Enterprise deployments **MAY** additionally resolve `did:web` or HTTPS JWKS (`kty: "OKP"`, `crv: "Ed25519"`, `x: "<base64url_32_bytes>"`).

### 2.3 Authenticated Facilitator Clearing Request
When an Agent requests a `vrt1` receipt from `POST /v1/clear` on a Facilitator, the Agent **MUST** sign the clearing intent with its Ed25519 private key:

```text
agent_sig_input =
  "vectoll-clear/v1\n" +
  agentId + "\n" +
  challengeId + "\n" +
  reqHash + "\n" +
  String(maxAcceptedAmount) + "\n" +
  rail + "\n" +
  String(timestamp)
```

* Header or JSON field `agentSignature`: `base64url(Ed25519.Sign(agentPrivKey, UTF8(agent_sig_input)))`.
* The Facilitator **MUST** reject any clearing request whose `timestamp` deviates from server time by more than `±60` seconds or whose `agentId` public key fails Ed25519 signature verification.
* For direct Agent-to-Gate authentication (RFC 9421 HTTP Message Signatures profile), Agents attach `X-Vectoll-Agent-Id`, `X-Vectoll-Timestamp`, and `X-Vectoll-Signature` (alongside standard RFC 9421 `Signature-Input` and `Signature` headers).

---

## 3. Bounded Spend Mandates (`vsm1`)

A **Vectoll Spend Mandate (`vsm1`)** separates the **Principal** (human user, CFO, or treasury service that owns funds) from the **Agent** (autonomous software executing tasks). Even if an LLM agent suffers prompt injection or infinite retry loops, the Facilitator cryptographically enforces the Principal's signed ceiling.

### 3.1 Compact Wire Format
```text
vsm1.<payload_b64url>.<principal_signature_b64url>
```
* `signing_input = ASCII("vsm1." + payload_b64url)`
* `principal_signature_b64url = base64url(Ed25519.Sign(principalPrivKey, signing_input))`

### 3.2 Mandate Claims Schema
```json
{
  "v": 1,
  "mandateId": "mnd_019370f4a8c1",
  "principalId": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
  "agentId": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "currency": "UGX",
  "decimals": 0,
  "maxPerCall": 600000,
  "maxDaily": 2000000,
  "allowedServices": ["acme-hospitality-api", "kampala-freight-api"],
  "allowedRails": ["momo", "airtel_money", "x402_usdc"],
  "hitlThreshold": 500000,
  "purpose": "Q4 East Africa field team travel & logistics procurement",
  "issuedAt": 1795700000,
  "expiresAt": 1798378400
}
```

### 3.3 Normative Enforcement Rules
Both the client-side SDK (`@vectoll/sdk` / Python `vectoll`) **and** the Facilitator **MUST** enforce all seven invariants before debiting funds:
1. **Cryptographic Delegation:** `principalId` resolves to a valid Ed25519 public key that verifies `principal_signature_b64url` over `"vsm1." + payload_b64url`, AND `principalId` matches the owner of the funded wallet (or explicitly authorized delegator).
2. **Subject Match:** `mandate.agentId === clearingRequest.agentId`.
3. **Temporal Validity:** `mandate.issuedAt <= now <= mandate.expiresAt` and `mandateId` is not on the Facilitator's revocation list.
4. **Service Scope:** `mandate.allowedServices` contains `"*"` or exact `challenge.service`.
5. **Rail Scope:** `mandate.allowedRails` contains `"*"` or the selected `rail`.
6. **Per-Call Ceiling:** Normalized debit amount in `mandate.currency` **MUST** satisfy `debitAmount <= mandate.maxPerCall`.
7. **Rolling 24-Hour Cap:** `rollingSpendLast24h(mandateId) + debitAmount <= mandate.maxDaily`.

---

## 4. Escrow & Human-in-the-Loop (HITL) State Machine

High-value commerce actions (e.g., booking a hotel room for `550,000 UGX` or dispatching a truck) are non-atomic and often exceed automated comfort thresholds.

```text
                  [ Clearing Request ]
                           │
            ┌──────────────┴──────────────┐
      amount < hitl                 amount >= hitl
            │                             │
            ▼                             ▼
      ┌───────────┐               ┌──────────────┐
      │ AUTHORIZED│◄──Approve─────│ PENDING_HITL │──Reject──► [ REJECTED ]
      │ (Escrowed)│               └──────────────┘            (Zero Debit)
      └─────┬─────┘
            │
     ┌──────┼──────────────┐
     │      │              │
  Fulfill Dispute      Cancel/Expire
     │      │              │
     ▼      ▼              ▼
┌─────────┐ ┌──────────┐ ┌──────────┐
│ SETTLED │ │ DISPUTED │ │ REFUNDED │
└─────────┘ └──────────┘ └──────────┘
```

### 4.1 HITL Pause & One-Tap Approval
When `challenge.hitlThreshold` OR `mandate.hitlThreshold` is crossed:
1. Facilitator creates a `PENDING_HITL` approval record (`hitl_<id>`), **does not** mint a `vrt1` yet, and returns `HTTP 202 Accepted` to the Agent:
   ```json
   {
     "status": "PENDING_HITL",
     "approvalId": "hitl_7c91e3a2",
     "pollUrl": "/v1/hitl/hitl_7c91e3a2",
     "reason": "Amount 550000 UGX meets HITL threshold 500000 UGX",
     "expiresAt": 1795754700
   }
   ```
2. Facilitator fires signed HMAC/Ed25519 outbound webhooks to configured channels (WhatsApp Business, Slack, Email, or Vectoll Console).
3. Approver clicks **Approve** (`POST /v1/hitl/:approvalId/decide` with `{ decision: "approve" }`):
   * Facilitator atomically locks the funds (or debits float), transitions state to `AUTHORIZED` (or `SETTLED` for instant mode), and generates the `vrt1` token so the polling or callback-resumed Agent completes its request seamlessly.
4. Approver clicks **Reject** (or TTL expires):
   * State transitions to `REJECTED` / `EXPIRED`; zero funds leave the Agent wallet.

### 4.2 Escrow Fulfillment & Release
When `settlementMode == "escrow"`:
1. Upon authorization, Facilitator moves funds from `liability:agent_float:<wallet>` into `liability:escrow:<escrowId>` and issues a `vrt1` with `mode: "escrow"` and `esc: "<escrowId>"`.
2. Origin fulfills the booking/order and submits `POST /v1/escrow/:escrowId/fulfill` with proof of fulfillment (`fulfillmentRef`).
3. Facilitator moves funds from `liability:escrow:<escrowId>` to `liability:merchant_payable:<merchant>` + `revenue:platform_fee`, marking the escrow `SETTLED`.
4. If cancelled or unfulfilled before `escrowExpiresAt`, `POST /v1/escrow/:escrowId/refund` atomically reverses `liability:escrow:<escrowId>` back to `liability:agent_float:<wallet>`.
