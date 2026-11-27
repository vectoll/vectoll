# RFC-0004: WebAuthn Passkey Spend Mandates, Multi-Tenant Isolation & Federated Clearing

* **RFC ID:** RFC-0004
* **Status:** Draft Standard (Implemented in v0.4)
* **Version:** `vectoll/0.4`
* **Updated:** November 2026

---

## 1. Abstract

This specification extends Vectoll with three enterprise and global-network capabilities:
1. **Hardware Passkey Spend Mandates (`vsm1p`)** using W3C WebAuthn / FIDO2 (`ES256` / NIST `P-256`), aligning Vectoll with AP2 / FIDO2 human-presence delegation.
2. **Multi-Tenant Merchant Isolation & Scoped API Keys (`vk_live_*`)** hashed at rest with `SHA-256`.
3. **Federated Cross-Facilitator Peering (`vfv1`)**, allowing an AI Agent funded on **Facilitator A** (e.g., an enterprise SEPA treasury in Frankfurt) to seamlessly settle `HTTP 402` challenges issued by a Gate trusting **Facilitator B** (e.g., a cloud provider in Tokyo or San Francisco).

---

## 2. WebAuthn / Passkey Spend Mandates (`vsm1p`)

While `vsm1` uses Ed25519 (`did:key`) for programmatic treasury keys, human principals on laptops and phones hold non-exportable **FIDO2 / WebAuthn Passkeys** (`ECDSA P-256` with `SHA-256`).

### 2.1 Wire Format
```text
vsm1p.<payload_b64url>.<webauthn_proof_b64url>
```
* `principalId`: `"did:passkey:" + lowercase_hex(SHA256(spki_der_bytes))[0..32]`
* `challenge`: `base64url(SHA256("vsm1-passkey." + payload_b64url))`
* `webauthn_proof_b64url`: Base64url JSON containing `{ publicKeySpkiB64Url, credentialId, authenticatorDataB64Url, clientDataJsonB64Url, signatureDerB64Url }`.

### 2.2 Verification Algorithm
Verifiers **MUST** check:
1. `SHA256(spki_der)` prefix matches `claims.principalId`.
2. `authenticatorData` length `>= 37` bytes and Bit 0 (`UP` — User Present) is `1`.
3. `clientDataJSON.type === "webauthn.get"` and `clientDataJSON.challenge === base64url(SHA256("vsm1-passkey." + payload_b64url))`.
4. `ECDSA_P256_SHA256.Verify(spki_pub, authenticatorData || SHA256(clientDataJSON), signatureDer)` succeeds.
5. Standard `RFC-0002` ceiling checks (`maxPerCall`, `maxDaily`, `allowedServices`, `allowedRails`, `expiresAt`, revocation list) pass.

---

## 3. Multi-Tenant Merchant Isolation (`vk_live_*`)

Facilitators hosting multiple merchants enforce strict tenant boundaries:
* Each Merchant registers ownership of one or more `service` identifiers (`aud`).
* API keys follow `vk_live_<48_hex_chars>`. Facilitators **MUST NOT** store plaintext keys; only `SHA256(apiKey)` is persisted alongside an array of scopes (`hitl:decide`, `escrow:manage`, `payouts:write`, `ledger:read`).
* Any mutation targeting a registered `service` (HITL approval/rejection, escrow release, or merchant payout) **MUST** present a valid `Bearer vk_live_*` belonging to that exact merchant with the required scope (or a super-admin key).

---

## 4. Federated Cross-Facilitator Peering (`vfv1`)

### 4.1 Peering Handshake & Multi-KID JWKS
1. Facilitator B registers Facilitator A as a trusted peer (`peerId`, `issuerUrl`, `kid`, `publicKey`, `creditLimit`, `currency`).
2. Facilitator B includes endorsed peer keys inside `GET /.well-known/jwks.json` (`keys: [localKey, ...peerKeys]`).
3. Gates (`vectoll-gate` in Go and `@vectoll/edge`) index **all** keys in JWKS by `kid`, allowing zero-roundtrip offline verification of receipts signed by any trusted peer.

### 4.2 Bilateral Inter-Facilitator Clearing (`POST /v1/federation/clear`)
When an Agent funded on **Home Facilitator A** encounters a `402` challenge pointing to **Target Facilitator B**:
1. Agent calls `POST /v1/clear` on its **Home Facilitator A** (passing the `challenge` whose `facilitatorUrl` is Facilitator B).
2. Home Facilitator A:
   * Verifies Agent signature, Spend Mandate (`vsm1` or `vsm1p`), and float balance.
   * Atomically debits `liability:agent_float:<agent>` and credits `liability:peer_payable:<facB>` in its local double-entry ledger.
   * Signs an **Inter-Facilitator Clearing Voucher (`vfv1.<payload>.<sig>`)** with Facilitator A's Ed25519 private key and forwards it to `POST <facB>/v1/federation/settle-inbound`.
3. Target Facilitator B:
   * Verifies Facilitator A's Ed25519 signature against its registered peer table and enforces Facilitator A's bilateral `creditLimit`.
   * Atomically debits `asset:peer_receivable:<facA>` and credits `liability:merchant_payable:<service>` + `revenue:facilitator_fee`.
   * Mints and returns Facilitator B's native `vrt1` token!
4. Home Facilitator A returns Facilitator B's `vrt1` token to the Agent, which retries the Gate and receives `200 OK`—even if the Gate has never heard of Facilitator A!
