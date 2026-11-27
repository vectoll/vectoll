# RFC-0003: Two-Tier Clearing, Double-Entry Ledger & Multi-Rail Adapter Contract

* **RFC ID:** RFC-0003
* **Status:** Draft Standard (Implemented in v0.1)
* **Version:** `vectoll/0.1`
* **Updated:** November 2026

---

## 1. Abstract

This RFC specifies the financial accounting core of `vectoll-facilitator`:
1. The **Double-Entry Integer Ledger** schema and invariants.
2. **Multi-Currency FX Normalization** with deterministic rounding and slippage bounds.
3. The **`VectollRailAdapter`** contract unifying Mobile Money (`momo`, `airtel_money`, `mpesa`), Web3 Stablecoins (`x402_usdc`), Cards (`stripe`), and Enterprise Credit Vouchers (`voucher`).

---

## 2. Chart of Accounts & Double-Entry Invariants

### 2.1 Account Hierarchy
Every account is uniquely keyed by `(account_code, currency, decimals)`:

| Account Prefix | Type | Normal Balance | Purpose |
| :--- | :--- | :--- | :--- |
| `asset:rail_clearing:<rail>:<cur>` | Asset | Debit | External funds received via Mobile Money, Stripe, Bank, or On-Chain USDC. |
| `asset:fx_bridge:<cur>` | Asset/Clearing | Neutral | Counter-account for cross-currency atomic FX conversions. |
| `liability:agent_float:<agentId>:<cur>` | Liability | Credit | Spendable prepaid balance belonging to an Agent Wallet. |
| `liability:escrow:<escrowId>:<cur>` | Liability | Credit | Time-locked funds awaiting Origin fulfillment confirmation. |
| `liability:merchant_payable:<service>:<cur>` | Liability | Credit | Verified net earnings owed to an Origin merchant. |
| `revenue:facilitator_fee:<cur>` | Revenue | Credit | Platform clearing fee (`feeBps`, `0` bps by default in self-hosted OSS mode). |

### 2.2 Fundamental Accounting Invariants
1. **Zero-Sum Journal Entries:** Every `JournalTransaction` (`tx_<id>`) contains `N >= 2` posting lines. For every currency `C` present in a journal transaction:
   $$\sum_{i \in C} \text{debit}_i - \sum_{i \in C} \text{credit}_i = 0$$
   Any transaction violating this equation **MUST** abort and roll back atomically.
2. **Non-Negative Liability Balances:** `liability:agent_float`, `liability:escrow`, and `liability:merchant_payable` balances **MUST NOT** drop below `0`. Insufficient float aborts before any `vrt1` signature is produced.
3. **Idempotency Keys:** Every deposit, clearing call (`challengeId`), escrow transition, and merchant payout carries a unique `idempotencyKey`. Repeating an identical request returns the stored result without double-posting.

---

## 3. Journal Posting Flows

### 3.1 Flow A: Agent Wallet Top-Up (`100,000 UGX` via MTN MoMo)
| Account | Debit | Credit |
| :--- | ---: | ---: |
| `asset:rail_clearing:momo:UGX` | `100000` | `0` |
| `liability:agent_float:did:key:z6Mk...:UGX` | `0` | `100000` |

### 3.2 Flow B: Instant Metered API Call (`50 UGX`, `200 bps` / `2%` fee = `1 UGX`)
| Account | Debit | Credit |
| :--- | ---: | ---: |
| `liability:agent_float:did:key:z6Mk...:UGX` | `50` | `0` |
| `liability:merchant_payable:acme-hospitality-api:UGX` | `0` | `49` |
| `revenue:facilitator_fee:UGX` | `0` | `1` |

### 3.3 Flow C: Cross-Currency Clearing (`Agent holds USD`, `Merchant prices 50 UGX`)
Suppose FX quote is `1 USD = 3,700 UGX` (`1,000,000` micro-USD = `3,700` UGX → `1` UGX = `270.27` micro-USD → ceiling for solvency = `271` micro-USD, so `50 UGX` = `13,514` micro-USD + slippage check):
* **Tx Leg 1 (USD):** Debit `liability:agent_float:<agent>:USD` `13514`, Credit `asset:fx_bridge:USD` `13514`.
* **Tx Leg 2 (UGX):** Debit `asset:fx_bridge:UGX` `50`, Credit `liability:merchant_payable:<service>:UGX` `49`, Credit `revenue:facilitator_fee:UGX` `1`.
Both legs commit inside **one atomic database transaction**, recording the exact applied FX quote ID and rate.

### 3.4 Flow D: Merchant Batch Payout (`500,000 UGX` to Merchant MoMo MSISDN)
| Account | Debit | Credit |
| :--- | ---: | ---: |
| `liability:merchant_payable:acme-hospitality-api:UGX` | `500000` | `0` |
| `asset:rail_clearing:momo:UGX` | `0` | `500000` |

---

## 4. Standardized `VectollRailAdapter` Interface

Every settlement rail plugin in `@vectoll/adapters` implements the following asynchronous contract:

```typescript
export interface VectollRailAdapter {
  readonly railId: string; // e.g. "momo" | "airtel_money" | "mpesa" | "x402_usdc" | "stripe" | "voucher"
  readonly displayName: string;
  readonly supportedCurrencies: readonly string[];

  /** Quote FX + rail fees between agent wallet currency and merchant currency */
  quote(input: RailQuoteRequest): Promise<RailQuote>;

  /** Initiate or verify an inbound funding / direct payment authorization */
  authorize(input: RailAuthorizeRequest): Promise<RailAuthorization>;

  /** Finalize capture/settlement for an authorized payment or direct on-chain tx */
  settle(input: RailSettleRequest): Promise<RailSettlementResult>;

  /** Disburse accumulated merchant payable balance to external merchant account */
  payout(input: RailPayoutRequest): Promise<RailPayoutResult>;
}
```

### 4.1 First-Party Adapter Specifications
1. **`momo` (MTN Mobile Money Open API):**
   * Supports `UGX`, `GHS`, `RWF`, `ZMW`, `XAF`, `XOF`.
   * Top-up flow maps to Collection `POST /collection/v1_0/requesttopay` (`X-Reference-Id` UUIDv4) + signed callback webhook; Merchant batch sweep maps to Disbursement `POST /disbursement/v1_0/transfer`.
2. **`airtel_money` (Airtel Africa Open API):**
   * Supports `UGX`, `KES`, `TZS`, `NGN`, `RWF`, `ZMW`.
   * USSD push collection (`/merchant/v1/payments/`) + B2B/B2C disbursement (`/standard/v1/disbursements/`).
3. **`mpesa` (Safaricom Daraja API):**
   * Supports `KES`, `TZS`, `ETB`.
   * Lipa Na M-Pesa Online STK Push (`/mpesa/stkpush/v1/processrequest`) + B2C payout (`/mpesa/b2c/v3/paymentrequest`).
4. **`x402_usdc` (x402 V2 Stablecoin Adapter):**
   * Supports `USDC` (`decimals = 6`) on Base (`eip155:8453`), Base Sepolia (`eip155:84532`), Polygon, and Solana.
   * Verifies EIP-3009 `transferWithAuthorization` typed-data signatures or settled tx hashes directly, enabling instant non-custodial clearing alongside float mode.
5. **`stripe` (Cards & Bank Tokens):**
   * Supports `USD`, `EUR`, `GBP`, `KES`, `NGN`.
   * Integrates PaymentIntents (`confirm: true`, off-session agentic payment methods) and Stripe Connect transfers.
6. **`voucher` (Enterprise Cryptographic Credit Vouchers):**
   * Zero-fee signed Ed25519 credit notes (`vcv1.<payload>.<sig>`) issued by organizations to grant partners, researchers, or internal microservices bounded API quotas without external banking rails.
