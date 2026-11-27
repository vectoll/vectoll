# Contributing to Vectoll

Thank you for building the open metering and multi-rail settlement layer for the agentic web.

## Engineering Non-Negotiables

1. **Zero Floating-Point Money:** Every amount in ledger postings, challenges, mandates, and receipts must be a safe integer in currency minor units paired with explicit `currency` and `decimals`.
2. **Cross-Language Protocol Parity:** Any change to `vrt1` receipts, `vsm1` mandates, `reqHash` canonicalization, or `PAYMENT-*` headers MUST update `spec/test-vectors/crypto-vectors.json` and pass tests across:
   * TypeScript (`pnpm test`)
   * Go (`cd services/gate && go test ./...`)
   * Python (`pytest sdks/python`)
3. **Sub-Millisecond Hot Path:** `vectoll-gate` verification code must never introduce synchronous external HTTP calls on verified requests.
4. **Ledger Invariant Enforcement:** Every Facilitator state mutation affecting balances must preserve `sum(debits) === sum(credits)` per currency inside an atomic transaction.

## Local Development Commands

```bash
pnpm install
pnpm build
pnpm test
cd services/gate && go test -v ./... && cd ../..
pytest sdks/python
```

## Submitting Pull Requests

1. Fork `vectoll/vectoll` and create a focused branch (`feat/mpesa-b2b`, `fix/gate-query-canonicalization`, `docs/rfc-0004-...`).
2. Add unit and integration tests covering happy paths, boundary conditions, and adversarial inputs (tampered signatures, replay attempts, insufficient float).
3. Ensure CI checks pass cleanly before requesting review.
