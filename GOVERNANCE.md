# Vectoll Open-Source Governance

Vectoll is an open protocol and software stack licensed under the **Apache License, Version 2.0**.

## Protocol Evolution (RFC Process)

1. **Specification First:** Normative wire changes are proposed via Pull Requests under `docs/spec/RFC-XXXX-*.md` alongside JSON Schema updates in `spec/schemas/`.
2. **Cross-Language Proof:** Changes to cryptographic tokens (`vrt1`, `vsm1`, `vsm1p`, `vcv1`, `vfv1`) or canonical request hashing (`reqHash`) must include deterministic test vectors in `spec/test-vectors/crypto-vectors.json` passing across TypeScript, Go, and Python in CI.
3. **Wire Stability:** Ratified token prefixes are immutable. Breaking cryptographic or wire changes require introducing a new versioned prefix rather than mutating existing parsers.

## Conformance Verification

Any service or custom gateway implementation claiming Vectoll compatibility can verify compliance using the automated conformance auditor:

```bash
npx @vectoll/cli check https://your-endpoint.example --strict
```
