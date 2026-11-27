# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | Yes |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for suspected cryptographic, ledger, double-spend, signature bypass, or replay vulnerabilities.**

Please report security findings privately to **`security@vectoll.org`** (or via GitHub Private Vulnerability Reporting on `github.com/vectoll/vectoll`) with:
1. Affected component (`services/gate`, `@vectoll/core`, `@vectoll/facilitator`, `@vectoll/edge`, SDKs, or RFC spec).
2. Minimal proof-of-concept script or HTTP trace reproducing the issue.
3. Estimated impact (signature forgery, float double-spend, mandate ceiling bypass, header injection, DoS).

### Response SLA
* **Acknowledgement:** Within 24 hours.
* **Triage & Severity Assessment:** Within 72 hours.
* **Coordinated Fix & Advisory:** Within 7 days for Critical/High findings.

See [`docs/security-and-threat-model.md`](./docs/security-and-threat-model.md) for Vectoll's architectural invariants and STRIDE threat model.
