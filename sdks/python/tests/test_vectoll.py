import json
from pathlib import Path

import pytest

from vectoll import (
    AgentWallet,
    SpendMandate,
    compute_request_hash,
    did_key_to_public_key,
    ed25519_verify,
    verify_vrt,
)

VECTORS_PATH = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "crypto-vectors.json"


def test_cross_language_crypto_vectors() -> None:
    assert VECTORS_PATH.exists(), f"Missing shared vectors at {VECTORS_PATH}"
    vec = json.loads(VECTORS_PATH.read_text("utf-8"))

    fac = AgentWallet.from_seed(vec["keys"]["facilitator"]["seedHex"], kid=vec["keys"]["facilitator"]["kid"])
    prin = AgentWallet.from_seed(vec["keys"]["principal"]["seedHex"], kid=vec["keys"]["principal"]["kid"])
    agent = AgentWallet.from_seed(vec["keys"]["agent"]["seedHex"], kid=vec["keys"]["agent"]["kid"])

    assert fac.did == vec["keys"]["facilitator"]["did"]
    assert fac.public_key_b64url == vec["keys"]["facilitator"]["publicKeyBase64Url"]
    assert prin.did == vec["keys"]["principal"]["did"]
    assert agent.did == vec["keys"]["agent"]["did"]
    assert did_key_to_public_key(agent.did) == agent.public_key_bytes

    for rh in vec["requestHashes"]:
        got = compute_request_hash(rh["method"], rh["target"], rh["bodyUtf8"])
        assert got == rh["expectedReqHash"]

    # Verify TypeScript-minted VRT receipt in Python!
    claims = verify_vrt(
        vec["vrtVector"]["token"],
        fac.public_key_b64url,
        expected_audience="acme-hospitality-api",
        expected_req_hash=vec["vrtVector"]["claims"]["req"],
        min_amount=50,
        expected_currency="UGX",
        now_seconds=1795753810,
    )
    assert claims["jti"] == vec["vrtVector"]["claims"]["jti"]

    # Verify TypeScript-minted Spend Mandate in Python!
    m_claims = SpendMandate.verify(vec["mandateVector"]["token"], now_seconds=1795753810)
    assert m_claims["mandateId"] == vec["mandateVector"]["claims"]["mandateId"]

    # Verify deterministic clearing intent signature parity!
    intent = vec["clearingIntentVector"]["intent"]
    py_sig = agent.sign_clearing_intent(
        challenge_id=intent["challengeId"],
        req_hash=intent["reqHash"],
        max_accepted_amount=intent["maxAcceptedAmount"],
        rail=intent["rail"],
        timestamp=intent["timestamp"],
    )
    assert py_sig == vec["clearingIntentVector"]["signatureBase64Url"]
    assert ed25519_verify(
        agent.did,
        "\n".join(
            [
                "vectoll-clear/v1",
                intent["agentId"],
                intent["challengeId"],
                intent["reqHash"],
                str(intent["maxAcceptedAmount"]),
                intent["rail"],
                str(intent["timestamp"]),
            ]
        ),
        py_sig,
    )


def test_python_mandate_issue_and_tamper_rejection() -> None:
    principal = AgentWallet.generate()
    agent = AgentWallet.generate()
    mandate = SpendMandate.issue(
        principal=principal,
        agent_did=agent.did,
        currency="UGX",
        decimals=0,
        max_per_call=100_000,
        max_daily=500_000,
    )
    verified = SpendMandate.verify(mandate.token)
    assert verified["agentId"] == agent.did

    # Tamper signature -> must raise
    bad_token = mandate.token[:-4] + "AAAA"
    with pytest.raises(ValueError, match="ERR_INVALID_MANDATE_SIGNATURE"):
        SpendMandate.verify(bad_token)


def test_human_readable_pricing_and_asgi_middleware() -> None:
    import asyncio
    from vectoll import parse_price
    from vectoll.asgi import VectollMiddleware

    assert parse_price("$0.005") == (5000, "USD", 6)
    assert parse_price("€1.25") == (1_250_000, "EUR", 6)
    assert parse_price("50 UGX") == (50, "UGX", 0)
    assert parse_price("10 KES") == (1000, "KES", 2)
    assert parse_price("free") == (0, "USD", 6)

    fac = AgentWallet.generate(kid="fac-asgi-1")

    async def demo_app(scope, receive, send):
        receipt = scope.get("vectoll_receipt")
        body = json.dumps({"ok": True, "paid_by": receipt["sub"] if receipt else "human"}).encode()
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})

    mw = VectollMiddleware(
        demo_app,
        service_name="fastapi-demo",
        facilitator_url="http://localhost:4021",
        facilitator_public_key=fac.public_key_b64url,
        facilitator_kid=fac.kid,
        routes={"GET /api/predict": "$0.01"},
    )

    async def call_asgi(headers):
        events = []

        async def recv():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def snd(ev):
            events.append(ev)

        await mw({"type": "http", "method": "GET", "path": "/api/predict", "query_string": b"", "headers": headers}, recv, snd)
        return events

    # 1. Unpaid agent receives 402
    ev402 = asyncio.run(call_asgi([(b"user-agent", b"GPTBot/1.0")]))
    assert ev402[0]["status"] == 402

    # 2. Paid agent with valid Ed25519 VRT receives 200 + PAYMENT-RESPONSE
    from vectoll import b64url_encode
    import time

    now = int(time.time())
    req_hash = compute_request_hash("GET", "/api/predict", b"")
    claims = {
        "v": 1, "jti": "vrt_py_asgi_1", "kid": fac.kid, "iss": "http://localhost:4021",
        "sub": "did:key:z6MkPythonAgent", "aud": "fastapi-demo", "chg": "chg_1",
        "req": req_hash, "amt": 10_000, "cur": "USD", "dec": 6,
        "rail": "stripe", "mode": "instant", "iat": now, "exp": now + 60,
    }
    p_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")))
    vrt = f"vrt1.{p_b64}.{b64url_encode(fac.sign(f'vrt1.{p_b64}'))}"

    ev200 = asyncio.run(call_asgi([(b"user-agent", b"VectollAgent/0.1"), (b"payment-signature", vrt.encode())]))
    assert ev200[0]["status"] == 200
    assert json.loads(ev200[1]["body"])["paid_by"] == "did:key:z6MkPythonAgent"

    # 3. Replay attempt is rejected with 402!
    ev_replay = asyncio.run(call_asgi([(b"user-agent", b"VectollAgent/0.1"), (b"payment-signature", vrt.encode())]))
    assert ev_replay[0]["status"] == 402


def test_python_ai_toolkit_schema_and_budget_guard() -> None:
    from vectoll import VectollClient
    from vectoll.tools import DiscoveredTool, VectollToolkit

    wallet = AgentWallet.generate()
    client = VectollClient(wallet=wallet, preferred_rail="stripe", wallet_currency="USD")
    t = DiscoveredTool(
        name="demo_search",
        description="Search docs",
        service_name="demo",
        base_url="http://localhost:4020",
        mcp_endpoint=None,
        mcp_tool_name=None,
        method="GET",
        route_path="/api/search",
        amount=10_000,  # $0.01
        currency="USD",
        decimals=6,
        input_schema={"type": "object", "properties": {}},
    )
    tk = VectollToolkit([t], client=client, max_session_budget="$0.005")
    assert len(tk.to_openai_tools()) == 1
    assert len(tk.to_anthropic_tools()) == 1
    assert len(tk.to_gemini_declarations()) == 1
    assert tk.as_callables()[0].__name__ == "demo_search"

    with pytest.raises(RuntimeError, match="ERR_SESSION_BUDGET_EXCEEDED"):
        tk.execute("demo_search", {})


