"""Drop-in ASGI 3.0 Middleware for FastAPI, Starlette, Litestar, and Quart."""

from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from vectoll import (
    b64url_encode,
    compute_request_hash,
    parse_price,
    verify_vrt,
)

DEFAULT_GLOBAL_RAILS = [
    "x402_usdc",
    "stripe",
    "sepa_instant",
    "ach_fednow",
    "pix_upi",
    "mpesa",
    "momo",
    "airtel_money",
    "voucher",
]

BOT_UA_TOKENS = (
    "gptbot", "claudebot", "perplexitybot", "google-extended", "ccbot",
    "vectollagent", "mcp-client", "langchain", "crewai", "python-requests",
    "python-httpx", "curl/", "wget/", "go-http-client", "undici",
)


class VectollMiddleware:
    """
    Standard ASGI 3.0 paywall & metering middleware.

    Usage with FastAPI / Starlette:
        app.add_middleware(
            VectollMiddleware,
            facilitator_url="http://localhost:4021",
            routes={
                "GET /api/predict": "$0.01",
                "GET /articles/*": {"price": "$0.002", "browsers": "free"},
            },
        )
    """

    def __init__(
        self,
        app: Callable[..., Any],
        routes: Dict[str, Any],
        facilitator_url: str = "http://127.0.0.1:4021",
        service_name: str = "vectoll-python-app",
        facilitator_public_key: Optional[str] = None,
        facilitator_kid: str = "fac-key-1",
        rails: Optional[List[str]] = None,
    ) -> None:
        self.app = app
        self.service_name = service_name
        self.facilitator_url = facilitator_url.rstrip("/")
        self._pub_key = facilitator_public_key or ""
        self._kid = facilitator_kid
        self.rails = rails or list(DEFAULT_GLOBAL_RAILS)
        self._consumed_jti: Dict[str, int] = {}
        self.routes = self._compile_routes(routes)

    def _compile_routes(self, raw_routes: Dict[str, Any]) -> List[Dict[str, Any]]:
        compiled: List[Dict[str, Any]] = []
        for spec, val in raw_routes.items():
            s = spec.strip()
            if " " in s:
                method, path = s.split(" ", 1)
                method = method.upper()
                path = path.strip()
            else:
                method, path = "GET", s
            if not path.startswith("/"):
                path = "/" + path

            if isinstance(val, (str, int)):
                amt, cur, dec = parse_price(val)
                compiled.append({
                    "method": method, "path": path, "amount": amt,
                    "currency": cur, "decimals": dec, "browsers_free": False,
                })
            elif isinstance(val, dict):
                amt, cur, dec = parse_price(val["price"], val.get("currency", "USD"))
                compiled.append({
                    "method": method, "path": path, "amount": amt,
                    "currency": cur, "decimals": dec,
                    "browsers_free": val.get("browsers") == "free" or bool(val.get("human_passthrough")),
                })
        return compiled

    def _match_route(self, method: str, path: str) -> Optional[Dict[str, Any]]:
        m = method.upper()
        for r in self.routes:
            if r["method"] not in (m, "*"):
                continue
            if r["path"] == path:
                return r
            if r["path"].endswith("/*"):
                prefix = r["path"][:-1]
                if path.startswith(prefix) or path == prefix[:-1]:
                    return r
        return None

    def _resolve_pub_key(self) -> str:
        if self._pub_key:
            return self._pub_key
        with urllib.request.urlopen(f"{self.facilitator_url}/.well-known/jwks.json", timeout=5) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
            key = doc["keys"][0]
            self._pub_key = key["x"]
            self._kid = key.get("kid", self._kid)
            return self._pub_key

    def _is_human_browser(self, headers: Dict[str, str], browsers_free: bool) -> bool:
        if not browsers_free:
            return False
        if headers.get("payment-signature") or headers.get("x-vectoll-agent-id"):
            return False
        ua = headers.get("user-agent", "")
        if not ua or any(tok in ua.lower() for tok in BOT_UA_TOKENS):
            return False
        accept = headers.get("accept", "")
        return ua.startswith("Mozilla/5.0 ") and "text/html" in accept

    async def __call__(self, scope: Dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET").upper()
        path: str = scope.get("path", "/")
        qs: bytes = scope.get("query_string", b"")
        target = path + (f"?{qs.decode('latin-1')}" if qs else "")

        if method == "GET" and path == "/.well-known/vectoll.json":
            try:
                self._resolve_pub_key()
            except Exception:
                pass
            manifest = {
                "vectollVersion": "0.1",
                "x402Version": 2,
                "service": {"name": self.service_name, "mcpEndpoint": None},
                "settlement": {
                    "facilitatorUrl": self.facilitator_url,
                    "jwksUrl": f"{self.facilitator_url}/.well-known/jwks.json",
                    "facilitatorPublicKey": self._pub_key,
                    "facilitatorKid": self._kid,
                    "defaultCurrency": "USD",
                    "defaultDecimals": 6,
                    "acceptedRails": self.rails,
                },
                "routes": [
                    {
                        "path": r["path"],
                        "method": r["method"],
                        "amount": r["amount"],
                        "currency": r["currency"],
                        "decimals": r["decimals"],
                        "settlementMode": "instant",
                        "humanPassthrough": r["browsers_free"],
                    }
                    for r in self.routes
                ],
            }
            await self._send_json(send, 200, manifest)
            return

        hdr_map: Dict[str, str] = {}
        clean_raw_headers: List[Tuple[bytes, bytes]] = []
        for k_bytes, v_bytes in scope.get("headers", []):
            k_low = k_bytes.decode("latin-1").lower()
            v_str = v_bytes.decode("latin-1")
            hdr_map[k_low] = v_str
            if not k_low.startswith("x-vectoll-"):
                clean_raw_headers.append((k_bytes, v_bytes))

        route = self._match_route(method, path)
        if not route or route["amount"] == 0 or self._is_human_browser(hdr_map, route["browsers_free"]):
            scope = dict(scope, headers=clean_raw_headers)
            await self.app(scope, receive, send)
            return

        # Buffer request body so we can compute SHA-256 reqHash AND replay body to downstream ASGI app
        body_chunks: List[bytes] = []
        while True:
            msg = await receive()
            chunk = msg.get("body", b"")
            if chunk:
                body_chunks.append(chunk)
            if not msg.get("more_body", False):
                break
        full_body = b"".join(body_chunks)

        req_hash = compute_request_hash(method, target, full_body)
        sig_hdr = hdr_map.get("payment-signature") or hdr_map.get("authorization", "")

        if not sig_hdr or (not sig_hdr.startswith("vrt1.") and not sig_hdr.lower().startswith("vectoll vrt1.")):
            try:
                self._resolve_pub_key()
            except Exception:
                pass
            now = int(time.time())
            challenge = {
                "x402Version": 2,
                "protocol": "vectoll/0.1",
                "challengeId": f"chg_{os.urandom(12).hex()}",
                "service": self.service_name,
                "resource": target,
                "method": method,
                "reqHash": req_hash,
                "amount": route["amount"],
                "currency": route["currency"],
                "decimals": route["decimals"],
                "settlementMode": "instant",
                "requireMandate": False,
                "hitlThreshold": None,
                "facilitatorUrl": self.facilitator_url,
                "facilitatorKid": self._kid,
                "acceptedRails": self.rails,
                "issuedAt": now,
                "expiresAt": now + 60,
            }
            encoded = b64url_encode(json.dumps(challenge, separators=(",", ":")))
            await self._send_json(
                send,
                402,
                challenge,
                extra_headers=[(b"payment-required", encoded.encode("ascii")), (b"cache-control", b"no-store")],
            )
            return

        try:
            pub_key = self._resolve_pub_key()
            claims = verify_vrt(
                sig_hdr,
                pub_key,
                expected_audience=self.service_name,
                expected_req_hash=req_hash,
                min_amount=route["amount"],
                expected_currency=route["currency"],
            )
        except Exception as exc:
            await self._send_json(send, 402, {"error": str(exc)})
            return

        now = int(time.time())
        jti = claims["jti"]
        if jti in self._consumed_jti and self._consumed_jti[jti] >= now:
            await self._send_json(send, 402, {"error": "ERR_RECEIPT_REPLAYED"})
            return
        self._consumed_jti[jti] = max(int(claims["exp"]) + 60, now + 60)

        clean_raw_headers.extend([
            (b"x-vectoll-verified", b"true"),
            (b"x-vectoll-receipt-id", jti.encode("utf-8")),
            (b"x-vectoll-agent-id", claims["sub"].encode("utf-8")),
        ])
        new_scope = dict(scope, headers=clean_raw_headers, vectoll_receipt=claims)

        body_sent = False

        async def replayed_receive() -> Dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": full_body, "more_body": False}
            return {"type": "http.disconnect"}

        pay_resp = b64url_encode(
            json.dumps(
                {
                    "x402Version": 2,
                    "protocol": "vectoll/0.1",
                    "receiptId": jti,
                    "settled": True,
                    "mode": claims["mode"],
                    "amount": claims["amt"],
                    "currency": claims["cur"],
                    "decimals": claims["dec"],
                    "rail": claims["rail"],
                    "verifiedAt": now,
                },
                separators=(",", ":"),
            )
        ).encode("ascii")

        async def wrapped_send(event: Dict[str, Any]) -> None:
            if event["type"] == "http.response.start":
                hdrs = list(event.get("headers", []))
                hdrs.append((b"payment-response", pay_resp))
                event = dict(event, headers=hdrs)
            await send(event)

        await self.app(new_scope, replayed_receive, wrapped_send)

    @staticmethod
    async def _send_json(
        send: Callable[..., Any],
        status: int,
        payload: Any,
        extra_headers: Optional[List[Tuple[bytes, bytes]]] = None,
    ) -> None:
        raw = json.dumps(payload).encode("utf-8")
        headers: List[Tuple[bytes, bytes]] = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(raw)).encode("ascii")),
        ]
        if extra_headers:
            headers.extend(extra_headers)
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": raw})
