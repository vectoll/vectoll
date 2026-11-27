"""Vectoll Python SDK (v0.1.0) — Ed25519 Agent Wallets, Spend Mandates, VRT Verifier & Auto-402 Client."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DID_KEY_ED25519_PREFIX = b"\xed\x01"

CURRENCY_DECIMALS: Dict[str, int] = {
    "USD": 6, "EUR": 6, "GBP": 6, "CHF": 6, "CAD": 6, "AUD": 6, "SGD": 6,
    "USDC": 6, "USDT": 6, "PYUSD": 6,
    "JPY": 0, "KRW": 0, "UGX": 0, "RWF": 0,
    "INR": 2, "BRL": 2, "MXN": 2, "AED": 2, "ZAR": 2, "KES": 2, "NGN": 2, "GHS": 2, "TZS": 2,
}

SYMBOL_TO_CURRENCY: Dict[str, str] = {
    "$": "USD", "€": "EUR", "£": "GBP", "¥": "JPY", "₹": "INR",
}


def get_currency_decimals(currency: str, explicit: Optional[int] = None) -> int:
    if explicit is not None:
        return explicit
    return CURRENCY_DECIMALS.get(currency.upper(), 2)


def parse_price(
    value: str | int,
    fallback_currency: Optional[str] = None,
    explicit_decimals: Optional[int] = None,
) -> tuple[int, str, int]:
    """Losslessly convert human price strings like '$0.005', '0.02 EUR', '50 UGX' to (amount_minor, currency, decimals)."""
    has_explicit = bool(fallback_currency and fallback_currency.strip())
    cur = (fallback_currency or "USD").upper()
    if isinstance(value, int):
        if value < 0:
            raise ValueError("Price cannot be negative")
        return value, cur, get_currency_decimals(cur, explicit_decimals)

    s = value.strip()
    if not s or s.lower() == "free" or s == "0":
        return 0, cur, get_currency_decimals(cur, explicit_decimals)

    if s[0] in SYMBOL_TO_CURRENCY:
        if not has_explicit or s[0] != "$":
            cur = SYMBOL_TO_CURRENCY[s[0]]
        s = s[1:].strip()

    parts = s.split()
    num_str = s
    if len(parts) == 2:
        if parts[1].isalpha():
            num_str, cur = parts[0], parts[1].upper()
        elif parts[0].isalpha():
            cur, num_str = parts[0].upper(), parts[1]

    dec = get_currency_decimals(cur, explicit_decimals)
    if "." in num_str:
        whole, frac = num_str.split(".", 1)
    else:
        whole, frac = num_str, ""

    if len(frac) > dec:
        raise ValueError(f"Price '{value}' exceeds {cur} decimals ({dec})")
    padded = frac.ljust(dec, "0")
    combined = (whole + padded).lstrip("0") or "0"
    return int(combined), cur, dec


def b64url_encode(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(encoded: str) -> bytes:
    s = encoded.strip()
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def base58_encode(data: bytes) -> str:
    if not data:
        return ""
    zeroes = 0
    for b in data:
        if b == 0:
            zeroes += 1
        else:
            break
    num = int.from_bytes(data, "big")
    chars: List[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(BASE58_ALPHABET[rem])
    chars.extend("1" for _ in range(zeroes))
    return "".join(reversed(chars))


def base58_decode(s: str) -> bytes:
    if not s:
        return b""
    zeroes = 0
    for ch in s:
        if ch == "1":
            zeroes += 1
        else:
            break
    num = 0
    for ch in s[zeroes:]:
        idx = BASE58_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError(f"Invalid base58 character: {ch}")
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    return (b"\x00" * zeroes) + raw


def public_key_to_did_key(pub_bytes: bytes) -> str:
    if len(pub_bytes) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return "did:key:z" + base58_encode(DID_KEY_ED25519_PREFIX + pub_bytes)


def did_key_to_public_key(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError(f"Unsupported DID format: {did}")
    decoded = base58_decode(did[len("did:key:z") :])
    if len(decoded) != 34 or decoded[:2] != DID_KEY_ED25519_PREFIX:
        raise ValueError(f"Invalid Ed25519 multicodec prefix in {did}")
    return decoded[2:]


def compute_request_hash(method: str, target: str, body: bytes | str = b"") -> str:
    m = method.strip().upper()
    t = target if target.startswith("/") else f"/{target}"
    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    body_hex = hashlib.sha256(body_bytes).hexdigest()
    canonical = f"{m}\n{t}\n{body_hex}".encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class AgentWallet:
    kid: str
    did: str
    seed_bytes: bytes
    public_key_bytes: bytes

    @classmethod
    def from_seed(cls, seed: bytes | str, kid: Optional[str] = None) -> "AgentWallet":
        if isinstance(seed, str):
            seed_bytes = bytes.fromhex(seed) if len(seed) == 64 else b64url_decode(seed)
        else:
            seed_bytes = bytes(seed)
        if len(seed_bytes) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        priv = Ed25519PrivateKey.from_private_bytes(seed_bytes)
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        did = public_key_to_did_key(pub_bytes)
        resolved_kid = kid or f"key-{pub_bytes[:6].hex()}"
        return cls(kid=resolved_kid, did=did, seed_bytes=seed_bytes, public_key_bytes=pub_bytes)

    @classmethod
    def generate(cls, kid: Optional[str] = None) -> "AgentWallet":
        return cls.from_seed(os.urandom(32), kid=kid)

    @property
    def public_key_b64url(self) -> str:
        return b64url_encode(self.public_key_bytes)

    def sign(self, message: bytes | str) -> bytes:
        msg = message.encode("utf-8") if isinstance(message, str) else message
        priv = Ed25519PrivateKey.from_private_bytes(self.seed_bytes)
        return priv.sign(msg)

    def sign_clearing_intent(
        self,
        challenge_id: str,
        req_hash: str,
        max_accepted_amount: int,
        rail: str,
        timestamp: int,
    ) -> str:
        sig_input = "\n".join(
            [
                "vectoll-clear/v1",
                self.did,
                challenge_id,
                req_hash,
                str(max_accepted_amount),
                rail,
                str(timestamp),
            ]
        )
        return b64url_encode(self.sign(sig_input))

    def sign_http_headers(self, req_hash: str, timestamp: Optional[int] = None) -> Dict[str, str]:
        ts = timestamp if timestamp is not None else int(time.time())
        sig_input = f"vectoll-agent-sig/v1\n{self.did}\n{ts}\n{req_hash}"
        sig_b64url = b64url_encode(self.sign(sig_input))
        return {
            "X-Vectoll-Agent-Id": self.did,
            "X-Vectoll-Timestamp": str(ts),
            "X-Vectoll-Signature": sig_b64url,
        }


def ed25519_verify(public_key: bytes | str, message: bytes | str, signature: bytes | str) -> bool:
    try:
        if isinstance(public_key, str):
            pub_bytes = (
                did_key_to_public_key(public_key)
                if public_key.startswith("did:key:z")
                else b64url_decode(public_key)
            )
        else:
            pub_bytes = public_key
        sig_bytes = b64url_decode(signature) if isinstance(signature, str) else signature
        msg_bytes = message.encode("utf-8") if isinstance(message, str) else message
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, msg_bytes)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_vrt(
    token: str,
    facilitator_public_key: bytes | str,
    expected_audience: Optional[str] = None,
    expected_req_hash: Optional[str] = None,
    min_amount: Optional[int] = None,
    expected_currency: Optional[str] = None,
    now_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    cleaned = token.strip()
    if cleaned.lower().startswith("vectoll "):
        cleaned = cleaned[8:].strip()
    parts = cleaned.split(".")
    if len(parts) != 3 or parts[0] != "vrt1":
        raise ValueError("ERR_MALFORMED_VRT")

    signing_input = f"vrt1.{parts[1]}"
    if not ed25519_verify(facilitator_public_key, signing_input, parts[2]):
        raise ValueError("ERR_INVALID_RECEIPT_SIGNATURE")

    claims = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    now = now_seconds if now_seconds is not None else int(time.time())
    if now > int(claims["exp"]) + 5:
        raise ValueError("ERR_RECEIPT_EXPIRED")
    if expected_audience and claims["aud"] != expected_audience:
        raise ValueError("ERR_AUDIENCE_MISMATCH")
    if expected_req_hash and not hmac.compare_digest(claims["req"], expected_req_hash):
        raise ValueError("ERR_REQUEST_HASH_MISMATCH")
    if expected_currency and claims["cur"].upper() != expected_currency.upper():
        raise ValueError("ERR_CURRENCY_MISMATCH")
    if min_amount is not None and int(claims["amt"]) < min_amount:
        raise ValueError("ERR_INSUFFICIENT_RECEIPT_AMOUNT")
    return claims


@dataclass(frozen=True)
class SpendMandate:
    token: str
    claims: Dict[str, Any]

    @classmethod
    def issue(
        cls,
        principal: AgentWallet,
        agent_did: str,
        currency: str,
        decimals: int,
        max_per_call: int,
        max_daily: int,
        allowed_services: Optional[List[str]] = None,
        allowed_rails: Optional[List[str]] = None,
        hitl_threshold: Optional[int] = None,
        mandate_id: Optional[str] = None,
        issued_at: Optional[int] = None,
        expires_at: Optional[int] = None,
    ) -> "SpendMandate":
        if max_per_call <= 0 or max_daily < max_per_call:
            raise ValueError("SpendMandate requires 0 < max_per_call <= max_daily")
        now = issued_at if issued_at is not None else int(time.time())
        claims: Dict[str, Any] = {
            "v": 1,
            "mandateId": mandate_id or f"mnd_{os.urandom(10).hex()}",
            "principalId": principal.did,
            "agentId": agent_did,
            "currency": currency.upper(),
            "decimals": decimals,
            "maxPerCall": max_per_call,
            "maxDaily": max_daily,
            "allowedServices": allowed_services or ["*"],
            "allowedRails": allowed_rails or ["*"],
            "hitlThreshold": hitl_threshold,
            "issuedAt": now,
            "expiresAt": expires_at if expires_at is not None else now + 86400 * 30,
        }
        payload_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")))
        sig_b64 = b64url_encode(principal.sign(f"vsm1.{payload_b64}"))
        return cls(token=f"vsm1.{payload_b64}.{sig_b64}", claims=claims)

    @staticmethod
    def verify(token: str, now_seconds: Optional[int] = None) -> Dict[str, Any]:
        parts = token.strip().split(".")
        if len(parts) != 3 or parts[0] != "vsm1":
            raise ValueError("ERR_MALFORMED_MANDATE")
        claims = json.loads(b64url_decode(parts[1]).decode("utf-8"))
        if not ed25519_verify(claims["principalId"], f"vsm1.{parts[1]}", parts[2]):
            raise ValueError("ERR_INVALID_MANDATE_SIGNATURE")
        now = now_seconds if now_seconds is not None else int(time.time())
        if now > int(claims["expiresAt"]):
            raise ValueError("ERR_MANDATE_EXPIRED")
        return claims


class VectollClient:
    """Automatic HTTP 402 Agent & MCP Client for Python agents."""

    def __init__(
        self,
        wallet: AgentWallet,
        preferred_rail: str = "momo",
        facilitator_url: Optional[str] = None,
        wallet_currency: Optional[str] = None,
        max_price_per_call: Optional[int] = None,
        mandate: Optional[SpendMandate | str] = None,
        hitl_timeout_sec: float = 15.0,
    ) -> None:
        self.wallet = wallet
        self.preferred_rail = preferred_rail
        self.facilitator_url = facilitator_url.rstrip("/") if facilitator_url else None
        self.wallet_currency = wallet_currency
        self.max_price_per_call = max_price_per_call
        self.mandate_token = mandate.token if isinstance(mandate, SpendMandate) else mandate
        self.hitl_timeout_sec = hitl_timeout_sec

    def top_up(
        self,
        amount: int | str,
        currency: Optional[str] = None,
        rail: Optional[str] = None,
        decimals: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not self.facilitator_url:
            raise ValueError("facilitator_url required for top_up")
        amt_minor, cur_code, dec_val = parse_price(
            amount, currency or self.wallet_currency or "USD", decimals
        )
        payload: Dict[str, Any] = {
            "agentId": self.wallet.did,
            "amount": amt_minor,
            "currency": cur_code,
            "decimals": dec_val,
            "rail": rail or self.preferred_rail,
        }
        req = urllib.request.Request(
            f"{self.facilitator_url}/v1/wallets/topup",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def request(
        self,
        method: str,
        url: str,
        body: Optional[bytes | str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        parsed = urllib.parse.urlsplit(url)
        target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        body_bytes = b"" if body is None else (body.encode("utf-8") if isinstance(body, str) else body)
        req_hash = compute_request_hash(method, target, body_bytes)

        req_headers = {"User-Agent": "VectollAgent-Python/0.1"}
        if headers:
            req_headers.update(headers)
        req_headers.update(self.wallet.sign_http_headers(req_hash))

        req1 = urllib.request.Request(
            url,
            data=body_bytes if body_bytes else None,
            headers=req_headers,
            method=method.upper(),
        )
        try:
            with urllib.request.urlopen(req1, timeout=10) as resp:
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers.items()),
                    "body": resp.read().decode("utf-8"),
                    "challenged": False,
                }
        except urllib.error.HTTPError as err:
            if err.code != 402:
                raise
            pay_req_hdr = err.headers.get("PAYMENT-REQUIRED")
            err_body = err.read().decode("utf-8")
            challenge = (
                json.loads(b64url_decode(pay_req_hdr).decode("utf-8"))
                if pay_req_hdr
                else json.loads(err_body)
            )

        if challenge["reqHash"] != req_hash:
            raise RuntimeError("Security abort: challenge reqHash mismatch")
        if self.max_price_per_call is not None and int(challenge["amount"]) > self.max_price_per_call:
            raise RuntimeError("Agent policy abort: challenge exceeds max_price_per_call")

        rail = (
            self.preferred_rail
            if self.preferred_rail in challenge["acceptedRails"]
            else challenge["acceptedRails"][0]
        )
        fac_url = (self.facilitator_url or challenge["facilitatorUrl"]).rstrip("/")
        now = int(time.time())
        max_amt = self.max_price_per_call if self.max_price_per_call is not None else 9_007_199_254_740_991

        clear_sig = self.wallet.sign_clearing_intent(
            challenge_id=challenge["challengeId"],
            req_hash=req_hash,
            max_accepted_amount=max_amt,
            rail=rail,
            timestamp=now,
        )
        clear_payload: Dict[str, Any] = {
            "challenge": challenge,
            "agentId": self.wallet.did,
            "rail": rail,
            "walletCurrency": self.wallet_currency or challenge["currency"],
            "maxAcceptedAmount": max_amt,
            "timestamp": now,
            "agentSignature": clear_sig,
        }
        if self.mandate_token:
            clear_payload["mandateToken"] = self.mandate_token

        clear_req = urllib.request.Request(
            f"{fac_url}/v1/clear",
            data=json.dumps(clear_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(clear_req, timeout=10) as c_resp:
            c_status = c_resp.status
            c_data = json.loads(c_resp.read().decode("utf-8"))

        vrt_token: Optional[str] = None
        if c_status == 202 and c_data.get("status") == "PENDING_HITL":
            deadline = time.time() + self.hitl_timeout_sec
            while time.time() < deadline:
                time.sleep(0.1)
                with urllib.request.urlopen(f"{fac_url}{c_data['pollUrl']}", timeout=5) as p_resp:
                    p_data = json.loads(p_resp.read().decode("utf-8"))
                    if p_data.get("status") == "APPROVED" and p_data.get("vrt"):
                        vrt_token = p_data["vrt"]
                        break
                    if p_data.get("status") in ("REJECTED", "EXPIRED"):
                        raise RuntimeError(f"HITL {p_data['status']}")
            if not vrt_token:
                raise TimeoutError("Timed out awaiting HITL approval")
        else:
            vrt_token = c_data["vrt"]

        retry_headers = dict(req_headers)
        retry_headers["PAYMENT-SIGNATURE"] = vrt_token
        req2 = urllib.request.Request(
            url,
            data=body_bytes if body_bytes else None,
            headers=retry_headers,
            method=method.upper(),
        )
        with urllib.request.urlopen(req2, timeout=10) as resp2:
            return {
                "status": resp2.status,
                "headers": dict(resp2.headers.items()),
                "body": resp2.read().decode("utf-8"),
                "challenged": True,
                "vrt": vrt_token,
            }

    def get_json(self, url: str) -> Any:
        out = self.request("GET", url)
        return json.loads(out["body"])
