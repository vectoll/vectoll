"""AI Agent Framework Toolkit for OpenAI, Anthropic, Gemini, LangChain, CrewAI & AutoGen."""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from vectoll import VectollClient, parse_price


def _sanitize_name(service: str, raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "_", f"{service}_{raw}").strip("_")
    return cleaned[:64]


@dataclass(frozen=True)
class DiscoveredTool:
    name: str
    description: str
    service_name: str
    base_url: str
    mcp_endpoint: Optional[str]
    mcp_tool_name: Optional[str]
    method: str
    route_path: str
    amount: int
    currency: str
    decimals: int
    input_schema: Dict[str, Any]


class VectollToolkit:
    """
    Auto-discovers Vectoll endpoints (`/.well-known/vectoll.json` or Discovery Registry)
    and exposes ready-to-bind tools for OpenAI, Anthropic, Gemini, LangChain, and CrewAI
    with strict cumulative session budget enforcement.
    """

    def __init__(
        self,
        tools: List[DiscoveredTool],
        client: VectollClient,
        max_session_budget: Optional[str | int] = None,
    ) -> None:
        self.client = client
        self.tools: Dict[str, DiscoveredTool] = {t.name: t for t in tools}
        self.spent_minor = 0
        self.call_count = 0
        self.max_budget_minor: Optional[int] = None
        if max_session_budget is not None:
            amt, _, _ = parse_price(max_session_budget, client.wallet_currency or "USD")
            self.max_budget_minor = amt

    @classmethod
    def from_domains(
        cls,
        domain_urls: List[str],
        client: VectollClient,
        max_session_budget: Optional[str | int] = None,
    ) -> "VectollToolkit":
        discovered: List[DiscoveredTool] = []
        for raw_url in domain_urls:
            base = raw_url.strip().rstrip("/")
            with urllib.request.urlopen(f"{base}/.well-known/vectoll.json", timeout=10) as resp:
                doc = json.loads(resp.read().decode("utf-8"))
            svc_name = doc["service"]["name"]
            mcp_ep = doc["service"].get("mcpEndpoint")
            for r in doc.get("routes", []):
                if "*" in r["path"]:
                    continue
                mcp_obj = r.get("mcpTool")
                raw_tool = (
                    mcp_obj["name"]
                    if mcp_obj and mcp_obj.get("name")
                    else f"{r['method'].lower()}_{r['path'].strip('/')}"
                )
                desc = (mcp_obj.get("description") if mcp_obj else None) or f"{r['method']} {r['path']}"
                discovered.append(
                    DiscoveredTool(
                        name=_sanitize_name(svc_name, raw_tool),
                        description=f"{desc} [Price: {r['amount']} {r['currency']} minor]",
                        service_name=svc_name,
                        base_url=base,
                        mcp_endpoint=mcp_ep,
                        mcp_tool_name=mcp_obj["name"] if mcp_obj else None,
                        method=r["method"].upper(),
                        route_path=r["path"],
                        amount=int(r["amount"]),
                        currency=r["currency"],
                        decimals=int(r["decimals"]),
                        input_schema={"type": "object", "properties": {}, "additionalProperties": True},
                    )
                )
        return cls(discovered, client=client, max_session_budget=max_session_budget)

    @classmethod
    def from_discovery_search(
        cls,
        registry_url: str,
        client: VectollClient,
        query: Optional[str] = None,
        rail: Optional[str] = None,
        max_price_usd: Optional[str | int] = None,
        max_session_budget: Optional[str | int] = None,
    ) -> "VectollToolkit":
        params: Dict[str, str] = {}
        if query:
            params["q"] = query
        if rail:
            params["rail"] = rail
        if max_price_usd is not None:
            amt, _, _ = parse_price(max_price_usd, "USD")
            params["maxPriceUsdMicro"] = str(amt)
        qs = urllib.parse.urlencode(params)
        url = f"{registry_url.rstrip('/')}/v1/discovery/search" + (f"?{qs}" if qs else "")
        with urllib.request.urlopen(url, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        tools: List[DiscoveredTool] = []
        for r in payload.get("results", []):
            if "*" in r["routePath"]:
                continue
            raw_name = r.get("mcpToolName") or f"{r['method'].lower()}_{r['routePath']}"
            tools.append(
                DiscoveredTool(
                    name=_sanitize_name(r["serviceName"], raw_name),
                    description=f"{r['description']} [Price: {r['amount']} {r['currency']} minor]",
                    service_name=r["serviceName"],
                    base_url=r["baseUrl"],
                    mcp_endpoint=r.get("mcpEndpoint"),
                    mcp_tool_name=r.get("mcpToolName"),
                    method=r["method"].upper(),
                    route_path=r["routePath"],
                    amount=int(r["amount"]),
                    currency=r["currency"],
                    decimals=int(r["decimals"]),
                    input_schema={"type": "object", "properties": {}, "additionalProperties": True},
                )
            )
        return cls(tools, client=client, max_session_budget=max_session_budget)

    def execute(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        tool = self.tools.get(tool_name)
        if not tool:
            raise KeyError(f"Unknown Vectoll tool: {tool_name}")

        if self.max_budget_minor is not None and self.spent_minor + tool.amount > self.max_budget_minor:
            raise RuntimeError(
                f"ERR_SESSION_BUDGET_EXCEEDED: {self.spent_minor + tool.amount} > {self.max_budget_minor}"
            )

        args = arguments or {}
        if tool.mcp_endpoint and tool.mcp_tool_name:
            rpc_body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": tool.mcp_tool_name, "arguments": args},
                }
            )
            res = self.client.request(
                "POST",
                f"{tool.base_url}{tool.mcp_endpoint}",
                body=rpc_body,
                headers={"Content-Type": "application/json"},
            )
            rpc_out = json.loads(res["body"])
            text = rpc_out.get("result", {}).get("content", [{}])[0].get("text", "{}")
            out = json.loads(text)
        else:
            url = f"{tool.base_url}{tool.route_path}"
            if tool.method == "GET" and args:
                url += "?" + urllib.parse.urlencode({k: str(v) for k, v in args.items()})
                res = self.client.request("GET", url)
            else:
                res = self.client.request(
                    tool.method,
                    url,
                    body=json.dumps(args) if args else None,
                    headers={"Content-Type": "application/json"} if args else None,
                )
            out = json.loads(res["body"])

        self.spent_minor += tool.amount
        self.call_count += 1
        return out

    def to_openai_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                },
            }
            for t in self.tools.values()
        ]

    def to_anthropic_tools(self) -> List[Dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in self.tools.values()
        ]

    def to_gemini_declarations(self) -> List[Dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "parameters": t.input_schema}
            for t in self.tools.values()
        ]

    def as_callables(self) -> List[Callable[..., Any]]:
        """Returns standard documented Python callables for CrewAI, AutoGen, ADK & LangChain."""
        fns: List[Callable[..., Any]] = []
        for t in self.tools.values():

            def _make(bound_tool: DiscoveredTool) -> Callable[..., Any]:
                def tool_fn(**kwargs: Any) -> Any:
                    return self.execute(bound_tool.name, kwargs)

                tool_fn.__name__ = bound_tool.name
                tool_fn.__doc__ = bound_tool.description
                return tool_fn

            fns.append(_make(t))
        return fns
