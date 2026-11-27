import http from 'node:http';
import {
  buildDiscoveryManifest,
  classifyTraffic,
  computeRequestHash,
  createPaymentChallenge,
  createPaymentResponseHeader,
  encodePaymentHeader,
  extractStructuredDocument,
  formatMinorAmount,
  getCurrencyDecimals,
  verifyVrt,
  type VectollConfig,
  type VectollRouteConfig,
} from '@vectoll/core';
import { type ReplayGuard } from './redis.js';

export * from './redis.js';

export class ReplayStore implements ReplayGuard {
  private readonly consumed = new Map<string, number>();

  /**
   * Atomically returns true if jti is fresh and marks it consumed; returns false if already used.
   */
  consume(jti: string, expiresAtSeconds: number, nowSeconds = Math.floor(Date.now() / 1000)): boolean {
    if (this.consumed.size > 5000) {
      for (const [k, exp] of this.consumed.entries()) {
        if (exp < nowSeconds) this.consumed.delete(k);
      }
    }
    const existingExp = this.consumed.get(jti);
    if (existingExp !== undefined && existingExp >= nowSeconds) {
      return false;
    }
    this.consumed.set(jti, Math.max(expiresAtSeconds + 60, nowSeconds + 60));
    return true;
  }
}

function matchRoute(
  routes: VectollRouteConfig[],
  method: string,
  pathname: string,
): VectollRouteConfig | undefined {
  const upperMethod = method.toUpperCase();
  for (const r of routes) {
    if (r.method.toUpperCase() !== upperMethod && r.method !== '*') continue;
    if (r.path === pathname) return r;
    if (r.path.endsWith('/*')) {
      const prefix = r.path.slice(0, -1);
      if (pathname.startsWith(prefix) || pathname === prefix.slice(0, -1)) return r;
    }
  }
  return undefined;
}

export interface VectollGateOptions {
  config: VectollConfig;
  facilitatorPublicKey?: string;
  replayStore?: ReplayGuard;
  fetchImpl?: typeof fetch;
}

export function createVectollEdgeHandler(options: VectollGateOptions) {
  const { config } = options;
  const fetchFn = options.fetchImpl ?? fetch;
  const replayStore: ReplayGuard = options.replayStore ?? new ReplayStore();
  const explicitSingleKey = options.facilitatorPublicKey ?? config.settlement.facilitator_public_key ?? '';
  let cachedPubKey = explicitSingleKey;
  let cachedKid = config.settlement.facilitator_kid ?? 'fac-key-1';
  const trustedKeysByKid: Record<string, string> = {};

  const refreshJwks = async (): Promise<void> => {
    const facUrl = config.settlement.facilitator_url.replace(/\/$/, '');
    const res = await fetchFn(`${facUrl}/.well-known/jwks.json`);
    if (res.ok) {
      const jwks = (await res.json()) as { keys?: Array<{ kid?: string; x?: string }> };
      for (const k of jwks.keys ?? []) {
        if (k.x && k.kid) {
          trustedKeysByKid[k.kid] = k.x;
        }
      }
      const first = jwks.keys?.[0];
      if (first?.x) {
        cachedPubKey = first.x;
        if (first.kid) cachedKid = first.kid;
      }
    }
  };

  const ensureFacilitatorKey = async (): Promise<string | Record<string, string>> => {
    if (explicitSingleKey) return explicitSingleKey;
    if (Object.keys(trustedKeysByKid).length > 0) return trustedKeysByKid;
    await refreshJwks();
    if (!cachedPubKey && Object.keys(trustedKeysByKid).length === 0) {
      throw new Error('Unable to resolve facilitator Ed25519 public key');
    }
    return Object.keys(trustedKeysByKid).length > 0 ? trustedKeysByKid : cachedPubKey;
  };

  const discoveryPath = config.service.discovery_path ?? '/.well-known/vectoll.json';
  const metrics = {
    humanPassthrough: 0,
    challenged402: 0,
    verified200: 0,
    rejectedInvalid: 0,
    rejectedReplay: 0,
  };

  return async function handleRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const target = `${url.pathname}${url.search}`;

    // 0. Gate Health & Prometheus /metrics
    if (request.method === 'GET' && pathname === '/metrics') {
      const prom = [
        '# HELP vectoll_gate_requests_total Total HTTP requests processed by Vectoll Gate',
        '# TYPE vectoll_gate_requests_total counter',
        `vectoll_gate_requests_total{outcome="human_passthrough"} ${metrics.humanPassthrough}`,
        `vectoll_gate_requests_total{outcome="challenged_402"} ${metrics.challenged402}`,
        `vectoll_gate_requests_total{outcome="verified_200"} ${metrics.verified200}`,
        `vectoll_gate_requests_total{outcome="rejected_invalid"} ${metrics.rejectedInvalid}`,
        `vectoll_gate_requests_total{outcome="rejected_replay"} ${metrics.rejectedReplay}`,
      ].join('\n') + '\n';
      return new Response(prom, {
        status: 200,
        headers: { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' },
      });
    }

    if (request.method === 'GET' && (pathname === '/health' || pathname === '/_vectoll/status')) {
      return new Response(
        JSON.stringify({
          status: 'ok',
          service: 'vectoll-gate',
          version: '1.0.0',
          protectedService: config.service.name,
          origin: config.service.origin,
          discoveryPath,
          mcpEndpoint: config.service.enable_mcp !== false ? '/mcp' : null,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8' } },
      );
    }

    // 1. Discovery Manifest (always free)
    if (request.method === 'GET' && pathname === discoveryPath) {
      try {
        await ensureFacilitatorKey();
      } catch {
        // best-effort key population
      }
      const manifest = buildDiscoveryManifest(config, {
        facilitatorPublicKey: cachedPubKey,
        facilitatorKid: cachedKid,
      });
      return new Response(JSON.stringify(manifest, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    }

    // 2a. Browser & Client MCP Discovery / Inspector (GET /mcp)
    if (config.service.enable_mcp !== false && pathname === '/mcp' && request.method === 'GET') {
      const mcpTools = config.routes
        .filter((r) => Boolean(r.mcp_tool))
        .map((r) => {
          const cur = r.currency ?? config.settlement.default_currency;
          const dec = getCurrencyDecimals(cur, r.decimals);
          return {
            name: r.mcp_tool!,
            description: r.mcp_description ?? `${r.method} ${r.path}`,
            method: r.method,
            upstreamPath: r.path,
            amount: r.price,
            currency: cur,
            decimals: dec,
            formattedPrice: formatMinorAmount(r.price, cur, dec),
            settlementMode: r.settlement_mode ?? 'instant',
            requireMandate: Boolean(r.require_mandate),
          };
        });

      if ((request.headers.get('accept') ?? '').includes('text/html')) {
        const rows = mcpTools
          .map(
            (t) =>
              `<tr><td><strong>${t.name}</strong></td><td>${t.description}</td><td><code>${t.method} ${t.upstreamPath}</code></td><td>${t.formattedPrice}</td><td>${t.settlementMode}${t.requireMandate ? ' + mandate' : ''}</td></tr>`,
          )
          .join('');
        const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><title>Vectoll MCP Gateway — ${config.service.name}</title>
<style>
  body{margin:0;background:#090d16;color:#f3f4f6;font-family:Inter,system-ui,sans-serif;padding:28px;}
  .wrap{max-width:1100px;margin:0 auto;display:grid;gap:18px;}
  .card{background:#111827;border:1px solid #1f2937;border-radius:8px;padding:20px;}
  h1{margin:0;font-size:19px;display:flex;align-items:center;gap:10px;}
  .badge{font-size:12px;font-family:monospace;padding:3px 9px;border-radius:4px;background:rgba(124,58,237,.2);color:#c4b5fd;border:1px solid rgba(124,58,237,.45);}
  table{width:100%;border-collapse:collapse;font-family:ui-monospace,monospace;font-size:12.5px;margin-top:10px;}
  th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #1f2937;}
  th{color:#9ca3af;font-size:11px;text-transform:uppercase;}
  pre{background:#060911;border:1px solid #1f2937;padding:12px;border-radius:6px;overflow:auto;font-size:12px;color:#a7f3d0;}
  button{background:#10b981;color:#05100c;font-weight:700;border:none;padding:8px 14px;border-radius:5px;cursor:pointer;font-family:monospace;}
</style></head><body><div class="wrap">
  <div class="card">
    <h1>VECTOLL MCP GATEWAY <span class="badge">JSON-RPC 2.0 · protocolVersion 2025-06-18</span></h1>
    <p style="color:#9ca3af;font-size:13px;margin:8px 0 0;">Service: <code>${config.service.name}</code> · Accepted Rails: <code>${config.settlement.accepted_rails.join(', ')}</code> · Discovery: <a style="color:#38bdf8" href="${discoveryPath}">${discoveryPath}</a></p>
  </div>
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <strong>Metered MCP Tools (${mcpTools.length})</strong>
      <button onclick="runToolsList()">Test JSON-RPC tools/list</button>
    </div>
    <table><thead><tr><th>MCP Tool</th><th>Description</th><th>Upstream Route</th><th>Price</th><th>Mode</th></tr></thead><tbody>${rows}</tbody></table>
    <pre id="rpc-out">// Click "Test JSON-RPC tools/list" or POST JSON-RPC 2.0 payloads to /mcp</pre>
  </div>
</div>
<script>
async function runToolsList(){
  const res = await fetch('/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
  });
  document.getElementById('rpc-out').textContent = JSON.stringify(await res.json(), null, 2);
}
</script></body></html>`;
        return new Response(html, {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }

      return new Response(
        JSON.stringify(
          {
            protocolVersion: '2025-06-18',
            transport: 'streamable-http',
            endpoint: '/mcp',
            serverInfo: { name: config.service.name, version: '0.1.0' },
            acceptedRails: config.settlement.accepted_rails,
            tools: mcpTools,
          },
          null,
          2,
        ),
        { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8' } },
      );
    }

    // 2b. Native JSON-RPC 2.0 MCP Auto-Wrapper (POST /mcp)
    if (config.service.enable_mcp !== false && pathname === '/mcp' && request.method === 'POST') {
      const rawBody = new Uint8Array(await request.arrayBuffer());
      const bodyStr = Buffer.from(rawBody).toString('utf8');
      let rpc: { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> };
      try {
        rpc = JSON.parse(bodyStr);
      } catch {
        return new Response(
          JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }),
          { status: 400, headers: { 'Content-Type': 'application/json' } },
        );
      }

      if (rpc.method === 'initialize') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: rpc.id ?? 1,
            result: {
              protocolVersion: '2025-06-18',
              serverInfo: { name: config.service.name, version: '0.1.0' },
              capabilities: { tools: {} },
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }

      if (rpc.method === 'tools/list') {
        const tools = config.routes
          .filter((r) => Boolean(r.mcp_tool))
          .map((r) => ({
            name: r.mcp_tool!,
            description: r.mcp_description ?? `${r.method} ${r.path}`,
            inputSchema: {
              type: 'object',
              additionalProperties: true,
            },
            _meta: {
              vectollPricing: {
                amount: r.price,
                currency: r.currency ?? config.settlement.default_currency,
                decimals: getCurrencyDecimals(r.currency ?? config.settlement.default_currency, r.decimals),
                settlementMode: r.settlement_mode ?? 'instant',
                requireMandate: Boolean(r.require_mandate),
              },
            },
          }));
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: rpc.id ?? 1, result: { tools } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (rpc.method === 'tools/call') {
        const toolName = String(rpc.params?.name ?? '');
        const toolArgs = (rpc.params?.arguments ?? {}) as Record<string, unknown>;
        const matchedRoute = config.routes.find((r) => r.mcp_tool === toolName);
        if (!matchedRoute) {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id: rpc.id ?? 1,
              error: { code: -32601, message: `Unknown MCP tool: ${toolName}` },
            }),
            { status: 404, headers: { 'Content-Type': 'application/json' } },
          );
        }

        const reqHash = computeRequestHash('POST', '/mcp', rawBody);
        const cur = matchedRoute.currency ?? config.settlement.default_currency;
        const dec = getCurrencyDecimals(cur, matchedRoute.decimals);
        const sigHeader =
          request.headers.get('payment-signature') ?? request.headers.get('authorization');

        if (!sigHeader) {
          await ensureFacilitatorKey().catch(() => undefined);
          const challenge = createPaymentChallenge({
            service: config.service.name,
            resource: '/mcp',
            method: 'POST',
            reqHash,
            amount: matchedRoute.price,
            currency: cur,
            decimals: dec,
            settlementMode: matchedRoute.settlement_mode ?? 'instant',
            requireMandate: matchedRoute.require_mandate ?? false,
            hitlThreshold: matchedRoute.hitl_threshold ?? null,
            facilitatorUrl: config.settlement.facilitator_url,
            facilitatorKid: cachedKid,
            acceptedRails: config.settlement.accepted_rails,
          });
          return new Response(JSON.stringify(challenge), {
            status: 402,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Cache-Control': 'no-store',
              'PAYMENT-REQUIRED': encodePaymentHeader(challenge),
            },
          });
        }

        const pubKey = await ensureFacilitatorKey();
        const check = verifyVrt(sigHeader, pubKey, {
          expectedAudience: config.service.name,
          expectedReqHash: reqHash,
          minAmount: matchedRoute.price,
          expectedCurrency: cur,
        });
        if (!check.valid) {
          return new Response(JSON.stringify({ error: check.code, reason: check.reason }), {
            status: 402,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (!(await replayStore.consume(check.claims.jti, check.claims.exp))) {
          return new Response(
            JSON.stringify({ error: 'ERR_RECEIPT_REPLAYED', reason: 'VRT jti already consumed' }),
            { status: 402, headers: { 'Content-Type': 'application/json' } },
          );
        }

        // Proxy to underlying Origin route
        const originBase = config.service.origin.replace(/\/$/, '');
        let originUrl = `${originBase}${matchedRoute.path}`;
        let originBody: string | undefined;
        if (matchedRoute.method === 'GET') {
          const qs = new URLSearchParams();
          for (const [k, v] of Object.entries(toolArgs)) qs.set(k, String(v));
          const qsStr = qs.toString();
          if (qsStr) originUrl += `?${qsStr}`;
        } else {
          originBody = JSON.stringify(toolArgs);
        }

        const originRes = await fetchFn(originUrl, {
          method: matchedRoute.method,
          headers: {
            'Content-Type': 'application/json',
            'X-Vectoll-Verified': 'true',
            'X-Vectoll-Receipt-Id': check.claims.jti,
            'X-Vectoll-Agent-Id': check.claims.sub,
            'X-Vectoll-Paid-Amount': `${check.claims.amt} ${check.claims.cur}`,
            'X-Vectoll-Rail': check.claims.rail,
          },
          body: originBody,
        });
        const originText = await originRes.text();
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: rpc.id ?? 1,
            result: {
              content: [{ type: 'text', text: originText }],
              isError: !originRes.ok,
            },
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'PAYMENT-RESPONSE': createPaymentResponseHeader(check.claims),
            },
          },
        );
      }
    }

    // 3. Standard HTTP Reverse Proxy Flow
    const route = matchRoute(config.routes, request.method, pathname);
    const rawBody =
      request.method === 'GET' || request.method === 'HEAD'
        ? new Uint8Array(0)
        : new Uint8Array(await request.arrayBuffer());

    const headerObj: Record<string, string> = {};
    request.headers.forEach((v, k) => {
      headerObj[k.toLowerCase()] = v;
    });

    // Unmetered route or verified Human Browser passthrough -> proxy directly after stripping spoofed headers
    if (
      !route ||
      route.price === 0 ||
      classifyTraffic(headerObj, Boolean(route.human_passthrough), pathname) === 'human'
    ) {
      metrics.humanPassthrough++;
      return forwardToOrigin(fetchFn, config.service.origin, request, target, rawBody);
    }

    // Agent on metered route -> check PAYMENT-SIGNATURE
    const reqHash = computeRequestHash(request.method, target, rawBody);
    const cur = route.currency ?? config.settlement.default_currency;
    const dec = getCurrencyDecimals(cur, route.decimals);
    const sigHeader =
      request.headers.get('payment-signature') ?? request.headers.get('authorization');

    if (!sigHeader || (!sigHeader.startsWith('vrt1.') && !/^vectoll\s+vrt1\./i.test(sigHeader))) {
      metrics.challenged402++;
      await ensureFacilitatorKey().catch(() => undefined);
      const challenge = createPaymentChallenge({
        service: config.service.name,
        resource: target,
        method: request.method,
        reqHash,
        amount: route.price,
        currency: cur,
        decimals: dec,
        settlementMode: route.settlement_mode ?? 'instant',
        requireMandate: route.require_mandate ?? false,
        hitlThreshold: route.hitl_threshold ?? null,
        facilitatorUrl: config.settlement.facilitator_url,
        facilitatorKid: cachedKid,
        acceptedRails: config.settlement.accepted_rails,
        ttlSeconds: config.security?.challenge_ttl_seconds ?? 60,
      });

      return new Response(JSON.stringify(challenge), {
        status: 402,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
          'PAYMENT-REQUIRED': encodePaymentHeader(challenge),
          'WWW-Authenticate': `Vectoll realm="${config.service.name}", challengeId="${challenge.challengeId}", facilitator="${config.settlement.facilitator_url}"`,
        },
      });
    }

    let pubKey = await ensureFacilitatorKey();
    let check = verifyVrt(sigHeader, pubKey, {
      expectedAudience: config.service.name,
      expectedReqHash: reqHash,
      minAmount: route.price,
      expectedCurrency: cur,
    });
    if (!check.valid && check.code === 'ERR_UNKNOWN_KID' && !explicitSingleKey) {
      await refreshJwks().catch(() => undefined);
      pubKey = await ensureFacilitatorKey();
      check = verifyVrt(sigHeader, pubKey, {
        expectedAudience: config.service.name,
        expectedReqHash: reqHash,
        minAmount: route.price,
        expectedCurrency: cur,
      });
    }

    if (!check.valid) {
      metrics.rejectedInvalid++;
      return new Response(JSON.stringify({ error: check.code, reason: check.reason }), {
        status: 402,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }

    if (!(await replayStore.consume(check.claims.jti, check.claims.exp))) {
      metrics.rejectedReplay++;
      return new Response(
        JSON.stringify({ error: 'ERR_RECEIPT_REPLAYED', reason: 'VRT receipt has already been spent' }),
        { status: 402, headers: { 'Content-Type': 'application/json; charset=utf-8' } },
      );
    }

    metrics.verified200++;

    const originRes = await forwardToOrigin(fetchFn, config.service.origin, request, target, rawBody, {
      'X-Vectoll-Verified': 'true',
      'X-Vectoll-Receipt-Id': check.claims.jti,
      'X-Vectoll-Agent-Id': check.claims.sub,
      'X-Vectoll-Paid-Amount': `${check.claims.amt} ${check.claims.cur}`,
      'X-Vectoll-Rail': check.claims.rail,
      ...(check.claims.esc ? { 'X-Vectoll-Escrow-Id': check.claims.esc } : {}),
    });

    const outHeaders = new Headers(originRes.headers);
    outHeaders.set('PAYMENT-RESPONSE', createPaymentResponseHeader(check.claims));

    // Optional HTML-to-Structured JSON / Markdown Agent Translation
    const transformMode = route.agent_transform ?? 'none';
    const originCt = originRes.headers.get('content-type') ?? '';
    if (transformMode !== 'none' && originCt.includes('text/html')) {
      const rawHtml = await originRes.text();
      const extracted = extractStructuredDocument(rawHtml, target);
      if (transformMode === 'markdown' || (request.headers.get('accept') ?? '').includes('text/markdown')) {
        outHeaders.set('Content-Type', 'text/markdown; charset=utf-8');
        return new Response(extracted.markdown, { status: originRes.status, headers: outHeaders });
      }
      outHeaders.set('Content-Type', 'application/json; charset=utf-8');
      return new Response(
        JSON.stringify({ ...extracted, receiptId: check.claims.jti, paidBy: check.claims.sub }),
        { status: originRes.status, headers: outHeaders },
      );
    }

    return new Response(originRes.body, {
      status: originRes.status,
      headers: outHeaders,
    });
  };
}

async function forwardToOrigin(
  fetchFn: typeof fetch,
  originBase: string,
  incoming: Request,
  target: string,
  rawBody: Uint8Array,
  trustedHeaders: Record<string, string> = {},
): Promise<Response> {
  const cleanHeaders = new Headers();
  incoming.headers.forEach((v, k) => {
    const lk = k.toLowerCase();
    // Strip untrusted X-Vectoll-* or hop-by-hop headers
    if (lk.startsWith('x-vectoll-') || lk === 'host' || lk === 'content-length') return;
    cleanHeaders.set(k, v);
  });
  for (const [k, v] of Object.entries(trustedHeaders)) {
    cleanHeaders.set(k, v);
  }
  const dest = `${originBase.replace(/\/$/, '')}${target}`;
  try {
    return await fetchFn(dest, {
      method: incoming.method,
      headers: cleanHeaders,
      body: rawBody.length > 0 ? Buffer.from(rawBody) : undefined,
    });
  } catch (err) {
    return new Response(
      JSON.stringify({
        error: 'ERR_ORIGIN_UNREACHABLE',
        origin: originBase,
        target,
        message: `Upstream origin ${originBase} is not reachable (${err instanceof Error ? err.message : String(err)})`,
        discoveryManifest: '/.well-known/vectoll.json',
        mcpEndpoint: '/mcp',
      }),
      { status: 502, headers: { 'Content-Type': 'application/json; charset=utf-8' } },
    );
  }
}

export function createNodeGateServer(options: VectollGateOptions): http.Server {
  const edgeHandler = createVectollEdgeHandler(options);
  return http.createServer(async (req, res) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      const bodyBuf = Buffer.concat(chunks);
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === 'string') headers.set(k, v);
        else if (Array.isArray(v)) headers.set(k, v.join(', '));
      }
      const fullUrl = `http://${req.headers.host ?? 'localhost'}${req.url ?? '/'}`;
      const webReq = new Request(fullUrl, {
        method: req.method ?? 'GET',
        headers,
        body: req.method === 'GET' || req.method === 'HEAD' ? undefined : bodyBuf,
      });

      const webRes = await edgeHandler(webReq);
      const outHeaders: Record<string, string> = {};
      webRes.headers.forEach((val, key) => {
        outHeaders[key] = val;
      });
      res.writeHead(webRes.status, outHeaders);
      const outBuf = Buffer.from(await webRes.arrayBuffer());
      res.end(outBuf);
    } catch (err) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
    }
  });
}
