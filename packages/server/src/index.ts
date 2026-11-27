import http from 'node:http';
import {
  buildDiscoveryManifest,
  classifyTraffic,
  computeRequestHash,
  createPaymentChallenge,
  createPaymentResponseHeader,
  DEFAULT_GLOBAL_RAILS,
  ed25519Verify,
  encodePaymentHeader,
  normalizeRouteMap,
  parsePrice,
  verifyVrt,
  type ConciseRouteValue,
  type VectollConfig,
  type VectollRouteConfig,
  type VrtClaims,
} from '@vectoll/core';
import { ReplayStore } from '@vectoll/edge';
import { VectollFacilitator } from '@vectoll/facilitator';

export interface VectollMiddlewareOptions {
  /** Logical service name (defaults to "vectoll-app") */
  name?: string;
  /** Route pricing map, e.g. { "GET /api/search": "$0.005", "GET /blog/*": { price: "$0.001", browsers: "free" } } */
  routes: Record<string, ConciseRouteValue>;
  /** Default currency when omitted in prices (defaults to "USD") */
  currency?: string;
  /** Accepted payment rails (defaults to all 9 global rails) */
  rails?: string[];
  /**
   * External Facilitator URL (e.g. "https://facilitator.vectoll.com" or "http://localhost:4021").
   * When omitted, runs a zero-config embedded Facilitator right on your own server under `/_vectoll/*`!
   */
  facilitatorUrl?: string;
  /** Explicit Facilitator Ed25519 public key (auto-resolved when omitted) */
  facilitatorPublicKey?: string;
  facilitatorKid?: string;
  /** SQLite path when using embedded single-port facilitator (defaults to ":memory:") */
  dbPath?: string;
}

export interface VectollAugmentedRequest extends http.IncomingMessage {
  vectoll?: VrtClaims;
  body?: unknown;
}

function matchRoute(
  routes: VectollRouteConfig[],
  method: string,
  pathname: string,
): VectollRouteConfig | undefined {
  const m = method.toUpperCase();
  for (const r of routes) {
    if (r.method !== m && r.method !== '*') continue;
    if (r.path === pathname) return r;
    if (r.path.endsWith('/*')) {
      const prefix = r.path.slice(0, -1);
      if (pathname.startsWith(prefix) || pathname === prefix.slice(0, -1)) return r;
    }
  }
  return undefined;
}

async function readRawNodeBody(req: VectollAugmentedRequest): Promise<Uint8Array> {
  if (req.method === 'GET' || req.method === 'HEAD') {
    return new Uint8Array(0);
  }
  // If an upstream body-parser (like express.json()) already consumed req stream:
  if (req.body !== undefined) {
    if (Buffer.isBuffer(req.body) || req.body instanceof Uint8Array) {
      return new Uint8Array(req.body);
    }
    if (typeof req.body === 'string') {
      return new Uint8Array(Buffer.from(req.body, 'utf8'));
    }
    return new Uint8Array(Buffer.from(JSON.stringify(req.body), 'utf8'));
  }
  if (req.readableEnded) {
    return new Uint8Array(0);
  }
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const combined = Buffer.concat(chunks);
  // Populate req.body if JSON so downstream handlers that don't re-read stream still have parsed body
  const ct = req.headers['content-type'] ?? '';
  if (combined.length > 0 && ct.includes('application/json') && req.body === undefined) {
    try {
      req.body = JSON.parse(combined.toString('utf8'));
    } catch {
      // leave raw
    }
  }
  return new Uint8Array(combined);
}

/**
 * Drop-in Node.js / Express / Connect / Fastify middleware.
 * Protects routes on your existing port with zero separate proxy servers required.
 */
export function vectollMiddleware(options: VectollMiddlewareOptions) {
  const serviceName = options.name ?? 'vectoll-app';
  const defaultCurrency = (options.currency ?? 'USD').toUpperCase();
  const acceptedRails =
    options.rails && !options.rails.includes('*') ? options.rails : DEFAULT_GLOBAL_RAILS;
  const normalizedRoutes = normalizeRouteMap(options.routes, defaultCurrency);
  const replay = new ReplayStore();

  // Zero-ops single-port mode when no external facilitatorUrl is configured!
  const embeddedFac = options.facilitatorUrl
    ? null
    : new VectollFacilitator({ dbPath: options.dbPath ?? ':memory:' });
  const embeddedHttpSrv = embeddedFac ? embeddedFac.createHttpServer() : null;

  let cachedPubKey =
    options.facilitatorPublicKey ?? (embeddedFac ? embeddedFac.keyPair.publicKeyBase64Url : '');
  let cachedKid = options.facilitatorKid ?? (embeddedFac ? embeddedFac.keyPair.kid : 'fac-key-1');

  const ensurePublicKey = async (facBaseUrl: string): Promise<string> => {
    if (cachedPubKey) return cachedPubKey;
    const res = await fetch(`${facBaseUrl.replace(/\/$/, '')}/.well-known/jwks.json`);
    if (res.ok) {
      const doc = (await res.json()) as { keys?: Array<{ kid?: string; x?: string }> };
      if (doc.keys?.[0]?.x) {
        cachedPubKey = doc.keys[0].x;
        if (doc.keys[0].kid) cachedKid = doc.keys[0].kid;
      }
    }
    if (!cachedPubKey) throw new Error('Unable to resolve Facilitator Ed25519 public key');
    return cachedPubKey;
  };

  return async function middleware(
    req: VectollAugmentedRequest,
    res: http.ServerResponse,
    next?: (err?: unknown) => void,
  ): Promise<void> {
    try {
      const proto = (req.headers['x-forwarded-proto'] as string | undefined) ?? 'http';
      const host = req.headers.host ?? '127.0.0.1';
      const baseOrigin = `${proto}://${host}`;
      const urlObj = new URL(req.url ?? '/', baseOrigin);
      const pathname = urlObj.pathname;
      const target = `${urlObj.pathname}${urlObj.search}`;

      const facUrl = options.facilitatorUrl ?? `${baseOrigin}/_vectoll`;
      if (embeddedFac) {
        embeddedFac.issuerUrl = facUrl;
      }

      // 1. Embedded single-port Facilitator endpoints (/_vectoll/*)
      if (embeddedHttpSrv && pathname.startsWith('/_vectoll/')) {
        req.url = pathname.slice('/_vectoll'.length) + urlObj.search;
        embeddedHttpSrv.emit('request', req, res);
        return;
      }

      // 2. Auto-served Discovery Manifest (/.well-known/vectoll.json)
      if (req.method === 'GET' && pathname === '/.well-known/vectoll.json') {
        await ensurePublicKey(facUrl).catch(() => undefined);
        const cfg: VectollConfig = {
          version: '1.0',
          service: { name: serviceName, origin: baseOrigin, enable_mcp: false },
          settlement: {
            facilitator_url: facUrl,
            facilitator_kid: cachedKid,
            facilitator_public_key: cachedPubKey,
            default_currency: defaultCurrency,
            accepted_rails: acceptedRails,
          },
          routes: normalizedRoutes,
        };
        const manifest = buildDiscoveryManifest(cfg, {
          facilitatorPublicKey: cachedPubKey,
          facilitatorKid: cachedKid,
        });
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify(manifest, null, 2));
        return;
      }

      // Strip any untrusted client X-Vectoll-* headers
      for (const k of Object.keys(req.headers)) {
        if (k.toLowerCase().startsWith('x-vectoll-')) {
          delete req.headers[k];
        }
      }

      const route = matchRoute(normalizedRoutes, req.method ?? 'GET', pathname);
      const headerMap: Record<string, string | undefined> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        headerMap[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
      }

      if (
        !route ||
        route.price === 0 ||
        classifyTraffic(headerMap, Boolean(route.human_passthrough), pathname) === 'human'
      ) {
        if (next) next();
        return;
      }

      const rawBody = await readRawNodeBody(req);
      const reqHash = computeRequestHash(req.method ?? 'GET', target, rawBody);
      const sigHeader = headerMap['payment-signature'] ?? headerMap['authorization'];

      if (
        !sigHeader ||
        (!sigHeader.startsWith('vrt1.') && !/^vectoll\s+vrt1\./i.test(sigHeader))
      ) {
        await ensurePublicKey(facUrl).catch(() => undefined);
        const challenge = createPaymentChallenge({
          service: serviceName,
          resource: target,
          method: req.method ?? 'GET',
          reqHash,
          amount: route.price,
          currency: route.currency ?? defaultCurrency,
          decimals: route.decimals ?? 6,
          settlementMode: route.settlement_mode ?? 'instant',
          requireMandate: route.require_mandate ?? false,
          hitlThreshold: route.hitl_threshold ?? null,
          facilitatorUrl: facUrl,
          facilitatorKid: cachedKid,
          acceptedRails,
        });
        res.writeHead(402, {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
          'PAYMENT-REQUIRED': encodePaymentHeader(challenge),
          'WWW-Authenticate': `Vectoll realm="${serviceName}", challengeId="${challenge.challengeId}", facilitator="${facUrl}"`,
        });
        res.end(JSON.stringify(challenge));
        return;
      }

      const pubKey = await ensurePublicKey(facUrl);
      const check = verifyVrt(sigHeader, pubKey, {
        expectedAudience: serviceName,
        expectedReqHash: reqHash,
        minAmount: route.price,
        expectedCurrency: route.currency ?? defaultCurrency,
      });

      if (!check.valid) {
        res.writeHead(402, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: check.code, reason: check.reason }));
        return;
      }

      if (!replay.consume(check.claims.jti, check.claims.exp)) {
        res.writeHead(402, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(
          JSON.stringify({
            error: 'ERR_RECEIPT_REPLAYED',
            reason: 'VRT receipt has already been consumed',
          }),
        );
        return;
      }

      req.vectoll = check.claims;
      req.headers['x-vectoll-verified'] = 'true';
      req.headers['x-vectoll-receipt-id'] = check.claims.jti;
      req.headers['x-vectoll-agent-id'] = check.claims.sub;
      res.setHeader('PAYMENT-RESPONSE', createPaymentResponseHeader(check.claims));

      if (next) next();
    } catch (err) {
      if (next) {
        next(err);
      } else {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
    }
  };
}

// ─── Web Fetch / Next.js App Router / Hono / Cloudflare Workers Wrapper ───

export interface WithVectollOptions {
  price: string | number;
  service?: string;
  facilitatorUrl: string;
  facilitatorPublicKey?: string;
  facilitatorKid?: string;
  rails?: string[];
  browsers?: 'free' | 'paid';
}

/**
 * One-line route wrapper for Next.js Route Handlers, Hono, Cloudflare Workers, Bun, and Deno:
 *
 *   export const GET = withVectoll({ price: '$0.005', facilitatorUrl: '...' }, async (req, receipt) => {
 *     return Response.json({ ok: true, paidBy: receipt?.sub });
 *   });
 */
export function withVectoll(
  priceOrOptions: string | WithVectollOptions,
  handler: (request: Request, receipt: VrtClaims | null) => Promise<Response> | Response,
): (request: Request) => Promise<Response> {
  const opts: WithVectollOptions =
    typeof priceOrOptions === 'string'
      ? {
          price: priceOrOptions,
          facilitatorUrl: process.env.VECTOLL_FACILITATOR_URL ?? 'http://127.0.0.1:4021',
        }
      : priceOrOptions;

  const parsed = parsePrice(opts.price);
  const serviceName = opts.service ?? process.env.VECTOLL_SERVICE_NAME ?? 'vectoll-app';
  const acceptedRails = opts.rails ?? DEFAULT_GLOBAL_RAILS;
  const replay = new ReplayStore();
  let pubKey = opts.facilitatorPublicKey ?? process.env.VECTOLL_FACILITATOR_PUBLIC_KEY ?? '';
  let kid = opts.facilitatorKid ?? 'fac-key-1';

  const ensureKey = async (): Promise<string> => {
    if (pubKey) return pubKey;
    const res = await fetch(`${opts.facilitatorUrl.replace(/\/$/, '')}/.well-known/jwks.json`);
    if (res.ok) {
      const jwks = (await res.json()) as { keys?: Array<{ kid?: string; x?: string }> };
      if (jwks.keys?.[0]?.x) {
        pubKey = jwks.keys[0].x;
        if (jwks.keys[0].kid) kid = jwks.keys[0].kid;
      }
    }
    if (!pubKey) throw new Error('Unable to resolve Facilitator Ed25519 public key');
    return pubKey;
  };

  return async function wrappedFetchHandler(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const target = `${url.pathname}${url.search}`;
    const hdrObj: Record<string, string> = {};
    request.headers.forEach((v, k) => {
      hdrObj[k.toLowerCase()] = v;
    });

    if (
      parsed.amount === 0 ||
      classifyTraffic(hdrObj, opts.browsers === 'free', url.pathname) === 'human'
    ) {
      return handler(request, null);
    }

    const cloneForHash = request.clone();
    const rawBody =
      request.method === 'GET' || request.method === 'HEAD'
        ? new Uint8Array(0)
        : new Uint8Array(await cloneForHash.arrayBuffer());
    const reqHash = computeRequestHash(request.method, target, rawBody);

    const sigHeader =
      request.headers.get('payment-signature') ?? request.headers.get('authorization');

    if (
      !sigHeader ||
      (!sigHeader.startsWith('vrt1.') && !/^vectoll\s+vrt1\./i.test(sigHeader))
    ) {
      await ensureKey().catch(() => undefined);
      const challenge = createPaymentChallenge({
        service: serviceName,
        resource: target,
        method: request.method,
        reqHash,
        amount: parsed.amount,
        currency: parsed.currency,
        decimals: parsed.decimals,
        facilitatorUrl: opts.facilitatorUrl,
        facilitatorKid: kid,
        acceptedRails,
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

    const resolvedKey = await ensureKey();
    const check = verifyVrt(sigHeader, resolvedKey, {
      expectedAudience: serviceName,
      expectedReqHash: reqHash,
      minAmount: parsed.amount,
      expectedCurrency: parsed.currency,
    });
    if (!check.valid) {
      return new Response(JSON.stringify({ error: check.code, reason: check.reason }), {
        status: 402,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    }
    if (!replay.consume(check.claims.jti, check.claims.exp)) {
      return new Response(
        JSON.stringify({ error: 'ERR_RECEIPT_REPLAYED', reason: 'VRT already consumed' }),
        { status: 402, headers: { 'Content-Type': 'application/json; charset=utf-8' } },
      );
    }

    const upstreamRes = await handler(request, check.claims);
    const outHeaders = new Headers(upstreamRes.headers);
    outHeaders.set('PAYMENT-RESPONSE', createPaymentResponseHeader(check.claims));
    return new Response(upstreamRes.body, {
      status: upstreamRes.status,
      headers: outHeaders,
    });
  };
}

// ─── Webhook Signature Verification (for Merchant Backends) ────────────────

export function verifyWebhookSignature(
  rawBody: string,
  headers: Record<string, string | undefined>,
  facilitatorPublicKey: Uint8Array | string,
  maxSkewSeconds = 300,
  nowSeconds = Math.floor(Date.now() / 1000),
): { valid: boolean; event?: { id: string; type: string; data: unknown }; reason?: string } {
  const norm: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(headers)) norm[k.toLowerCase()] = v;

  const tsRaw = norm['x-vectoll-webhook-timestamp'];
  const sig = norm['x-vectoll-webhook-signature'];
  if (!tsRaw || !sig) {
    return { valid: false, reason: 'Missing X-Vectoll-Webhook-Timestamp or X-Vectoll-Webhook-Signature' };
  }
  const ts = Number(tsRaw);
  if (!Number.isFinite(ts) || Math.abs(nowSeconds - ts) > maxSkewSeconds) {
    return { valid: false, reason: 'Webhook timestamp outside tolerance window' };
  }
  const sigInput = `vectoll-webhook/v1.${ts}.${rawBody}`;
  if (!ed25519Verify(facilitatorPublicKey, sigInput, sig)) {
    return { valid: false, reason: 'Invalid Ed25519 webhook signature' };
  }
  try {
    return { valid: true, event: JSON.parse(rawBody) as { id: string; type: string; data: unknown } };
  } catch {
    return { valid: false, reason: 'Malformed webhook JSON payload' };
  }
}

// ─── Standalone Metered MCP Server SDK ─────────────────────────────────────

export interface MeteredMcpToolDef<TArgs = Record<string, unknown>> {
  price: string | number;
  currency?: string;
  description: string;
  inputSchema?: Record<string, unknown>;
  handler: (args: TArgs, receipt: VrtClaims | null) => Promise<unknown> | unknown;
}

export interface MeteredMcpServerOptions {
  name: string;
  version?: string;
  facilitatorUrl?: string;
  facilitatorPublicKey?: string;
  facilitatorKid?: string;
  rails?: string[];
  dbPath?: string;
}

export function createMeteredMcpServer(options: MeteredMcpServerOptions) {
  const tools = new Map<
    string,
    {
      name: string;
      description: string;
      amount: number;
      currency: string;
      decimals: number;
      inputSchema: Record<string, unknown>;
      handler: (args: Record<string, unknown>, receipt: VrtClaims | null) => Promise<unknown> | unknown;
    }
  >();

  const acceptedRails = options.rails ?? DEFAULT_GLOBAL_RAILS;
  const replay = new ReplayStore();
  const embeddedFac = options.facilitatorUrl
    ? null
    : new VectollFacilitator({ dbPath: options.dbPath ?? ':memory:' });
  const embeddedFacHttp = embeddedFac ? embeddedFac.createHttpServer() : null;

  let cachedPubKey =
    options.facilitatorPublicKey ?? (embeddedFac ? embeddedFac.keyPair.publicKeyBase64Url : '');
  let cachedKid = options.facilitatorKid ?? (embeddedFac ? embeddedFac.keyPair.kid : 'fac-key-1');

  const ensureKey = async (facBase: string): Promise<string> => {
    if (cachedPubKey) return cachedPubKey;
    const res = await fetch(`${facBase.replace(/\/$/, '')}/.well-known/jwks.json`);
    if (res.ok) {
      const jwks = (await res.json()) as { keys?: Array<{ kid?: string; x?: string }> };
      if (jwks.keys?.[0]?.x) {
        cachedPubKey = jwks.keys[0].x;
        if (jwks.keys[0].kid) cachedKid = jwks.keys[0].kid;
      }
    }
    if (!cachedPubKey) throw new Error('Unable to resolve Facilitator public key');
    return cachedPubKey;
  };

  return {
    facilitator: embeddedFac,

    tool<TArgs = Record<string, unknown>>(
      name: string,
      config: Omit<MeteredMcpToolDef<TArgs>, 'handler'>,
      handler: (args: TArgs, receipt: VrtClaims | null) => Promise<unknown> | unknown,
    ) {
      const parsed = parsePrice(config.price, config.currency);
      tools.set(name, {
        name,
        description: config.description,
        amount: parsed.amount,
        currency: parsed.currency,
        decimals: parsed.decimals,
        inputSchema: config.inputSchema ?? { type: 'object', additionalProperties: true },
        handler: handler as (args: Record<string, unknown>, receipt: VrtClaims | null) => Promise<unknown>,
      });
      return this;
    },

    async handleFetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      const baseOrigin = `${url.protocol}//${url.host}`;
      const facUrl = options.facilitatorUrl ?? `${baseOrigin}/_vectoll`;
      if (embeddedFac) embeddedFac.issuerUrl = facUrl;

      if (request.method === 'GET' && url.pathname === '/mcp') {
        return Response.json({
          protocolVersion: '2025-06-18',
          serverInfo: { name: options.name, version: options.version ?? '0.1.0' },
          tools: Array.from(tools.values()).map((t) => ({
            name: t.name,
            description: t.description,
            amount: t.amount,
            currency: t.currency,
            decimals: t.decimals,
          })),
        });
      }

      if (request.method !== 'POST' || url.pathname !== '/mcp') {
        return Response.json({ error: 'Not Found' }, { status: 404 });
      }

      const rawBytes = new Uint8Array(await request.arrayBuffer());
      const rpc = JSON.parse(Buffer.from(rawBytes).toString('utf8')) as {
        id?: unknown;
        method?: string;
        params?: Record<string, unknown>;
      };

      if (rpc.method === 'initialize') {
        return Response.json({
          jsonrpc: '2.0',
          id: rpc.id ?? 1,
          result: {
            protocolVersion: '2025-06-18',
            serverInfo: { name: options.name, version: options.version ?? '0.1.0' },
            capabilities: { tools: {} },
          },
        });
      }

      if (rpc.method === 'tools/list') {
        return Response.json({
          jsonrpc: '2.0',
          id: rpc.id ?? 1,
          result: {
            tools: Array.from(tools.values()).map((t) => ({
              name: t.name,
              description: t.description,
              inputSchema: t.inputSchema,
              _meta: {
                vectollPricing: { amount: t.amount, currency: t.currency, decimals: t.decimals },
              },
            })),
          },
        });
      }

      if (rpc.method === 'tools/call') {
        const toolName = String(rpc.params?.name ?? '');
        const toolArgs = (rpc.params?.arguments ?? {}) as Record<string, unknown>;
        const def = tools.get(toolName);
        if (!def) {
          return Response.json(
            { jsonrpc: '2.0', id: rpc.id ?? 1, error: { code: -32601, message: `Unknown tool ${toolName}` } },
            { status: 404 },
          );
        }

        let verifiedClaims: VrtClaims | null = null;
        if (def.amount > 0) {
          const reqHash = computeRequestHash('POST', '/mcp', rawBytes);
          const sigHdr =
            request.headers.get('payment-signature') ?? request.headers.get('authorization');

          if (!sigHdr) {
            await ensureKey(facUrl).catch(() => undefined);
            const chg = createPaymentChallenge({
              service: options.name,
              resource: '/mcp',
              method: 'POST',
              reqHash,
              amount: def.amount,
              currency: def.currency,
              decimals: def.decimals,
              facilitatorUrl: facUrl,
              facilitatorKid: cachedKid,
              acceptedRails,
            });
            return new Response(JSON.stringify(chg), {
              status: 402,
              headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Cache-Control': 'no-store',
                'PAYMENT-REQUIRED': encodePaymentHeader(chg),
              },
            });
          }

          const pub = await ensureKey(facUrl);
          const check = verifyVrt(sigHdr, pub, {
            expectedAudience: options.name,
            expectedReqHash: reqHash,
            minAmount: def.amount,
            expectedCurrency: def.currency,
          });
          if (!check.valid) {
            return Response.json({ error: check.code, reason: check.reason }, { status: 402 });
          }
          if (!replay.consume(check.claims.jti, check.claims.exp)) {
            return Response.json({ error: 'ERR_RECEIPT_REPLAYED' }, { status: 402 });
          }
          verifiedClaims = check.claims;
        }

        const out = await def.handler(toolArgs, verifiedClaims);
        const text = typeof out === 'string' ? out : JSON.stringify(out);
        const headers: Record<string, string> = { 'Content-Type': 'application/json; charset=utf-8' };
        if (verifiedClaims) {
          headers['PAYMENT-RESPONSE'] = createPaymentResponseHeader(verifiedClaims);
        }
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: rpc.id ?? 1,
            result: { content: [{ type: 'text', text }], isError: false },
          }),
          { status: 200, headers },
        );
      }

      return Response.json(
        { jsonrpc: '2.0', id: rpc.id ?? 1, error: { code: -32601, message: 'Method not supported' } },
        { status: 400 },
      );
    },

    createNodeServer(): http.Server {
      return http.createServer(async (req, res) => {
        const proto = (req.headers['x-forwarded-proto'] as string | undefined) ?? 'http';
        const host = req.headers.host ?? '127.0.0.1';
        const urlObj = new URL(req.url ?? '/', `${proto}://${host}`);

        if (embeddedFacHttp && urlObj.pathname.startsWith('/_vectoll/')) {
          req.url = urlObj.pathname.slice('/_vectoll'.length) + urlObj.search;
          embeddedFacHttp.emit('request', req, res);
          return;
        }

        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
        const headers = new Headers();
        for (const [k, v] of Object.entries(req.headers)) {
          if (typeof v === 'string') headers.set(k, v);
        }
        const webRes = await this.handleFetch(
          new Request(urlObj.toString(), {
            method: req.method ?? 'GET',
            headers,
            body: req.method === 'GET' || req.method === 'HEAD' ? undefined : Buffer.concat(chunks),
          }),
        );
        const outHdrs: Record<string, string> = {};
        webRes.headers.forEach((v, k) => (outHdrs[k] = v));
        res.writeHead(webRes.status, outHdrs);
        res.end(Buffer.from(await webRes.arrayBuffer()));
      });
    },
  };
}
