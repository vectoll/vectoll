import fs from 'node:fs';
import path from 'node:path';
import { parsePrice, parseRouteKey } from './pricing.js';
import { getCurrencyDecimals, type SettlementMode, type VectollConfig, type VectollRouteConfig } from './types.js';

export const DEFAULT_GLOBAL_RAILS = [
  'x402_usdc',
  'stripe',
  'sepa_instant',
  'ach_fednow',
  'pix_upi',
  'mpesa',
  'momo',
  'airtel_money',
  'voucher',
];

export type ConciseRouteValue =
  | string
  | number
  | {
      price: string | number;
      currency?: string;
      decimals?: number;
      browsers?: 'free' | 'paid';
      human_passthrough?: boolean;
      transform?: 'none' | 'structured' | 'markdown';
      agent_transform?: 'none' | 'structured' | 'markdown';
      mode?: SettlementMode;
      settlement_mode?: SettlementMode;
      mandate?: boolean;
      require_mandate?: boolean;
      approve_above?: string | number | null;
      hitl_threshold?: number | null;
      mcp?: string;
      mcp_tool?: string;
      description?: string;
      mcp_description?: string;
    };

export interface ShorthandVectollConfig {
  name?: string;
  origin: string;
  listen?: string;
  facilitator?: string;
  currency?: string;
  rails?: string[];
  mcp?: boolean;
  routes: Record<string, ConciseRouteValue> | VectollRouteConfig[];
}

function stripInlineComment(line: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble) {
      if (i === 0 || /\s/.test(line[i - 1]!)) {
        return line.slice(0, i).trimEnd();
      }
    }
  }
  return line.trimEnd();
}

function parseInlineObject(inner: string): Record<string, unknown> {
  const obj: Record<string, unknown> = {};
  if (!inner.trim()) return obj;
  // Split by comma outside quotes
  const parts: string[] = [];
  let cur = '';
  let inS = false;
  let inD = false;
  for (const ch of inner) {
    if (ch === "'" && !inD) inS = !inS;
    else if (ch === '"' && !inS) inD = !inD;
    if (ch === ',' && !inS && !inD) {
      parts.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) parts.push(cur);

  for (const part of parts) {
    const idx = part.indexOf(':');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim().replace(/^['"]|['"]$/g, '');
    const v = part.slice(idx + 1).trim();
    obj[k] = parseScalar(v);
  }
  return obj;
}

function parseScalar(raw: string): unknown {
  const val = raw.trim();
  if (val === '' || val === 'null' || val === '~') return null;
  if (val === 'true') return true;
  if (val === 'false') return false;
  if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
    return val.slice(1, -1);
  }
  if (/^-?\d+$/.test(val)) {
    return Number(val);
  }
  if (val.startsWith('[') && val.endsWith(']')) {
    const inner = val.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(',').map((s) => parseScalar(s));
  }
  if (val.startsWith('{') && val.endsWith('}')) {
    return parseInlineObject(val.slice(1, -1));
  }
  return val;
}

/**
 * Supports BOTH:
 * 1. Ultra-clean 5-line shorthand vectoll.yaml:
 *    origin: "http://localhost:3000"
 *    routes:
 *      GET /api/search: "$0.005"
 *      GET /blog/*: { price: "$0.002", browsers: "free" }
 *
 * 2. Full canonical vectoll.yaml (version, service, settlement, routes array).
 */
export function parseVectollConfig(rawContent: string, defaultServiceName = 'vectoll-service'): VectollConfig {
  const trimmed = rawContent.trim();
  if (trimmed.startsWith('{')) {
    return normalizeAnyConfig(JSON.parse(trimmed) as Record<string, unknown>, defaultServiceName);
  }

  const lines = rawContent
    .split(/\r?\n/)
    .map((l) => stripInlineComment(l))
    .filter((l) => l.trim().length > 0);

  const root: Record<string, unknown> = {};
  let currentSection: string | null = null;
  let currentSubKey: string | null = null;
  let currentListObject: Record<string, unknown> | null = null;

  for (const line of lines) {
    const indent = line.search(/\S/);
    const content = line.trim();

    if (indent === 0) {
      currentSubKey = null;
      currentListObject = null;
      const colonIdx = content.indexOf(':');
      if (colonIdx === -1) throw new Error(`Invalid top-level YAML line: ${line}`);
      const key = content.slice(0, colonIdx).trim().replace(/^['"]|['"]$/g, '');
      const rest = content.slice(colonIdx + 1).trim();
      if (rest === '') {
        currentSection = key;
        root[key] = undefined;
      } else {
        currentSection = null;
        root[key] = parseScalar(rest);
      }
      continue;
    }

    if (!currentSection) {
      throw new Error(`Unexpected indented YAML line: ${line}`);
    }

    if (indent === 2 && content.startsWith('- ')) {
      if (!Array.isArray(root[currentSection])) {
        root[currentSection] = [];
      }
      const arr = root[currentSection] as unknown[];
      const itemRest = content.slice(2).trim();
      const colonIdx = itemRest.indexOf(':');
      if (colonIdx !== -1) {
        const k = itemRest.slice(0, colonIdx).trim();
        const v = itemRest.slice(colonIdx + 1).trim();
        currentListObject = { [k]: parseScalar(v) };
        arr.push(currentListObject);
      } else {
        currentListObject = null;
        arr.push(parseScalar(itemRest));
      }
      continue;
    }

    if (indent >= 4 && currentListObject && !content.startsWith('- ')) {
      const colonIdx = content.indexOf(':');
      if (colonIdx === -1) throw new Error(`Invalid object property line: ${line}`);
      const k = content.slice(0, colonIdx).trim();
      const v = content.slice(colonIdx + 1).trim();
      currentListObject[k] = parseScalar(v);
      continue;
    }

    if (indent === 2 && !content.startsWith('- ')) {
      currentListObject = null;
      if (root[currentSection] === undefined) {
        root[currentSection] = {};
      }
      const sectionObj = root[currentSection] as Record<string, unknown>;
      const colonIdx = content.indexOf(':');
      if (colonIdx === -1) throw new Error(`Invalid section property: ${line}`);
      const k = content.slice(0, colonIdx).trim().replace(/^['"]|['"]$/g, '');
      const v = content.slice(colonIdx + 1).trim();
      if (v === '') {
        currentSubKey = k;
        sectionObj[k] = undefined;
      } else {
        currentSubKey = null;
        sectionObj[k] = parseScalar(v);
      }
      continue;
    }

    if (indent >= 4 && currentSubKey) {
      const sectionObj = root[currentSection] as Record<string, unknown>;
      if (content.startsWith('- ')) {
        if (!Array.isArray(sectionObj[currentSubKey])) {
          sectionObj[currentSubKey] = [];
        }
        (sectionObj[currentSubKey] as unknown[]).push(parseScalar(content.slice(2)));
      } else {
        if (typeof sectionObj[currentSubKey] !== 'object' || sectionObj[currentSubKey] === null || Array.isArray(sectionObj[currentSubKey])) {
          sectionObj[currentSubKey] = {};
        }
        const colonIdx = content.indexOf(':');
        if (colonIdx === -1) throw new Error(`Invalid nested map line: ${line}`);
        const nk = content.slice(0, colonIdx).trim().replace(/^['"]|['"]$/g, '');
        const nv = content.slice(colonIdx + 1).trim();
        (sectionObj[currentSubKey] as Record<string, unknown>)[nk] = parseScalar(nv);
      }
      continue;
    }
  }

  return normalizeAnyConfig(root, defaultServiceName);
}

export function normalizeRouteMap(
  routesMap: Record<string, ConciseRouteValue>,
  defaultCurrency = 'USD',
): VectollRouteConfig[] {
  const out: VectollRouteConfig[] = [];
  for (const [routeSpec, val] of Object.entries(routesMap)) {
    const { method, path: routePath } = parseRouteKey(routeSpec);
    if (typeof val === 'string' || typeof val === 'number') {
      const parsed = parsePrice(val, defaultCurrency);
      out.push({
        path: routePath,
        method,
        price: parsed.amount,
        currency: parsed.currency,
        decimals: parsed.decimals,
        pricing_mode: 'fixed',
        settlement_mode: 'instant',
        require_mandate: false,
        hitl_threshold: null,
        human_passthrough: false,
        mcp_tool: deriveDefaultMcpToolName(method, routePath),
      });
    } else if (val && typeof val === 'object') {
      const explicitCur = val.currency ?? defaultCurrency;
      const parsed = parsePrice(val.price, explicitCur, val.decimals);
      let hitlMinor: number | null = val.hitl_threshold ?? null;
      if (val.approve_above !== undefined && val.approve_above !== null) {
        hitlMinor = parsePrice(val.approve_above, parsed.currency, parsed.decimals).amount;
      }
      const mode: SettlementMode =
        val.mode ?? val.settlement_mode ?? (hitlMinor !== null ? 'escrow' : 'instant');
      const humanFree =
        val.browsers === 'free' ? true : val.browsers === 'paid' ? false : Boolean(val.human_passthrough);
      out.push({
        path: routePath,
        method,
        price: parsed.amount,
        currency: parsed.currency,
        decimals: parsed.decimals,
        pricing_mode: 'fixed',
        settlement_mode: mode,
        require_mandate: val.mandate ?? val.require_mandate ?? mode === 'escrow',
        hitl_threshold: hitlMinor,
        human_passthrough: humanFree,
        agent_transform: val.transform ?? val.agent_transform ?? 'none',
        mcp_tool: val.mcp ?? val.mcp_tool ?? deriveDefaultMcpToolName(method, routePath),
        mcp_description: val.description ?? val.mcp_description,
      });
    }
  }
  return out;
}

function deriveDefaultMcpToolName(method: string, routePath: string): string | undefined {
  if (routePath.includes('*')) return undefined;
  const cleaned = routePath
    .replace(/^\/+/, '')
    .replace(/^api\/(v\d+\/)?/i, '')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
  if (!cleaned) return undefined;
  return `${method.toLowerCase()}_${cleaned}`;
}

function normalizeAnyConfig(raw: Record<string, unknown>, defaultServiceName: string): VectollConfig {
  // Shorthand top-level config: { origin: "http://localhost:3000", routes: { "GET /api/x": "$0.005" } }
  if (typeof raw.origin === 'string' && !raw.service) {
    const defCur = typeof raw.currency === 'string' ? raw.currency.toUpperCase() : 'USD';
    const rails = Array.isArray(raw.rails)
      ? (raw.rails as string[]).flatMap((r) => (r === '*' ? DEFAULT_GLOBAL_RAILS : [r]))
      : DEFAULT_GLOBAL_RAILS;
    const routesInput = raw.routes;
    const routes = Array.isArray(routesInput)
      ? (routesInput as VectollRouteConfig[])
      : normalizeRouteMap((routesInput ?? {}) as Record<string, ConciseRouteValue>, defCur);

    return validateVectollConfig({
      version: '1.0',
      service: {
        name: typeof raw.name === 'string' ? raw.name : defaultServiceName,
        origin: raw.origin,
        listen: typeof raw.listen === 'string' ? raw.listen : ':4020',
        enable_mcp: typeof raw.mcp === 'boolean' ? raw.mcp : true,
      },
      settlement: {
        facilitator_url:
          typeof raw.facilitator === 'string' ? raw.facilitator : 'http://127.0.0.1:4021',
        default_currency: defCur,
        accepted_rails: rails,
      },
      routes,
    });
  }

  // Also support routes map inside canonical config + string prices inside routes array!
  const cfg = raw as unknown as VectollConfig;
  const defCur = cfg.settlement?.default_currency?.toUpperCase() ?? 'USD';
  if (cfg.settlement && (!cfg.settlement.accepted_rails || cfg.settlement.accepted_rails.includes('*'))) {
    cfg.settlement.accepted_rails = DEFAULT_GLOBAL_RAILS;
  }
  if (cfg.routes && !Array.isArray(cfg.routes)) {
    cfg.routes = normalizeRouteMap(cfg.routes as unknown as Record<string, ConciseRouteValue>, defCur);
  }
  return validateVectollConfig(cfg);
}

export function validateVectollConfig(cfg: VectollConfig): VectollConfig {
  if (!cfg.service?.name || !cfg.service?.origin) {
    throw new Error('vectoll.yaml requires origin (or service.name and service.origin)');
  }
  if (!cfg.settlement) {
    cfg.settlement = {
      facilitator_url: 'http://127.0.0.1:4021',
      default_currency: 'USD',
      accepted_rails: DEFAULT_GLOBAL_RAILS,
    };
  }
  if (!cfg.settlement.facilitator_url) {
    cfg.settlement.facilitator_url = 'http://127.0.0.1:4021';
  }
  if (!cfg.settlement.default_currency) {
    cfg.settlement.default_currency = 'USD';
  }
  if (!Array.isArray(cfg.settlement.accepted_rails) || cfg.settlement.accepted_rails.length === 0) {
    cfg.settlement.accepted_rails = DEFAULT_GLOBAL_RAILS;
  }
  if (!Array.isArray(cfg.routes)) {
    throw new Error('vectoll.yaml requires routes');
  }

  cfg.settlement.default_currency = cfg.settlement.default_currency.toUpperCase();
  cfg.settlement.default_decimals = getCurrencyDecimals(
    cfg.settlement.default_currency,
    cfg.settlement.default_decimals,
  );

  cfg.routes = cfg.routes.map((r: VectollRouteConfig & { price: string | number; hitl_threshold?: string | number | null }) => {
    const explicitCur = (r.currency ?? cfg.settlement.default_currency).toUpperCase();
    const parsed = parsePrice(r.price ?? 0, explicitCur, r.decimals);
    let hitl: number | null = null;
    if (r.hitl_threshold !== undefined && r.hitl_threshold !== null) {
      hitl =
        typeof r.hitl_threshold === 'string'
          ? parsePrice(r.hitl_threshold, parsed.currency, parsed.decimals).amount
          : r.hitl_threshold;
    }
    return {
      ...r,
      method: (r.method ?? 'GET').toUpperCase(),
      price: parsed.amount,
      currency: parsed.currency,
      decimals: parsed.decimals,
      pricing_mode: r.pricing_mode ?? 'fixed',
      settlement_mode: r.settlement_mode ?? 'instant',
      require_mandate: r.require_mandate ?? false,
      hitl_threshold: hitl,
      human_passthrough: r.human_passthrough ?? false,
    };
  });
  return cfg;
}

export function loadVectollConfigFile(filePath: string): VectollConfig {
  const inferredName = path.basename(path.dirname(path.resolve(filePath)))
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-') || 'vectoll-service';
  return parseVectollConfig(fs.readFileSync(filePath, 'utf8'), inferredName);
}

export function buildDiscoveryManifest(
  cfg: VectollConfig,
  overrides: { facilitatorPublicKey?: string; facilitatorKid?: string } = {},
): Record<string, unknown> {
  const facUrl = cfg.settlement.facilitator_url.replace(/\/$/, '');
  return {
    vectollVersion: '0.1',
    x402Version: 2,
    service: {
      name: cfg.service.name,
      description: cfg.service.description ?? `${cfg.service.name} protected by Vectoll`,
      mcpEndpoint: cfg.service.enable_mcp !== false ? '/mcp' : null,
    },
    settlement: {
      facilitatorUrl: facUrl,
      jwksUrl: `${facUrl}/.well-known/jwks.json`,
      facilitatorPublicKey:
        overrides.facilitatorPublicKey ?? cfg.settlement.facilitator_public_key ?? '',
      facilitatorKid:
        overrides.facilitatorKid ?? cfg.settlement.facilitator_kid ?? 'fac-key-1',
      defaultCurrency: cfg.settlement.default_currency,
      defaultDecimals: getCurrencyDecimals(
        cfg.settlement.default_currency,
        cfg.settlement.default_decimals,
      ),
      acceptedRails: cfg.settlement.accepted_rails,
    },
    routes: cfg.routes.map((r) => ({
      path: r.path,
      method: r.method.toUpperCase(),
      pricingMode: r.pricing_mode ?? 'fixed',
      amount: r.price,
      currency: r.currency ?? cfg.settlement.default_currency,
      decimals: getCurrencyDecimals(r.currency ?? cfg.settlement.default_currency, r.decimals),
      settlementMode: r.settlement_mode ?? 'instant',
      requireMandate: Boolean(r.require_mandate),
      hitlThreshold: r.hitl_threshold ?? null,
      humanPassthrough: Boolean(r.human_passthrough),
      mcpTool: r.mcp_tool
        ? {
            name: r.mcp_tool,
            description: r.mcp_description ?? `${r.method} ${r.path}`,
          }
        : null,
    })),
  };
}

const BOT_UA_PATTERN =
  /GPTBot|ClaudeBot|PerplexityBot|Google-Extended|CCBot|Bytespider|Amazonbot|VectollAgent|MCP-Client|LangChain|CrewAI|AutoGen|python-requests|python-httpx|aiohttp|curl\/|wget\/|Go-http-client|HeadlessChrome|Playwright|Puppeteer|undici|node-fetch/i;

export function classifyTraffic(
  headers: Record<string, string | undefined>,
  routeHumanPassthrough: boolean,
  path: string,
): 'human' | 'agent' {
  if (!routeHumanPassthrough || path === '/mcp') {
    return 'agent';
  }
  const norm: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(headers)) {
    norm[k.toLowerCase()] = v;
  }

  if (
    norm['payment-signature'] ||
    norm['x-vectoll-agent-id'] ||
    norm['x-vectoll-mode'] === 'agent' ||
    (norm['authorization'] && /^vectoll\s+/i.test(norm['authorization']))
  ) {
    return 'agent';
  }

  const ua = norm['user-agent'] ?? '';
  if (!ua || BOT_UA_PATTERN.test(ua)) {
    return 'agent';
  }

  const accept = norm['accept'] ?? '';
  const isMozillaBrowser = ua.startsWith('Mozilla/5.0 ') && /(Chrome|Safari|Firefox|Edg)\//.test(ua);
  if (isMozillaBrowser && accept.includes('text/html')) {
    return 'human';
  }

  return 'agent';
}
