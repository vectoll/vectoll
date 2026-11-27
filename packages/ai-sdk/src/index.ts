import { formatMinorAmount, parsePrice } from '@vectoll/core';
import type { AgentFetchTelemetry, VectollAgentClient } from '@vectoll/sdk';

export interface DiscoveredPayableTool {
  name: string;
  description: string;
  serviceName: string;
  baseUrl: string;
  mcpEndpoint: string | null;
  mcpToolName: string | null;
  method: string;
  routePath: string;
  amount: number;
  currency: string;
  decimals: number;
  inputSchema: Record<string, unknown>;
}

export interface SpendEvent {
  toolName: string;
  serviceName: string;
  receiptId?: string;
  debitedAmount: number;
  debitedCurrency: string;
  totalMs: number;
}

export interface VectollToolkitOptions {
  client: VectollAgentClient;
  /** Maximum cumulative spend across the entire agent session in wallet currency (e.g. "$0.50") */
  maxSessionBudget?: string | number;
  onSpend?: (event: SpendEvent) => void;
  fetchImpl?: typeof fetch;
}

function sanitizeToolName(service: string, rawName: string): string {
  return `${service}_${rawName}`
    .replace(/[^a-zA-Z0-9_-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 64);
}

export class VectollToolkit {
  readonly client: VectollAgentClient;
  readonly tools = new Map<string, DiscoveredPayableTool>();
  private readonly maxSessionBudgetMinor?: number;
  private cumulativeSpentMinor = 0;
  private readonly spendHistory: SpendEvent[] = [];
  private readonly onSpend?: (event: SpendEvent) => void;

  constructor(tools: DiscoveredPayableTool[], options: VectollToolkitOptions) {
    this.client = options.client;
    this.onSpend = options.onSpend;
    if (options.maxSessionBudget !== undefined) {
      this.maxSessionBudgetMinor = parsePrice(
        options.maxSessionBudget,
        options.client.walletCurrency ?? 'USD',
      ).amount;
    }
    for (const t of tools) {
      this.tools.set(t.name, t);
    }
  }

  /**
   * Crawls `/.well-known/vectoll.json` across one or more domains and constructs a ready-to-use AI Toolkit.
   */
  static async fromDomains(
    domainUrls: string[],
    options: VectollToolkitOptions,
  ): Promise<VectollToolkit> {
    const fetchFn = options.fetchImpl ?? fetch;
    const discovered: DiscoveredPayableTool[] = [];

    for (const rawDomain of domainUrls) {
      const base = rawDomain.trim().replace(/\/$/, '');
      const res = await fetchFn(`${base}/.well-known/vectoll.json`, {
        headers: { Accept: 'application/json' },
      });
      if (!res.ok) {
        throw new Error(`Failed to discover ${base}/.well-known/vectoll.json (${res.status})`);
      }
      const doc = (await res.json()) as {
        service: { name: string; description?: string; mcpEndpoint?: string | null };
        routes: Array<{
          path: string;
          method: string;
          amount: number;
          currency: string;
          decimals: number;
          mcpTool?: { name: string; description?: string } | null;
        }>;
      };

      for (const r of doc.routes) {
        if (r.path.includes('*')) continue; // wildcard routes require explicit path params
        const rawTool =
          r.mcpTool?.name ??
          `${r.method.toLowerCase()}_${r.path.replace(/^\/+/, '').replace(/[^a-zA-Z0-9]+/g, '_')}`;
        const uniqueName = sanitizeToolName(doc.service.name, rawTool);
        const priceLabel = formatMinorAmount(r.amount, r.currency, r.decimals);
        const desc = `${r.mcpTool?.description ?? `${r.method} ${r.path}`} [Cost: ${priceLabel}]`;

        discovered.push({
          name: uniqueName,
          description: desc,
          serviceName: doc.service.name,
          baseUrl: base,
          mcpEndpoint: doc.service.mcpEndpoint ?? null,
          mcpToolName: r.mcpTool?.name ?? null,
          method: r.method.toUpperCase(),
          routePath: r.path,
          amount: r.amount,
          currency: r.currency,
          decimals: r.decimals,
          inputSchema: {
            type: 'object',
            properties: {},
            additionalProperties: true,
          },
        });
      }
    }

    return new VectollToolkit(discovered, options);
  }

  /**
   * Queries a Global Vectoll Discovery Registry (`/v1/discovery/search`) by capability keyword,
   * rail, and USD ceiling so an AI agent dynamically discovers and binds verified external tools!
   */
  static async fromDiscoverySearch(
    registryBaseUrl: string,
    search: { query?: string; rail?: string; maxPriceUsd?: string | number },
    options: VectollToolkitOptions,
  ): Promise<VectollToolkit> {
    const fetchFn = options.fetchImpl ?? fetch;
    const qs = new URLSearchParams();
    if (search.query) qs.set('q', search.query);
    if (search.rail) qs.set('rail', search.rail);
    if (search.maxPriceUsd !== undefined) {
      qs.set('maxPriceUsdMicro', String(parsePrice(search.maxPriceUsd, 'USD').amount));
    }

    const res = await fetchFn(
      `${registryBaseUrl.replace(/\/$/, '')}/v1/discovery/search?${qs.toString()}`,
    );
    if (!res.ok) {
      throw new Error(`Discovery search failed (${res.status})`);
    }
    const body = (await res.json()) as {
      results: Array<{
        baseUrl: string;
        serviceName: string;
        mcpEndpoint: string | null;
        routePath: string;
        method: string;
        mcpToolName: string | null;
        description: string;
        amount: number;
        currency: string;
        decimals: number;
      }>;
    };

    const tools: DiscoveredPayableTool[] = body.results
      .filter((r) => !r.routePath.includes('*'))
      .map((r) => {
        const rawName =
          r.mcpToolName ?? `${r.method.toLowerCase()}_${r.routePath.replace(/[^a-zA-Z0-9]+/g, '_')}`;
        const priceLabel = formatMinorAmount(r.amount, r.currency, r.decimals);
        return {
          name: sanitizeToolName(r.serviceName, rawName),
          description: `${r.description} [Cost: ${priceLabel}]`,
          serviceName: r.serviceName,
          baseUrl: r.baseUrl,
          mcpEndpoint: r.mcpEndpoint,
          mcpToolName: r.mcpToolName,
          method: r.method,
          routePath: r.routePath,
          amount: r.amount,
          currency: r.currency,
          decimals: r.decimals,
          inputSchema: { type: 'object', properties: {}, additionalProperties: true },
        };
      });

    return new VectollToolkit(tools, options);
  }

  getSpendSummary() {
    const cur = this.client.walletCurrency ?? 'USD';
    return {
      currency: cur,
      spentMinor: this.cumulativeSpentMinor,
      formattedSpent: formatMinorAmount(this.cumulativeSpentMinor, cur),
      maxBudgetMinor: this.maxSessionBudgetMinor ?? null,
      callCount: this.spendHistory.length,
      events: [...this.spendHistory],
    };
  }

  /**
   * Executes a discovered tool call, enforcing session budget caps and negotiating HTTP 402 automatically.
   */
  async execute(toolName: string, args: Record<string, unknown> = {}): Promise<unknown> {
    const tool = this.tools.get(toolName);
    if (!tool) {
      throw new Error(`Unknown Vectoll tool: ${toolName}`);
    }

    if (
      this.maxSessionBudgetMinor !== undefined &&
      (this.client.walletCurrency ?? 'USD').toUpperCase() === tool.currency.toUpperCase() &&
      this.cumulativeSpentMinor + tool.amount > this.maxSessionBudgetMinor
    ) {
      throw new Error(
        `ERR_SESSION_BUDGET_EXCEEDED: Calling ${toolName} (${tool.amount} ${tool.currency}) would exceed session budget ${this.maxSessionBudgetMinor}`,
      );
    }

    let data: unknown;
    let telemetry: AgentFetchTelemetry;

    if (tool.mcpEndpoint && tool.mcpToolName) {
      const mcpUrl = `${tool.baseUrl}${tool.mcpEndpoint}`;
      const out = await this.client.callMcpTool(mcpUrl, tool.mcpToolName, args);
      data = out.data;
      telemetry = out.telemetry;
    } else {
      let url = `${tool.baseUrl}${tool.routePath}`;
      let body: string | undefined;
      if (tool.method === 'GET') {
        const qs = new URLSearchParams();
        for (const [k, v] of Object.entries(args)) qs.set(k, String(v));
        const qsStr = qs.toString();
        if (qsStr) url += `?${qsStr}`;
      } else {
        body = JSON.stringify(args);
      }
      const res = await this.client.fetchWithTelemetry(url, {
        method: tool.method,
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body,
      });
      telemetry = res.telemetry;
      data = await res.response.json().catch(() => res.response.text());
    }

    const debited = telemetry.debitedAmount ?? 0;
    if (
      this.maxSessionBudgetMinor !== undefined &&
      this.cumulativeSpentMinor + debited > this.maxSessionBudgetMinor
    ) {
      this.cumulativeSpentMinor += debited;
      throw new Error(
        `ERR_SESSION_BUDGET_EXCEEDED: Session spend reached ${this.cumulativeSpentMinor} > ${this.maxSessionBudgetMinor}`,
      );
    }

    this.cumulativeSpentMinor += debited;
    const ev: SpendEvent = {
      toolName,
      serviceName: tool.serviceName,
      receiptId: telemetry.receiptId,
      debitedAmount: debited,
      debitedCurrency: telemetry.debitedCurrency ?? this.client.walletCurrency ?? tool.currency,
      totalMs: telemetry.totalMs,
    };
    this.spendHistory.push(ev);
    this.onSpend?.(ev);

    return data;
  }

  /** OpenAI Chat Completions / Responses API / LiteLLM / OpenRouter function tools */
  toOpenAiTools() {
    return Array.from(this.tools.values()).map((t) => ({
      type: 'function' as const,
      function: {
        name: t.name,
        description: t.description,
        parameters: t.inputSchema,
      },
    }));
  }

  /** Anthropic Messages API tools */
  toAnthropicTools() {
    return Array.from(this.tools.values()).map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.inputSchema,
    }));
  }

  /** Google Gemini FunctionDeclarations */
  toGeminiFunctionDeclarations() {
    return Array.from(this.tools.values()).map((t) => ({
      name: t.name,
      description: t.description,
      parameters: t.inputSchema,
    }));
  }

  /** Vercel AI SDK `tools` map with bound `execute` handlers */
  toVercelAiTools() {
    const out: Record<
      string,
      {
        description: string;
        parameters: Record<string, unknown>;
        execute: (args: Record<string, unknown>) => Promise<unknown>;
      }
    > = {};
    for (const t of this.tools.values()) {
      out[t.name] = {
        description: t.description,
        parameters: t.inputSchema,
        execute: (args) => this.execute(t.name, args),
      };
    }
    return out;
  }

  /** LangChain.js compatible structured tool objects */
  toLangChainTools() {
    return Array.from(this.tools.values()).map((t) => ({
      name: t.name,
      description: t.description,
      schema: t.inputSchema,
      invoke: (args: Record<string, unknown>) => this.execute(t.name, args),
    }));
  }
}
