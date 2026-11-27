import { assertSafeMinorAmount, getCurrencyDecimals } from '@vectoll/core';
import { IntegerFxEngine, type FxQuote } from './base.js';

export interface FxRateFeedResponse {
  base?: string;
  base_code?: string;
  rates: Record<string, number>;
}

export interface LiveFxOracleOptions {
  /** Upstream JSON FX endpoint returning { rates: { EUR: 0.92, JPY: 154.2, ... } } per 1 USD */
  feedUrl?: string;
  /** Cache TTL in seconds before background/lazy refresh (default: 300s) */
  ttlSeconds?: number;
  /** Hard maximum age before stale quotes are rejected if strictStaleCheck=true (default: 3600s) */
  maxStaleSeconds?: number;
  /** Circuit-breaker threshold: reject any incoming rate deviating more than X% from baseline (default: 35%) */
  maxDeviationPct?: number;
  /** Cross-currency spread in basis points (default: 30 bps = 0.30%) */
  spreadBps?: number;
  /** Reject quotes if feed has never synced or exceeded maxStaleSeconds (default: false — falls back safely) */
  strictStaleCheck?: boolean;
  fetchImpl?: typeof fetch;
}

export class LiveFxOracle {
  private engine: IntegerFxEngine;
  private readonly baselineRates = new Map<string, bigint>();
  private readonly liveRates = new Map<string, bigint>();
  private readonly feedUrl: string;
  private readonly ttlSeconds: number;
  private readonly maxStaleSeconds: number;
  private readonly maxDeviationPct: number;
  private readonly spreadBps: number;
  private readonly strictStaleCheck: boolean;
  private readonly fetchFn: typeof fetch;
  private lastUpdatedAt = 0;

  constructor(options: LiveFxOracleOptions = {}) {
    this.feedUrl = options.feedUrl ?? process.env.VECTOLL_FX_FEED_URL ?? 'https://open.er-api.com/v6/latest/USD';
    this.ttlSeconds = options.ttlSeconds ?? 300;
    this.maxStaleSeconds = options.maxStaleSeconds ?? 3600;
    this.maxDeviationPct = options.maxDeviationPct ?? 35;
    this.spreadBps = options.spreadBps ?? 30;
    this.strictStaleCheck = options.strictStaleCheck ?? false;
    this.fetchFn = options.fetchImpl ?? fetch;

    this.engine = new IntegerFxEngine({ spreadBps: this.spreadBps });
    for (const item of this.engine.listSupportedCurrencies()) {
      const val = BigInt(item.minorUnitsPerUsd);
      this.baselineRates.set(item.currency, val);
      this.liveRates.set(item.currency, val);
    }
  }

  getLastUpdatedAt(): number {
    return this.lastUpdatedAt;
  }

  /**
   * Refreshes integer minor-unit FX rates from live HTTP provider while enforcing
   * circuit-breaker bounds against corrupted or manipulated oracle responses.
   */
  async refresh(nowSeconds = Math.floor(Date.now() / 1000)): Promise<{
    updatedCurrencies: string[];
    rejectedAnomalies: Array<{ currency: string; reason: string }>;
    updatedAt: number;
  }> {
    const res = await this.fetchFn(this.feedUrl, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`ERR_FX_ORACLE_HTTP_${res.status}: Failed to fetch FX rates from ${this.feedUrl}`);
    }
    const payload = (await res.json()) as FxRateFeedResponse;
    if (!payload?.rates || typeof payload.rates !== 'object') {
      throw new Error('ERR_FX_ORACLE_SCHEMA: Missing rates map in oracle response');
    }

    const updatedCurrencies: string[] = [];
    const rejectedAnomalies: Array<{ currency: string; reason: string }> = [];
    const customMap: Record<string, bigint> = {};

    for (const [cur, currentVal] of this.liveRates.entries()) {
      customMap[cur] = currentVal;
    }

    for (const [rawCode, unitRatePerUsd] of Object.entries(payload.rates)) {
      const cur = rawCode.toUpperCase();
      const baseline = this.baselineRates.get(cur);
      if (!baseline) continue;

      if (typeof unitRatePerUsd !== 'number' || !Number.isFinite(unitRatePerUsd) || unitRatePerUsd <= 0) {
        rejectedAnomalies.push({ currency: cur, reason: `Non-positive rate: ${String(unitRatePerUsd)}` });
        continue;
      }

      const dec = getCurrencyDecimals(cur);
      const scaledMinor = Math.round(unitRatePerUsd * 10 ** dec);
      if (!Number.isSafeInteger(scaledMinor) || scaledMinor <= 0) {
        rejectedAnomalies.push({ currency: cur, reason: `Unsafe scaled minor units: ${scaledMinor}` });
        continue;
      }

      const candidate = BigInt(scaledMinor);
      // Circuit breaker check: |candidate - baseline| * 100 <= baseline * maxDeviationPct
      const diff = candidate > baseline ? candidate - baseline : baseline - candidate;
      if (diff * 100n > baseline * BigInt(this.maxDeviationPct)) {
        rejectedAnomalies.push({
          currency: cur,
          reason: `Circuit breaker tripped: ${candidate.toString()} deviates >${this.maxDeviationPct}% from baseline ${baseline.toString()}`,
        });
        continue;
      }

      this.liveRates.set(cur, candidate);
      customMap[cur] = candidate;
      updatedCurrencies.push(cur);
    }

    // Keep USD-pegged stablecoins anchored 1:1 unless explicitly overridden within bounds
    this.engine = new IntegerFxEngine({
      customMinorPerUsd: customMap,
      spreadBps: this.spreadBps,
    });
    this.lastUpdatedAt = nowSeconds;

    return {
      updatedCurrencies,
      rejectedAnomalies,
      updatedAt: nowSeconds,
    };
  }

  async quote(
    targetAmount: number,
    targetCurrency: string,
    sourceCurrency: string,
    nowSeconds = Math.floor(Date.now() / 1000),
  ): Promise<FxQuote> {
    assertSafeMinorAmount(targetAmount, 'targetAmount');

    const age = nowSeconds - this.lastUpdatedAt;
    if (this.lastUpdatedAt === 0 || age >= this.ttlSeconds) {
      try {
        await this.refresh(nowSeconds);
      } catch (err) {
        if (this.strictStaleCheck && (this.lastUpdatedAt === 0 || age > this.maxStaleSeconds)) {
          throw err;
        }
      }
    }

    if (this.strictStaleCheck && nowSeconds - this.lastUpdatedAt > this.maxStaleSeconds) {
      throw new Error('ERR_FX_QUOTE_STALE: Live FX oracle exceeded maxStaleSeconds');
    }

    return this.engine.quoteTargetAmount(targetAmount, targetCurrency, sourceCurrency, nowSeconds);
  }
}
