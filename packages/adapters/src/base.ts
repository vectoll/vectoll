import {
  assertSafeMinorAmount,
  getCurrencyDecimals,
  randomId,
  verifyCreditVoucher,
} from '@vectoll/core';

export interface FxQuote {
  quoteId: string;
  sourceCurrency: string;
  sourceDecimals: number;
  sourceAmount: number;
  targetCurrency: string;
  targetDecimals: number;
  targetAmount: number;
  spreadBps: number;
  quotedAt: number;
  expiresAt: number;
}

const DEFAULT_MINOR_PER_ONE_USD: Record<string, bigint> = {
  // Global Reserve, G10 & Regulated Stablecoins (micro-units, decimals = 6 unless noted)
  USD: 1_000_000n,
  USDC: 1_000_000n,
  USDT: 1_000_000n,
  PYUSD: 1_000_000n,
  EUR: 920_000n,      // 1 USD = 0.92 EUR
  GBP: 790_000n,      // 1 USD = 0.79 GBP
  CHF: 880_000n,      // 1 USD = 0.88 CHF
  CAD: 1_390_000n,    // 1 USD = 1.39 CAD
  AUD: 1_530_000n,    // 1 USD = 1.53 AUD
  SGD: 1_340_000n,    // 1 USD = 1.34 SGD
  // Asia-Pacific
  JPY: 154n,          // decimals = 0 (1 USD = 154 JPY)
  KRW: 1_395n,        // decimals = 0 (1 USD = 1,395 KRW)
  INR: 8_440n,        // decimals = 2 (1 USD = 84.40 INR)
  // Latin America
  BRL: 580n,          // decimals = 2 (1 USD = 5.80 BRL)
  MXN: 2_030n,        // decimals = 2 (1 USD = 20.30 MXN)
  // Middle East & Africa
  AED: 367n,          // decimals = 2 (1 USD = 3.67 AED)
  ZAR: 1_810n,        // decimals = 2 (1 USD = 18.10 ZAR)
  KES: 12_950n,       // decimals = 2 (1 USD = 129.50 KES)
  NGN: 165_000n,      // decimals = 2 (1 USD = 1,650.00 NGN)
  GHS: 1_540n,        // decimals = 2 (1 USD = 15.40 GHS)
  TZS: 268_000n,      // decimals = 2 (1 USD = 2,680.00 TZS)
  UGX: 3_700n,        // decimals = 0 (1 USD = 3,700 UGX)
  RWF: 1_380n,        // decimals = 0 (1 USD = 1,380 RWF)
};

export class IntegerFxEngine {
  private readonly minorPerUsd: Map<string, bigint>;
  private readonly spreadBps: number;

  constructor(options: { customMinorPerUsd?: Record<string, bigint>; spreadBps?: number } = {}) {
    this.minorPerUsd = new Map(Object.entries(DEFAULT_MINOR_PER_ONE_USD));
    if (options.customMinorPerUsd) {
      for (const [cur, val] of Object.entries(options.customMinorPerUsd)) {
        this.minorPerUsd.set(cur.toUpperCase(), val);
      }
    }
    this.spreadBps = options.spreadBps ?? 30; // 0.30% cross-currency spread
  }

  listSupportedCurrencies(): Array<{
    currency: string;
    decimals: number;
    minorUnitsPerUsd: string;
  }> {
    return Array.from(this.minorPerUsd.entries()).map(([currency, rate]) => ({
      currency,
      decimals: getCurrencyDecimals(currency),
      minorUnitsPerUsd: rate.toString(),
    }));
  }

  quoteTargetAmount(
    targetAmount: number,
    targetCurrency: string,
    sourceCurrency: string,
    nowSeconds = Math.floor(Date.now() / 1000),
  ): FxQuote {
    assertSafeMinorAmount(targetAmount, 'targetAmount');
    const srcCur = sourceCurrency.toUpperCase();
    const dstCur = targetCurrency.toUpperCase();
    const srcDec = getCurrencyDecimals(srcCur);
    const dstDec = getCurrencyDecimals(dstCur);

    if (srcCur === dstCur) {
      return {
        quoteId: randomId('fxq', 8),
        sourceCurrency: srcCur,
        sourceDecimals: srcDec,
        sourceAmount: targetAmount,
        targetCurrency: dstCur,
        targetDecimals: dstDec,
        targetAmount,
        spreadBps: 0,
        quotedAt: nowSeconds,
        expiresAt: nowSeconds + 60,
      };
    }

    const srcRate = this.minorPerUsd.get(srcCur);
    const dstRate = this.minorPerUsd.get(dstCur);
    if (!srcRate || !dstRate) {
      throw new Error(`Unsupported FX pair: ${srcCur} -> ${dstCur}`);
    }

    const numerator = BigInt(targetAmount) * srcRate * BigInt(10_000 + this.spreadBps);
    const denominator = dstRate * 10_000n;
    const rawSource = targetAmount === 0 ? 0n : (numerator + denominator - 1n) / denominator;

    const sourceAmount = Number(rawSource);
    assertSafeMinorAmount(sourceAmount, 'computedSourceAmount');

    return {
      quoteId: randomId('fxq', 8),
      sourceCurrency: srcCur,
      sourceDecimals: srcDec,
      sourceAmount,
      targetCurrency: dstCur,
      targetDecimals: dstDec,
      targetAmount,
      spreadBps: this.spreadBps,
      quotedAt: nowSeconds,
      expiresAt: nowSeconds + 60,
    };
  }
}

// ─── Standardized VectollRailAdapter Contract ──────────────────────────────

export interface RailQuoteRequest {
  targetAmount: number;
  targetCurrency: string;
  sourceCurrency: string;
}

export interface RailAuthorizeRequest {
  agentId: string;
  amount: number;
  currency: string;
  decimals: number;
  referenceId: string;
  metadata?: Record<string, string>;
}

export interface RailAuthorization {
  authorizationId: string;
  railId: string;
  status: 'AUTHORIZED' | 'CAPTURED' | 'PENDING_USER_PROMPT';
  providerRef: string;
  amount: number;
  currency: string;
  decimals: number;
  authorizedAt: number;
}

export interface RailSettleRequest {
  authorizationId: string;
  receiptId: string;
  amount: number;
  currency: string;
}

export interface RailSettlementResult {
  settlementId: string;
  railId: string;
  status: 'SETTLED';
  providerTxId: string;
  settledAt: number;
}

export interface RailPayoutRequest {
  merchantService: string;
  destinationAccount: string;
  amount: number;
  currency: string;
  decimals: number;
  batchId: string;
}

export interface RailPayoutResult {
  payoutId: string;
  railId: string;
  status: 'DISBURSED';
  providerDisbursementRef: string;
  amount: number;
  currency: string;
  disbursedAt: number;
}

export interface VectollRailAdapter {
  readonly railId: string;
  readonly displayName: string;
  readonly region: string;
  readonly supportedCurrencies: readonly string[];

  quote(input: RailQuoteRequest): Promise<FxQuote>;
  authorize(input: RailAuthorizeRequest): Promise<RailAuthorization>;
  settle(input: RailSettleRequest): Promise<RailSettlementResult>;
  payout(input: RailPayoutRequest): Promise<RailPayoutResult>;
}

abstract class BaseRailAdapter implements VectollRailAdapter {
  abstract readonly railId: string;
  abstract readonly displayName: string;
  abstract readonly region: string;
  abstract readonly supportedCurrencies: readonly string[];
  protected readonly fx: IntegerFxEngine;

  constructor(fx = new IntegerFxEngine()) {
    this.fx = fx;
  }

  async quote(input: RailQuoteRequest): Promise<FxQuote> {
    return this.fx.quoteTargetAmount(input.targetAmount, input.targetCurrency, input.sourceCurrency);
  }

  async authorize(input: RailAuthorizeRequest): Promise<RailAuthorization> {
    assertSafeMinorAmount(input.amount, `${this.railId}.authorize.amount`);
    const cur = input.currency.toUpperCase();
    if (!this.supportedCurrencies.includes(cur)) {
      throw new Error(`Rail ${this.railId} does not natively clear ${cur}; supported: ${this.supportedCurrencies.join(', ')}`);
    }
    return {
      authorizationId: randomId(`auth_${this.railId}`, 8),
      railId: this.railId,
      status: 'CAPTURED',
      providerRef: `${this.railId.toUpperCase()}-${input.referenceId}`,
      amount: input.amount,
      currency: cur,
      decimals: input.decimals,
      authorizedAt: Math.floor(Date.now() / 1000),
    };
  }

  async settle(input: RailSettleRequest): Promise<RailSettlementResult> {
    assertSafeMinorAmount(input.amount, `${this.railId}.settle.amount`);
    return {
      settlementId: randomId(`stl_${this.railId}`, 8),
      railId: this.railId,
      status: 'SETTLED',
      providerTxId: `${this.railId}_tx_${input.receiptId}`,
      settledAt: Math.floor(Date.now() / 1000),
    };
  }

  async payout(input: RailPayoutRequest): Promise<RailPayoutResult> {
    assertSafeMinorAmount(input.amount, `${this.railId}.payout.amount`);
    const cur = input.currency.toUpperCase();
    if (!this.supportedCurrencies.includes(cur)) {
      throw new Error(`Rail ${this.railId} cannot disburse ${cur}`);
    }
    return {
      payoutId: randomId(`pay_${this.railId}`, 8),
      railId: this.railId,
      status: 'DISBURSED',
      providerDisbursementRef: `${this.railId.toUpperCase()}-DISB-${input.batchId}`,
      amount: input.amount,
      currency: cur,
      disbursedAt: Math.floor(Date.now() / 1000),
    };
  }
}

export class X402UsdcAdapter extends BaseRailAdapter {
  readonly railId = 'x402_usdc';
  readonly displayName = 'x402 Global Stablecoins (USDC / PYUSD — Base, Ethereum, Solana)';
  readonly region = 'Global';
  readonly supportedCurrencies = ['USDC', 'USDT', 'PYUSD', 'USD'] as const;
}

export class StripeAdapter extends BaseRailAdapter {
  readonly railId = 'stripe';
  readonly displayName = 'Stripe Global Cards, Link & Agentic Tokens';
  readonly region = 'Global (46+ Countries)';
  readonly supportedCurrencies = [
    'USD', 'EUR', 'GBP', 'CHF', 'CAD', 'AUD', 'SGD', 'JPY', 'INR', 'BRL', 'MXN', 'AED', 'ZAR', 'KES', 'NGN',
  ] as const;
}

export class SepaInstantAdapter extends BaseRailAdapter {
  readonly railId = 'sepa_instant';
  readonly displayName = 'SEPA Instant & UK Faster Payments';
  readonly region = 'Europe & UK';
  readonly supportedCurrencies = ['EUR', 'GBP', 'CHF'] as const;
}

export class AchFedNowAdapter extends BaseRailAdapter {
  readonly railId = 'ach_fednow';
  readonly displayName = 'US FedNow, RTP & Treasury ACH';
  readonly region = 'North America';
  readonly supportedCurrencies = ['USD', 'CAD'] as const;
}

export class PixUpiInstantAdapter extends BaseRailAdapter {
  readonly railId = 'pix_upi';
  readonly displayName = 'Global Instant Bank Rails (PIX · UPI · SPEI · PayNow)';
  readonly region = 'LATAM & Asia-Pacific';
  readonly supportedCurrencies = ['BRL', 'INR', 'MXN', 'SGD', 'JPY', 'KRW'] as const;
}

export class MpesaAdapter extends BaseRailAdapter {
  readonly railId = 'mpesa';
  readonly displayName = 'M-Pesa Global / Daraja';
  readonly region = 'Africa';
  readonly supportedCurrencies = ['KES', 'TZS'] as const;
}

export class MtnMomoAdapter extends BaseRailAdapter {
  readonly railId = 'momo';
  readonly displayName = 'MTN Mobile Money (MoMo)';
  readonly region = 'Africa';
  readonly supportedCurrencies = ['GHS', 'ZAR', 'UGX', 'RWF'] as const;
}

export class AirtelMoneyAdapter extends BaseRailAdapter {
  readonly railId = 'airtel_money';
  readonly displayName = 'Airtel Money';
  readonly region = 'South Asia & Africa';
  readonly supportedCurrencies = ['INR', 'KES', 'NGN', 'UGX', 'TZS', 'RWF'] as const;
}

export class VoucherAdapter extends BaseRailAdapter {
  readonly railId = 'voucher';
  readonly displayName = 'Enterprise Cryptographic Credit Voucher (vcv1)';
  readonly region = 'Global B2B';
  readonly supportedCurrencies = [
    'USD', 'EUR', 'GBP', 'CHF', 'CAD', 'AUD', 'SGD', 'JPY', 'KRW', 'INR', 'BRL', 'MXN',
    'AED', 'ZAR', 'USDC', 'USDT', 'PYUSD', 'KES', 'NGN', 'GHS', 'TZS', 'UGX', 'RWF',
  ] as const;

  override async authorize(input: RailAuthorizeRequest): Promise<RailAuthorization> {
    const voucherToken = input.metadata?.voucherToken;
    if (voucherToken) {
      const check = verifyCreditVoucher(voucherToken);
      if (!check.valid || !check.claims) {
        throw new Error(`Invalid enterprise voucher: ${check.reason ?? 'unknown'}`);
      }
      if (check.claims.beneficiaryDid !== input.agentId) {
        throw new Error('Voucher beneficiaryDid does not match agentId');
      }
      if (check.claims.amount < input.amount || check.claims.currency !== input.currency.toUpperCase()) {
        throw new Error('Voucher credit insufficient or currency mismatch');
      }
    }
    return super.authorize(input);
  }
}

export class AdapterRegistry {
  private readonly adapters = new Map<string, VectollRailAdapter>();
  readonly fx: IntegerFxEngine;

  constructor(fx = new IntegerFxEngine()) {
    this.fx = fx;
  }

  register(adapter: VectollRailAdapter): this {
    this.adapters.set(adapter.railId, adapter);
    return this;
  }

  get(railId: string): VectollRailAdapter {
    const found = this.adapters.get(railId);
    if (!found) {
      throw new Error(`Unregistered settlement rail adapter: ${railId}`);
    }
    return found;
  }

  has(railId: string): boolean {
    return this.adapters.has(railId);
  }

  list(): VectollRailAdapter[] {
    return Array.from(this.adapters.values());
  }
}

export function createDefaultAdapterRegistry(fx = new IntegerFxEngine()): AdapterRegistry {
  return new AdapterRegistry(fx)
    .register(new X402UsdcAdapter(fx))
    .register(new StripeAdapter(fx))
    .register(new SepaInstantAdapter(fx))
    .register(new AchFedNowAdapter(fx))
    .register(new PixUpiInstantAdapter(fx))
    .register(new MpesaAdapter(fx))
    .register(new MtnMomoAdapter(fx))
    .register(new AirtelMoneyAdapter(fx))
    .register(new VoucherAdapter(fx));
}
