import crypto from 'node:crypto';
import { assertSafeMinorAmount, randomId } from '@vectoll/core';
import {
  IntegerFxEngine,
  MpesaAdapter,
  MtnMomoAdapter,
  PixUpiInstantAdapter,
  SepaInstantAdapter,
  StripeAdapter,
  X402UsdcAdapter,
  type RailAuthorization,
  type RailAuthorizeRequest,
  type RailPayoutRequest,
  type RailPayoutResult,
} from './base.js';

// ─── Webhook Cryptographic Verifiers (Stripe & Generic HMAC-SHA256) ─────────

/**
 * Verifies Stripe's `Stripe-Signature` header (`t=<timestamp>,v1=<hmac_sha256>`)
 * using constant-time comparison and replay window enforcement.
 */
export function verifyStripeWebhookSignature(
  rawBody: string | Uint8Array,
  signatureHeader: string,
  webhookSecret: string,
  toleranceSeconds = 300,
  nowSeconds = Math.floor(Date.now() / 1000),
): { valid: boolean; timestamp?: number; reason?: string } {
  const parts = signatureHeader.split(',').map((s) => s.trim());
  let timestampStr: string | undefined;
  const v1Sigs: string[] = [];

  for (const p of parts) {
    const [k, v] = p.split('=', 2);
    if (k === 't' && v) timestampStr = v;
    else if (k === 'v1' && v) v1Sigs.push(v);
  }

  if (!timestampStr || v1Sigs.length === 0) {
    return { valid: false, reason: 'Malformed Stripe-Signature header' };
  }

  const ts = Number(timestampStr);
  if (!Number.isFinite(ts) || Math.abs(nowSeconds - ts) > toleranceSeconds) {
    return { valid: false, reason: 'Stripe webhook timestamp outside tolerance window' };
  }

  const bodyStr = typeof rawBody === 'string' ? rawBody : Buffer.from(rawBody).toString('utf8');
  const signedPayload = `${ts}.${bodyStr}`;
  const expectedHex = crypto
    .createHmac('sha256', webhookSecret)
    .update(signedPayload, 'utf8')
    .digest('hex');
  const expectedBuf = Buffer.from(expectedHex, 'hex');

  for (const candidateHex of v1Sigs) {
    if (!/^[0-9a-fA-F]{64}$/.test(candidateHex)) continue;
    const candBuf = Buffer.from(candidateHex, 'hex');
    if (candBuf.length === expectedBuf.length && crypto.timingSafeEqual(candBuf, expectedBuf)) {
      return { valid: true, timestamp: ts };
    }
  }

  return { valid: false, reason: 'Stripe HMAC-SHA256 v1 signature mismatch' };
}

/**
 * Verifies standard HMAC-SHA256 webhook signatures used by Open Banking, Razorpay (UPI),
 * Paystack, Wise, and mobile-money aggregator callbacks.
 */
export function verifyHmacWebhookSignature(
  rawBody: string | Uint8Array,
  signatureHexOrBase64: string,
  secret: string,
  encoding: 'hex' | 'base64' = 'hex',
): boolean {
  const buf = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : Buffer.from(rawBody);
  const expected = crypto.createHmac('sha256', secret).update(buf).digest(encoding);
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(signatureHexOrBase64.trim(), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ─── 1. Stripe Live PaymentIntents & Connect Adapter ───────────────────────

export interface StripeLiveConfig {
  secretKey?: string;
  apiBaseUrl?: string;
  fetchImpl?: typeof fetch;
}

export class StripeLiveAdapter extends StripeAdapter {
  private readonly secretKey?: string;
  private readonly apiBaseUrl: string;
  private readonly fetchFn: typeof fetch;

  constructor(config: StripeLiveConfig = {}, fx = new IntegerFxEngine()) {
    super(fx);
    this.secretKey = config.secretKey ?? process.env.STRIPE_SECRET_KEY;
    this.apiBaseUrl = (config.apiBaseUrl ?? 'https://api.stripe.com').replace(/\/$/, '');
    this.fetchFn = config.fetchImpl ?? fetch;
  }

  /**
   * Normalizes Vectoll internal micro-units (decimals=6 for USD/EUR/GBP) to Stripe's
   * smallest ISO currency unit (cents=2 for USD/EUR/GBP, 0 for JPY/KRW).
   */
  static toStripeAmount(amountMinor: number, currency: string, vectollDecimals: number): number {
    const cur = currency.toUpperCase();
    const stripeDec = cur === 'JPY' || cur === 'KRW' ? 0 : 2;
    if (vectollDecimals === stripeDec) return amountMinor;
    if (vectollDecimals > stripeDec) {
      const divisor = 10 ** (vectollDecimals - stripeDec);
      return Math.max(1, Math.ceil(amountMinor / divisor));
    }
    return amountMinor * 10 ** (stripeDec - vectollDecimals);
  }

  override async authorize(input: RailAuthorizeRequest): Promise<RailAuthorization> {
    if (!this.secretKey) {
      return super.authorize(input); // Sandbox fallback when no live key configured
    }
    assertSafeMinorAmount(input.amount, 'stripe.authorize.amount');
    const cur = input.currency.toUpperCase();
    const stripeAmt = StripeLiveAdapter.toStripeAmount(input.amount, cur, input.decimals);

    const form = new URLSearchParams();
    form.set('amount', String(stripeAmt));
    form.set('currency', cur.toLowerCase());
    form.set('confirm', 'true');
    form.set('payment_method', input.metadata?.paymentMethodId ?? 'pm_card_visa');
    form.set('off_session', 'true');
    form.set('metadata[vectoll_agent_id]', input.agentId);
    form.set('metadata[vectoll_ref]', input.referenceId);

    const res = await this.fetchFn(`${this.apiBaseUrl}/v1/payment_intents`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.secretKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Idempotency-Key': `vectoll_auth_${input.referenceId}`,
      },
      body: form.toString(),
    });

    if (!res.ok) {
      throw new Error(`ERR_STRIPE_LIVE_${res.status}: ${await res.text()}`);
    }
    const pi = (await res.json()) as { id: string; status: string };
    return {
      authorizationId: pi.id,
      railId: this.railId,
      status: pi.status === 'succeeded' ? 'CAPTURED' : 'AUTHORIZED',
      providerRef: pi.id,
      amount: input.amount,
      currency: cur,
      decimals: input.decimals,
      authorizedAt: Math.floor(Date.now() / 1000),
    };
  }

  override async payout(input: RailPayoutRequest): Promise<RailPayoutResult> {
    if (!this.secretKey) {
      return super.payout(input);
    }
    const cur = input.currency.toUpperCase();
    const stripeAmt = StripeLiveAdapter.toStripeAmount(input.amount, cur, input.decimals);

    const form = new URLSearchParams();
    form.set('amount', String(stripeAmt));
    form.set('currency', cur.toLowerCase());
    form.set('destination', input.destinationAccount);
    form.set('metadata[vectoll_batch_id]', input.batchId);

    const res = await this.fetchFn(`${this.apiBaseUrl}/v1/transfers`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.secretKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Idempotency-Key': `vectoll_payout_${input.batchId}`,
      },
      body: form.toString(),
    });

    if (!res.ok) {
      throw new Error(`ERR_STRIPE_TRANSFER_${res.status}: ${await res.text()}`);
    }
    const tr = (await res.json()) as { id: string };
    return {
      payoutId: tr.id,
      railId: this.railId,
      status: 'DISBURSED',
      providerDisbursementRef: tr.id,
      amount: input.amount,
      currency: cur,
      disbursedAt: Math.floor(Date.now() / 1000),
    };
  }
}

// ─── 2. EVM On-Chain USDC Receipt Verifier (Base, Arbitrum, Polygon) ───────

const ERC20_TRANSFER_TOPIC0 =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

export const BASE_MAINNET_USDC = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';

export interface X402EvmLiveConfig {
  rpcUrl?: string;
  treasuryAddress?: string;
  usdcContractAddress?: string;
  fetchImpl?: typeof fetch;
}

export class X402EvmLiveAdapter extends X402UsdcAdapter {
  private readonly rpcUrl?: string;
  private readonly treasuryAddress?: string;
  private readonly usdcContract: string;
  private readonly fetchFn: typeof fetch;

  constructor(config: X402EvmLiveConfig = {}, fx = new IntegerFxEngine()) {
    super(fx);
    this.rpcUrl = config.rpcUrl ?? process.env.VECTOLL_EVM_RPC_URL;
    this.treasuryAddress = (config.treasuryAddress ?? process.env.VECTOLL_TREASURY_ADDRESS)?.toLowerCase();
    this.usdcContract = (config.usdcContractAddress ?? BASE_MAINNET_USDC).toLowerCase();
    this.fetchFn = config.fetchImpl ?? fetch;
  }

  override async authorize(input: RailAuthorizeRequest): Promise<RailAuthorization> {
    const txHash = input.metadata?.txHash;
    if (!this.rpcUrl || !txHash) {
      return super.authorize(input);
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
      throw new Error(`ERR_EVM_INVALID_TX_HASH: ${txHash}`);
    }

    const rpcRes = await this.fetchFn(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_getTransactionReceipt',
        params: [txHash],
      }),
    });

    if (!rpcRes.ok) {
      throw new Error(`ERR_EVM_RPC_HTTP_${rpcRes.status}`);
    }

    const rpcJson = (await rpcRes.json()) as {
      result?: {
        status: string;
        transactionHash: string;
        logs: Array<{ address: string; topics: string[]; data: string }>;
      } | null;
    };

    const receipt = rpcJson.result;
    if (!receipt || receipt.status !== '0x1') {
      throw new Error(`ERR_EVM_TX_NOT_CONFIRMED: tx ${txHash} missing or reverted`);
    }

    // Verify ERC-20 Transfer(from, to, value) log to treasuryAddress on USDC contract
    let verifiedAmount = 0n;
    for (const log of receipt.logs) {
      if (log.address.toLowerCase() !== this.usdcContract) continue;
      if (log.topics[0]?.toLowerCase() !== ERC20_TRANSFER_TOPIC0) continue;
      const toTopic = log.topics[2]?.toLowerCase() ?? '';
      const toAddress = '0x' + toTopic.slice(-40);
      if (this.treasuryAddress && toAddress !== this.treasuryAddress) continue;
      verifiedAmount += BigInt(log.data);
    }

    if (verifiedAmount < BigInt(input.amount)) {
      throw new Error(
        `ERR_EVM_INSUFFICIENT_TRANSFER: On-chain USDC transfer ${verifiedAmount.toString()} < required ${input.amount}`,
      );
    }

    return {
      authorizationId: receipt.transactionHash,
      railId: this.railId,
      status: 'CAPTURED',
      providerRef: receipt.transactionHash,
      amount: input.amount,
      currency: input.currency.toUpperCase(),
      decimals: input.decimals,
      authorizedAt: Math.floor(Date.now() / 1000),
    };
  }
}

// ─── 3. Safaricom Daraja M-Pesa Live Adapter (OAuth2 + STK Push + B2C) ─────

export interface MpesaDarajaLiveConfig {
  consumerKey?: string;
  consumerSecret?: string;
  shortCode?: string;
  passkey?: string;
  callbackUrl?: string;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

export class MpesaDarajaLiveAdapter extends MpesaAdapter {
  private readonly consumerKey?: string;
  private readonly consumerSecret?: string;
  private readonly shortCode: string;
  private readonly passkey: string;
  private readonly callbackUrl: string;
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private cachedToken?: { token: string; expiresAt: number };

  constructor(config: MpesaDarajaLiveConfig = {}, fx = new IntegerFxEngine()) {
    super(fx);
    this.consumerKey = config.consumerKey ?? process.env.MPESA_CONSUMER_KEY;
    this.consumerSecret = config.consumerSecret ?? process.env.MPESA_CONSUMER_SECRET;
    this.shortCode = config.shortCode ?? process.env.MPESA_SHORTCODE ?? '174379';
    this.passkey = config.passkey ?? process.env.MPESA_PASSKEY ?? '';
    this.callbackUrl = config.callbackUrl ?? 'https://facilitator.vectoll.com/webhooks/mpesa';
    this.baseUrl = (config.baseUrl ?? 'https://sandbox.safaricom.co.ke').replace(/\/$/, '');
    this.fetchFn = config.fetchImpl ?? fetch;
  }

  private async getAccessToken(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    if (this.cachedToken && this.cachedToken.expiresAt > now + 30) {
      return this.cachedToken.token;
    }
    const basic = Buffer.from(`${this.consumerKey}:${this.consumerSecret}`).toString('base64');
    const res = await this.fetchFn(
      `${this.baseUrl}/oauth/v1/generate?grant_type=client_credentials`,
      { headers: { Authorization: `Basic ${basic}` } },
    );
    if (!res.ok) throw new Error(`ERR_MPESA_OAUTH_${res.status}`);
    const data = (await res.json()) as { access_token: string; expires_in: string | number };
    this.cachedToken = {
      token: data.access_token,
      expiresAt: now + Number(data.expires_in || 3599),
    };
    return data.access_token;
  }

  override async authorize(input: RailAuthorizeRequest): Promise<RailAuthorization> {
    if (!this.consumerKey || !this.consumerSecret) {
      return super.authorize(input);
    }
    const token = await this.getAccessToken();
    const ts = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
    const password = Buffer.from(`${this.shortCode}${this.passkey}${ts}`).toString('base64');
    const wholeKes = Math.max(1, Math.ceil(input.amount / 10 ** input.decimals));
    const phone = input.metadata?.phoneNumber ?? '254708374149';

    const res = await this.fetchFn(`${this.baseUrl}/mpesa/stkpush/v1/processrequest`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        BusinessShortCode: this.shortCode,
        Password: password,
        Timestamp: ts,
        TransactionType: 'CustomerPayBillOnline',
        Amount: wholeKes,
        PartyA: phone,
        PartyB: this.shortCode,
        PhoneNumber: phone,
        CallBackURL: this.callbackUrl,
        AccountReference: input.referenceId,
        TransactionDesc: 'Vectoll Agent Float TopUp',
      }),
    });
    if (!res.ok) throw new Error(`ERR_MPESA_STK_${res.status}: ${await res.text()}`);
    const out = (await res.json()) as { CheckoutRequestID: string; ResponseCode: string };
    return {
      authorizationId: out.CheckoutRequestID,
      railId: this.railId,
      status: out.ResponseCode === '0' ? 'CAPTURED' : 'PENDING_USER_PROMPT',
      providerRef: out.CheckoutRequestID,
      amount: input.amount,
      currency: input.currency.toUpperCase(),
      decimals: input.decimals,
      authorizedAt: Math.floor(Date.now() / 1000),
    };
  }
}

// ─── 4. MTN MoMo Open API Live Adapter (Collection & Disbursement) ─────────

export interface MtnMomoLiveConfig {
  apiUser?: string;
  apiKey?: string;
  subscriptionKey?: string;
  targetEnvironment?: string;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

export class MtnMomoLiveAdapter extends MtnMomoAdapter {
  private readonly apiUser?: string;
  private readonly apiKey?: string;
  private readonly subscriptionKey?: string;
  private readonly targetEnv: string;
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;

  constructor(config: MtnMomoLiveConfig = {}, fx = new IntegerFxEngine()) {
    super(fx);
    this.apiUser = config.apiUser ?? process.env.MOMO_API_USER;
    this.apiKey = config.apiKey ?? process.env.MOMO_API_KEY;
    this.subscriptionKey = config.subscriptionKey ?? process.env.MOMO_SUBSCRIPTION_KEY;
    this.targetEnv = config.targetEnvironment ?? process.env.MOMO_TARGET_ENV ?? 'sandbox';
    this.baseUrl = (config.baseUrl ?? 'https://sandbox.momodeveloper.mtn.com').replace(/\/$/, '');
    this.fetchFn = config.fetchImpl ?? fetch;
  }

  override async authorize(input: RailAuthorizeRequest): Promise<RailAuthorization> {
    if (!this.apiUser || !this.apiKey || !this.subscriptionKey) {
      return super.authorize(input);
    }
    const basic = Buffer.from(`${this.apiUser}:${this.apiKey}`).toString('base64');
    const tokRes = await this.fetchFn(`${this.baseUrl}/collection/token/`, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${basic}`,
        'Ocp-Apim-Subscription-Key': this.subscriptionKey,
      },
    });
    if (!tokRes.ok) throw new Error(`ERR_MOMO_TOKEN_${tokRes.status}`);
    const { access_token } = (await tokRes.json()) as { access_token: string };

    const refUuid = crypto.randomUUID();
    const majorAmt = (input.amount / 10 ** input.decimals).toFixed(input.decimals === 0 ? 0 : 2);

    const payRes = await this.fetchFn(`${this.baseUrl}/collection/v1_0/requesttopay`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${access_token}`,
        'X-Reference-Id': refUuid,
        'X-Target-Environment': this.targetEnv,
        'Ocp-Apim-Subscription-Key': this.subscriptionKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        amount: majorAmt,
        currency: input.currency.toUpperCase(),
        externalId: input.referenceId,
        payer: { partyIdType: 'MSISDN', partyId: input.metadata?.msisdn ?? '256770000000' },
        payerMessage: 'Vectoll Agent Wallet TopUp',
        payeeNote: input.agentId,
      }),
    });
    if (payRes.status !== 202 && !payRes.ok) {
      throw new Error(`ERR_MOMO_RTP_${payRes.status}`);
    }
    return {
      authorizationId: refUuid,
      railId: this.railId,
      status: 'CAPTURED',
      providerRef: refUuid,
      amount: input.amount,
      currency: input.currency.toUpperCase(),
      decimals: input.decimals,
      authorizedAt: Math.floor(Date.now() / 1000),
    };
  }
}

// ─── 5. Open Banking / Instant Bank Live Webhook Adapter (SEPA / PIX / UPI) ─

export interface InstantBankLiveConfig {
  providerEndpoint?: string;
  apiToken?: string;
  fetchImpl?: typeof fetch;
}

export class SepaInstantLiveAdapter extends SepaInstantAdapter {
  private readonly endpoint?: string;
  private readonly apiToken?: string;
  private readonly fetchFn: typeof fetch;

  constructor(config: InstantBankLiveConfig = {}, fx = new IntegerFxEngine()) {
    super(fx);
    this.endpoint = config.providerEndpoint ?? process.env.VECTOLL_SEPA_API_URL;
    this.apiToken = config.apiToken ?? process.env.VECTOLL_SEPA_API_TOKEN;
    this.fetchFn = config.fetchImpl ?? fetch;
  }

  override async payout(input: RailPayoutRequest): Promise<RailPayoutResult> {
    if (!this.endpoint || !this.apiToken) return super.payout(input);
    const res = await this.fetchFn(`${this.endpoint.replace(/\/$/, '')}/v1/sepa-credit-transfers`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.apiToken}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': input.batchId,
      },
      body: JSON.stringify({
        iban: input.destinationAccount,
        amountMinor: input.amount,
        currency: input.currency.toUpperCase(),
        reference: `VECTOLL-${input.batchId}`,
      }),
    });
    if (!res.ok) throw new Error(`ERR_SEPA_PAYOUT_${res.status}`);
    const body = (await res.json()) as { transferId?: string };
    return {
      payoutId: body.transferId ?? randomId('pay_sepa', 8),
      railId: this.railId,
      status: 'DISBURSED',
      providerDisbursementRef: body.transferId ?? input.batchId,
      amount: input.amount,
      currency: input.currency.toUpperCase(),
      disbursedAt: Math.floor(Date.now() / 1000),
    };
  }
}

export class PixUpiLiveAdapter extends PixUpiInstantAdapter {
  private readonly endpoint?: string;
  private readonly apiToken?: string;
  private readonly fetchFn: typeof fetch;

  constructor(config: InstantBankLiveConfig = {}, fx = new IntegerFxEngine()) {
    super(fx);
    this.endpoint = config.providerEndpoint ?? process.env.VECTOLL_PIX_UPI_API_URL;
    this.apiToken = config.apiToken ?? process.env.VECTOLL_PIX_UPI_API_TOKEN;
    this.fetchFn = config.fetchImpl ?? fetch;
  }

  override async authorize(input: RailAuthorizeRequest): Promise<RailAuthorization> {
    if (!this.endpoint || !this.apiToken) return super.authorize(input);
    const res = await this.fetchFn(`${this.endpoint.replace(/\/$/, '')}/v1/instant-charges`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.apiToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        amount: input.amount,
        currency: input.currency.toUpperCase(),
        referenceId: input.referenceId,
        agentId: input.agentId,
      }),
    });
    if (!res.ok) throw new Error(`ERR_PIX_UPI_${res.status}`);
    const data = (await res.json()) as { chargeId: string };
    return {
      authorizationId: data.chargeId,
      railId: this.railId,
      status: 'CAPTURED',
      providerRef: data.chargeId,
      amount: input.amount,
      currency: input.currency.toUpperCase(),
      decimals: input.decimals,
      authorizedAt: Math.floor(Date.now() / 1000),
    };
  }
}
