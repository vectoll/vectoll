import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createCreditVoucher, generateKeyPair } from '@vectoll/core';
import {
  BASE_MAINNET_USDC,
  createDefaultAdapterRegistry,
  IntegerFxEngine,
  LiveFxOracle,
  MpesaDarajaLiveAdapter,
  MtnMomoLiveAdapter,
  StripeLiveAdapter,
  verifyHmacWebhookSignature,
  verifyStripeWebhookSignature,
  X402EvmLiveAdapter,
} from '../index.js';

describe('@vectoll/adapters multi-rail registry & integer FX engine', () => {
  it('computes lossless ceiling integer minor-unit FX quotes without floats', () => {
    const fx = new IntegerFxEngine({ spreadBps: 30 });
    // 50 UGX funded from USD (decimals=6, 1 USD = 3,700 UGX)
    const quote = fx.quoteTargetAmount(50, 'UGX', 'USD', 1795753800);
    assert.equal(quote.targetAmount, 50);
    assert.equal(quote.sourceCurrency, 'USD');
    assert.equal(quote.sourceDecimals, 6);
    assert.ok(Number.isSafeInteger(quote.sourceAmount));
    // 50 / 3700 USD = 0.01351351 USD = 13,514 micro-USD (+ 30bps = 13,555 micro-USD)
    assert.equal(quote.sourceAmount, 13555);

    // Same-currency quote has zero spread
    const same = fx.quoteTargetAmount(50, 'UGX', 'UGX');
    assert.equal(same.sourceAmount, 50);
    assert.equal(same.spreadBps, 0);
  });

  it('authorizes, settles, and disburses across Stripe, SEPA, PIX/UPI, x402 USDC, MoMo, and Vouchers', async () => {
    const registry = createDefaultAdapterRegistry();
    assert.equal(registry.list().length, 9);

    const stripe = registry.get('stripe');
    const sAuth = await stripe.authorize({
      agentId: 'did:key:z6MkGlobal',
      amount: 10_000_000,
      currency: 'EUR',
      decimals: 6,
      referenceId: 'eur-001',
    });
    assert.equal(sAuth.status, 'CAPTURED');

    const pix = registry.get('pix_upi');
    const pAuth = await pix.authorize({
      agentId: 'did:key:z6MkGlobal',
      amount: 25_000,
      currency: 'BRL',
      decimals: 2,
      referenceId: 'pix-001',
    });
    assert.equal(pAuth.status, 'CAPTURED');

    const momo = registry.get('momo');
    const auth = await momo.authorize({
      agentId: 'did:key:z6MkTest',
      amount: 100_000,
      currency: 'UGX',
      decimals: 0,
      referenceId: 'topup-001',
    });
    assert.equal(auth.status, 'CAPTURED');

    const payout = await momo.payout({
      merchantService: 'acme-hospitality-api',
      destinationAccount: '+256770000001',
      amount: 49_000,
      currency: 'UGX',
      decimals: 0,
      batchId: 'batch-001',
    });
    assert.equal(payout.status, 'DISBURSED');

    // Cryptographic enterprise voucher check
    const org = generateKeyPair();
    const agent = generateKeyPair();
    const { token } = createCreditVoucher({
      issuerKeyPair: org,
      beneficiaryDid: agent.did,
      service: 'acme-hospitality-api',
      amount: 10_000,
      currency: 'UGX',
      decimals: 0,
    });
    const voucherAdapter = registry.get('voucher');
    const vAuth = await voucherAdapter.authorize({
      agentId: agent.did,
      amount: 10_000,
      currency: 'UGX',
      decimals: 0,
      referenceId: 'vcv-001',
      metadata: { voucherToken: token },
    });
    assert.equal(vAuth.status, 'CAPTURED');
  });

  it('verifies M3 Live Stripe, Base EVM ERC-20 USDC, M-Pesa Daraja, MTN MoMo, webhooks & LiveFxOracle circuit breaker', async () => {
    // 1. StripeLiveAdapter + Stripe-Signature webhook verification
    const stripeLive = new StripeLiveAdapter({
      secretKey: 'sk_test_mock_123',
      fetchImpl: async (url, init) => {
        const body = String(init?.body ?? '');
        if (String(url).endsWith('/v1/payment_intents')) {
          assert.match(body, /amount=500/); // 5,000,000 micro-USD -> 500 cents ($5.00)
          return new Response(JSON.stringify({ id: 'pi_live_999', status: 'succeeded' }), { status: 200 });
        }
        return new Response(JSON.stringify({ id: 'tr_live_888' }), { status: 200 });
      },
    });
    const piAuth = await stripeLive.authorize({
      agentId: 'did:key:z6MkStripe',
      amount: 5_000_000,
      currency: 'USD',
      decimals: 6,
      referenceId: 'ref-stripe-1',
    });
    assert.equal(piAuth.providerRef, 'pi_live_999');

    const now = 1795760000;
    const hookPayload = '{"id":"evt_1","type":"payment_intent.succeeded"}';
    const hookSecret = 'whsec_test_secret';
    const v1 = crypto.createHmac('sha256', hookSecret).update(`${now}.${hookPayload}`).digest('hex');
    assert.equal(
      verifyStripeWebhookSignature(hookPayload, `t=${now},v1=${v1}`, hookSecret, 300, now).valid,
      true,
    );
    assert.equal(
      verifyStripeWebhookSignature(hookPayload, `t=${now - 900},v1=${v1}`, hookSecret, 300, now).valid,
      false,
    );
    assert.equal(
      verifyHmacWebhookSignature(hookPayload, crypto.createHmac('sha256', hookSecret).update(hookPayload).digest('hex'), hookSecret),
      true,
    );

    // 2. X402EvmLiveAdapter Base USDC ERC-20 Transfer log verification
    const treasury = '0x1111111111111111111111111111111111111111';
    const txHash = '0x' + 'a'.repeat(64);
    const evmLive = new X402EvmLiveAdapter({
      rpcUrl: 'https://mainnet.base.org',
      treasuryAddress: treasury,
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            result: {
              status: '0x1',
              transactionHash: txHash,
              logs: [
                {
                  address: BASE_MAINNET_USDC,
                  topics: [
                    '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
                    '0x0000000000000000000000002222222222222222222222222222222222222222',
                    '0x0000000000000000000000001111111111111111111111111111111111111111',
                  ],
                  data: '0x' + (2_000_000n).toString(16).padStart(64, '0'), // 2.00 USDC
                },
              ],
            },
          }),
          { status: 200 },
        ),
    });
    const evmAuth = await evmLive.authorize({
      agentId: 'did:key:z6MkEvm',
      amount: 2_000_000,
      currency: 'USDC',
      decimals: 6,
      referenceId: 'evm-1',
      metadata: { txHash },
    });
    assert.equal(evmAuth.providerRef, txHash);

    // 3. MpesaDarajaLiveAdapter & MtnMomoLiveAdapter OAuth2 + Payment Push
    const mpesaLive = new MpesaDarajaLiveAdapter({
      consumerKey: 'ck',
      consumerSecret: 'cs',
      passkey: 'pk',
      fetchImpl: async (url) => {
        if (String(url).includes('/oauth/')) {
          return new Response(JSON.stringify({ access_token: 'mpesa_tok', expires_in: '3599' }), { status: 200 });
        }
        return new Response(JSON.stringify({ CheckoutRequestID: 'ws_CO_12345', ResponseCode: '0' }), { status: 200 });
      },
    });
    const mpesaAuth = await mpesaLive.authorize({
      agentId: 'did:key:z6MkKe',
      amount: 10_000,
      currency: 'KES',
      decimals: 2,
      referenceId: 'ke-1',
    });
    assert.equal(mpesaAuth.providerRef, 'ws_CO_12345');

    const momoLive = new MtnMomoLiveAdapter({
      apiUser: 'u',
      apiKey: 'k',
      subscriptionKey: 'sub',
      fetchImpl: async (url) => {
        if (String(url).includes('/token/')) {
          return new Response(JSON.stringify({ access_token: 'momo_tok' }), { status: 200 });
        }
        return new Response('', { status: 202 });
      },
    });
    const momoAuth = await momoLive.authorize({
      agentId: 'did:key:z6MkGh',
      amount: 5000,
      currency: 'GHS',
      decimals: 2,
      referenceId: 'gh-1',
    });
    assert.equal(momoAuth.status, 'CAPTURED');

    // 4. LiveFxOracle updates valid currencies and trips circuit breaker on anomalous feeds
    const oracle = new LiveFxOracle({
      maxDeviationPct: 25,
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            base_code: 'USD',
            rates: {
              EUR: 0.94,    // valid (~2% move from 0.92 baseline)
              GBP: 999.0,   // poisoned feed! (>25% deviation -> must be rejected by circuit breaker!)
            },
          }),
          { status: 200 },
        ),
    });
    const sync = await oracle.refresh(1795760000);
    assert.ok(sync.updatedCurrencies.includes('EUR'));
    assert.equal(sync.rejectedAnomalies.length, 1);
    assert.equal(sync.rejectedAnomalies[0]?.currency, 'GBP');
    const q = await oracle.quote(10_000, 'USD', 'EUR', 1795760010);
    assert.ok(q.sourceAmount > 9000 && q.sourceAmount < 10_000);
  });
});
