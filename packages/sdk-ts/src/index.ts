import {
  computeRequestHash,
  decodePaymentHeader,
  parsePrice,
  signAgentHttpHeaders,
  signClearingIntent,
  verifySpendMandate,
  type PaymentChallenge,
  type PaymentResponseHeader,
  type VectollKeyPair,
} from '@vectoll/core';

export interface VectollAgentClientOptions {
  agentKeyPair: VectollKeyPair;
  facilitatorUrl?: string;
  preferredRail: string;
  walletCurrency?: string;
  /** Either minor units (5000) or human-readable string ("$0.05", "0.10 EUR") */
  maxPricePerCall?: number | string;
  mandateToken?: string;
  voucherToken?: string;
  hitlPollIntervalMs?: number;
  hitlTimeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export interface AgentFetchTelemetry {
  challenged: boolean;
  challengeId?: string;
  receiptId?: string;
  debitedAmount?: number;
  debitedCurrency?: string;
  clearingMs?: number;
  totalMs: number;
  paymentResponse?: PaymentResponseHeader;
}

export class VectollAgentClient {
  readonly keyPair: VectollKeyPair;
  readonly facilitatorUrl?: string;
  readonly preferredRail: string;
  readonly walletCurrency?: string;
  readonly maxPricePerCall?: number;
  readonly mandateToken?: string;
  readonly voucherToken?: string;
  readonly hitlPollIntervalMs: number;
  readonly hitlTimeoutMs: number;
  private readonly fetchFn: typeof fetch;

  constructor(options: VectollAgentClientOptions) {
    this.keyPair = options.agentKeyPair;
    this.facilitatorUrl = options.facilitatorUrl?.replace(/\/$/, '');
    this.preferredRail = options.preferredRail;
    this.walletCurrency = options.walletCurrency;
    this.maxPricePerCall =
      typeof options.maxPricePerCall === 'string'
        ? parsePrice(options.maxPricePerCall, options.walletCurrency ?? 'USD').amount
        : options.maxPricePerCall;
    this.mandateToken = options.mandateToken;
    this.voucherToken = options.voucherToken;
    this.hitlPollIntervalMs = options.hitlPollIntervalMs ?? 250;
    this.hitlTimeoutMs = options.hitlTimeoutMs ?? 15_000;
    this.fetchFn = options.fetchImpl ?? fetch;
  }

  async topUp(input: {
    /** Minor units (1_000_000) or human string ("$5.00", "10 EUR", "500 KES") */
    amount: number | string;
    currency?: string;
    decimals?: number;
    rail?: string;
    facilitatorUrl?: string;
  }): Promise<{
    txId: string;
    creditedAmount: number;
    currency: string;
    newBalance: number;
  }> {
    const facUrl = (input.facilitatorUrl ?? this.facilitatorUrl)?.replace(/\/$/, '');
    if (!facUrl) throw new Error('facilitatorUrl is required for topUp');
    const parsed = parsePrice(
      input.amount,
      input.currency ?? this.walletCurrency ?? 'USD',
      input.decimals,
    );
    const res = await this.fetchFn(`${facUrl}/v1/wallets/topup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agentId: this.keyPair.did,
        amount: parsed.amount,
        currency: parsed.currency,
        decimals: parsed.decimals,
        rail: input.rail ?? this.preferredRail,
      }),
    });
    if (!res.ok) {
      throw new Error(`Wallet top-up failed (${res.status}): ${await res.text()}`);
    }
    return (await res.json()) as {
      txId: string;
      creditedAmount: number;
      currency: string;
      newBalance: number;
    };
  }

  async fetchWithTelemetry(
    inputUrl: string | URL,
    init: RequestInit = {},
  ): Promise<{ response: Response; telemetry: AgentFetchTelemetry }> {
    const tStart = performance.now();
    const urlObj = new URL(String(inputUrl));
    const method = (init.method ?? 'GET').toUpperCase();
    const target = `${urlObj.pathname}${urlObj.search}`;

    const bodyBytes =
      init.body === undefined || init.body === null
        ? new Uint8Array(0)
        : typeof init.body === 'string'
          ? new Uint8Array(Buffer.from(init.body, 'utf8'))
          : init.body instanceof Uint8Array
            ? init.body
            : new Uint8Array(Buffer.from(String(init.body), 'utf8'));

    const reqHash = computeRequestHash(method, target, bodyBytes);
    const agentHeaders = signAgentHttpHeaders(reqHash, this.keyPair);

    const headers1 = new Headers(init.headers);
    headers1.set('User-Agent', headers1.get('User-Agent') ?? 'VectollAgent/0.1');
    for (const [k, v] of Object.entries(agentHeaders)) headers1.set(k, v);

    const firstRes = await this.fetchFn(String(inputUrl), {
      ...init,
      method,
      headers: headers1,
      body: bodyBytes.length > 0 ? Buffer.from(bodyBytes) : undefined,
    });

    if (firstRes.status !== 402) {
      return {
        response: firstRes,
        telemetry: { challenged: false, totalMs: Number((performance.now() - tStart).toFixed(3)) },
      };
    }

    // Parse HTTP 402 Challenge (prefer x402 V2 PAYMENT-REQUIRED header, fallback to JSON body)
    const paymentRequiredHdr = firstRes.headers.get('payment-required');
    const challenge: PaymentChallenge = paymentRequiredHdr
      ? decodePaymentHeader<PaymentChallenge>(paymentRequiredHdr)
      : ((await firstRes.json()) as PaymentChallenge);

    // Client-side security check: ensure challenge reqHash matches our exact outbound request!
    if (challenge.reqHash !== reqHash) {
      throw new Error(
        `Security abort: Server challenge reqHash (${challenge.reqHash}) does not match client request (${reqHash})`,
      );
    }

    if (typeof this.maxPricePerCall === 'number' && challenge.amount > this.maxPricePerCall) {
      throw new Error(
        `Agent policy abort: Challenge amount ${challenge.amount} ${challenge.currency} exceeds maxPricePerCall ${this.maxPricePerCall}`,
      );
    }

    // Client-side Spend Mandate pre-verification
    const selectedRail = challenge.acceptedRails.includes(this.preferredRail)
      ? this.preferredRail
      : challenge.acceptedRails[0];
    if (!selectedRail) {
      throw new Error(`No compatible rail between client and ${challenge.service}`);
    }

    if (this.mandateToken) {
      const mCheck = verifySpendMandate(this.mandateToken, {
        expectedAgentId: this.keyPair.did,
        service: challenge.service,
        rail: selectedRail,
        ...(this.walletCurrency === undefined ||
        this.walletCurrency.toUpperCase() === challenge.currency.toUpperCase()
          ? { debitAmountInMandateCurrency: challenge.amount }
          : {}),
      });
      if (!mCheck.valid) {
        throw new Error(`Client Spend Mandate blocked payment (${mCheck.code}): ${mCheck.reason}`);
      }
    }

    const facUrl = (this.facilitatorUrl ?? challenge.facilitatorUrl).replace(/\/$/, '');
    const now = Math.floor(Date.now() / 1000);
    // Allow generous ceiling if cross-currency wallet is used, bounded by maxPricePerCall if set
    const maxAcceptedAmount = this.maxPricePerCall ?? Number.MAX_SAFE_INTEGER;

    const clearSig = signClearingIntent(
      {
        agentId: this.keyPair.did,
        challengeId: challenge.challengeId,
        reqHash: challenge.reqHash,
        maxAcceptedAmount,
        rail: selectedRail,
        timestamp: now,
      },
      this.keyPair,
    );

    const clearRes = await this.fetchFn(`${facUrl}/v1/clear`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge,
        agentId: this.keyPair.did,
        rail: selectedRail,
        walletCurrency: this.walletCurrency ?? challenge.currency,
        maxAcceptedAmount,
        timestamp: now,
        agentSignature: clearSig,
        mandateToken: this.mandateToken,
        voucherToken: this.voucherToken,
      }),
    });

    if (!clearRes.ok) {
      throw new Error(`Facilitator clearing failed (${clearRes.status}): ${await clearRes.text()}`);
    }

    let vrtToken: string | undefined;
    let receiptId: string | undefined;
    let debitedAmount: number | undefined;
    let debitedCurrency: string | undefined;
    let clearingMs: number | undefined;

    if (clearRes.status === 202) {
      // Poll HITL approval until approved, rejected, or timeout
      const pending = (await clearRes.json()) as { approvalId: string; pollUrl: string; reason: string };
      const deadline = Date.now() + this.hitlTimeoutMs;
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, this.hitlPollIntervalMs));
        const poll = await this.fetchFn(`${facUrl}${pending.pollUrl}`);
        if (poll.ok) {
          const state = (await poll.json()) as { status: string; vrt?: string | null };
          if (state.status === 'APPROVED' && state.vrt) {
            vrtToken = state.vrt;
            break;
          }
          if (state.status === 'REJECTED' || state.status === 'EXPIRED') {
            throw new Error(`HITL approval ${state.status} for ${pending.approvalId}`);
          }
        }
      }
      if (!vrtToken) {
        throw new Error(`Timed out waiting for HITL approval (${pending.approvalId})`);
      }
    } else {
      const cleared = (await clearRes.json()) as {
        vrt: string;
        receiptId: string;
        debitedAmount: number;
        debitedCurrency: string;
        clearingMs: number;
      };
      vrtToken = cleared.vrt;
      receiptId = cleared.receiptId;
      debitedAmount = cleared.debitedAmount;
      debitedCurrency = cleared.debitedCurrency;
      clearingMs = cleared.clearingMs;
    }

    // Retry original request with PAYMENT-SIGNATURE: vrt1...
    const retryHeaders = new Headers(headers1);
    retryHeaders.set('PAYMENT-SIGNATURE', vrtToken);

    const paidRes = await this.fetchFn(String(inputUrl), {
      ...init,
      method,
      headers: retryHeaders,
      body: bodyBytes.length > 0 ? Buffer.from(bodyBytes) : undefined,
    });

    const payRespHdr = paidRes.headers.get('payment-response');
    const paymentResponse = payRespHdr
      ? decodePaymentHeader<PaymentResponseHeader>(payRespHdr)
      : undefined;

    return {
      response: paidRes,
      telemetry: {
        challenged: true,
        challengeId: challenge.challengeId,
        receiptId: receiptId ?? paymentResponse?.receiptId,
        debitedAmount,
        debitedCurrency,
        clearingMs,
        totalMs: Number((performance.now() - tStart).toFixed(3)),
        paymentResponse,
      },
    };
  }

  async fetch(inputUrl: string | URL, init?: RequestInit): Promise<Response> {
    const { response } = await this.fetchWithTelemetry(inputUrl, init);
    return response;
  }

  async callMcpTool<T = unknown>(
    mcpEndpointUrl: string,
    toolName: string,
    args: Record<string, unknown> = {},
  ): Promise<{ data: T; telemetry: AgentFetchTelemetry }> {
    const { response, telemetry } = await this.fetchWithTelemetry(mcpEndpointUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: Date.now(),
        method: 'tools/call',
        params: { name: toolName, arguments: args },
      }),
    });
    if (!response.ok) {
      throw new Error(`MCP call failed (${response.status}): ${await response.text()}`);
    }
    const rpcOut = (await response.json()) as {
      result?: { content?: Array<{ type: string; text: string }> };
      error?: { message: string };
    };
    if (rpcOut.error) {
      throw new Error(`MCP RPC Error: ${rpcOut.error.message}`);
    }
    const rawText = rpcOut.result?.content?.[0]?.text ?? '{}';
    let parsed: T;
    try {
      parsed = JSON.parse(rawText) as T;
    } catch {
      parsed = rawText as unknown as T;
    }
    return { data: parsed, telemetry };
  }
}
