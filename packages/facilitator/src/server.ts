import http from 'node:http';
import { performance } from 'node:perf_hooks';
import {
  base64UrlDecode,
  base64UrlEncode,
  ed25519Sign,
  ed25519Verify,
  generateKeyPair,
  getCurrencyDecimals,
  keyPairFromSeed,
  randomId,
  sha256Hex,
  signVrt,
  toPublicJwk,
  verifyClearingIntent,
  verifySpendMandate,
  type PaymentChallenge,
  type VectollKeyPair,
} from '@vectoll/core';
import { createDefaultAdapterRegistry, type AdapterRegistry } from '@vectoll/adapters';
import { DoubleEntryLedger, type EscrowRecord, type HitlRecord, type JournalPostingInput } from './ledger.js';

export interface FacilitatorOptions {
  dbPath?: string;
  facilitatorKey?: VectollKeyPair;
  facilitatorSeed?: string;
  facilitatorKid?: string;
  issuerUrl?: string;
  feeBps?: number;
  adminKey?: string;
  hitlWebhookUrl?: string;
  merchantWebhookUrl?: string;
  adapters?: AdapterRegistry;
}

export interface ClearRequestBody {
  challenge: PaymentChallenge;
  agentId: string;
  rail: string;
  walletCurrency?: string;
  maxAcceptedAmount: number;
  timestamp: number;
  agentSignature: string;
  mandateToken?: string;
  voucherToken?: string;
}

export class VectollFacilitator {
  readonly keyPair: VectollKeyPair;
  readonly ledger: DoubleEntryLedger;
  readonly adapters: AdapterRegistry;
  readonly feeBps: number;
  readonly adminKey?: string;
  readonly hitlWebhookUrl?: string;
  readonly merchantWebhookUrl?: string;
  issuerUrl: string;

  constructor(options: FacilitatorOptions = {}) {
    const kid = options.facilitatorKid ?? process.env.VECTOLL_FACILITATOR_KID ?? 'fac-key-1';
    if (options.facilitatorKey) {
      this.keyPair = options.facilitatorKey;
    } else if (options.facilitatorSeed ?? process.env.VECTOLL_FACILITATOR_SEED) {
      this.keyPair = keyPairFromSeed(
        (options.facilitatorSeed ?? process.env.VECTOLL_FACILITATOR_SEED)!,
        kid,
      );
    } else {
      this.keyPair = generateKeyPair(kid);
    }

    this.ledger = new DoubleEntryLedger(options.dbPath ?? process.env.VECTOLL_DB_PATH ?? ':memory:');
    this.adapters = options.adapters ?? createDefaultAdapterRegistry();
    this.feeBps = options.feeBps ?? Number(process.env.VECTOLL_FEE_BPS ?? 150);
    this.issuerUrl = options.issuerUrl ?? 'http://127.0.0.1:4021';
    this.adminKey = options.adminKey ?? process.env.VECTOLL_ADMIN_KEY;
    this.hitlWebhookUrl = options.hitlWebhookUrl ?? process.env.VECTOLL_HITL_WEBHOOK_URL;
    this.merchantWebhookUrl = options.merchantWebhookUrl ?? process.env.VECTOLL_WEBHOOK_URL;
  }

  signWebhookPayload(eventType: string, data: unknown, timestamp = Math.floor(Date.now() / 1000)): {
    body: string;
    headers: Record<string, string>;
  } {
    const eventId = randomId('evt', 10);
    const body = JSON.stringify({
      id: eventId,
      type: eventType,
      createdAt: timestamp,
      issuer: this.issuerUrl,
      kid: this.keyPair.kid,
      data,
    });
    const sigInput = `vectoll-webhook/v1.${timestamp}.${body}`;
    const sig = base64UrlEncode(ed25519Sign(this.keyPair.privateSeedBytes, sigInput));
    return {
      body,
      headers: {
        'Content-Type': 'application/json',
        'X-Vectoll-Webhook-Id': eventId,
        'X-Vectoll-Webhook-Timestamp': String(timestamp),
        'X-Vectoll-Webhook-Kid': this.keyPair.kid,
        'X-Vectoll-Webhook-Signature': sig,
      },
    };
  }

  private emitWebhook(targetUrl: string | undefined, eventType: string, data: unknown): void {
    if (!targetUrl) return;
    const { body, headers } = this.signWebhookPayload(eventType, data);
    fetch(targetUrl, { method: 'POST', headers, body }).catch(() => undefined);
  }

  revokeSpendMandate(input: {
    mandateId: string;
    principalId: string;
    reason?: string;
    timestamp?: number;
    principalSignature?: string;
  }): { mandateId: string; revoked: true } {
    if (input.principalSignature) {
      const ts = input.timestamp ?? Math.floor(Date.now() / 1000);
      const msg = `vectoll-revoke/v1\n${input.principalId}\n${input.mandateId}\n${ts}`;
      if (!ed25519Verify(input.principalId, msg, input.principalSignature)) {
        throw new Error('ERR_INVALID_REVOCATION_SIGNATURE: Principal signature check failed');
      }
    }
    this.ledger.revokeMandate(input.mandateId, input.principalId, input.reason);
    return { mandateId: input.mandateId, revoked: true };
  }

  getJwks(): { keys: ReturnType<typeof toPublicJwk>[] } {
    const peerRows = this.ledger.db
      .prepare('SELECT kid, public_key_b64url AS pub FROM federation_peers ORDER BY created_at ASC')
      .all() as Array<{ kid: string; pub: string }>;

    return {
      keys: [
        toPublicJwk(this.keyPair),
        ...peerRows.map((p) => ({
          kty: 'OKP' as const,
          crv: 'Ed25519' as const,
          kid: p.kid,
          use: 'sig' as const,
          alg: 'EdDSA' as const,
          x: p.pub,
        })),
      ],
    };
  }

  // ─── Multi-Tenant Merchant Accounts & Scoped API Keys (vk_live_*) ────────

  registerMerchant(input: {
    orgName: string;
    serviceName: string;
    webhookUrl?: string;
    payoutAccount?: string;
    scopes?: string[];
  }): {
    merchantId: string;
    orgName: string;
    serviceName: string;
    domainVerifyToken: string;
    keyId: string;
    apiKey: string;
    scopes: string[];
  } {
    if (!input.orgName || !input.serviceName) {
      throw new Error('ERR_INVALID_MERCHANT: orgName and serviceName are required');
    }
    const now = Math.floor(Date.now() / 1000);
    const merchantId = randomId('mch', 8);
    const domainVerifyToken = randomId('vectoll_verify', 16);

    return this.ledger.runSerializable(() => {
      this.ledger.db
        .prepare(
          `INSERT INTO merchants (merchant_id, org_name, service_name, webhook_url, payout_account, domain_verify_token, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          merchantId,
          input.orgName,
          input.serviceName,
          input.webhookUrl ?? null,
          input.payoutAccount ?? null,
          domainVerifyToken,
          now,
        );

      const issued = this.issueMerchantApiKeyInternal(
        merchantId,
        input.scopes ?? ['hitl:decide', 'escrow:manage', 'payouts:write', 'ledger:read'],
        now,
      );
      return {
        merchantId,
        orgName: input.orgName,
        serviceName: input.serviceName,
        domainVerifyToken,
        ...issued,
      };
    });
  }

  private issueMerchantApiKeyInternal(merchantId: string, scopes: string[], now = Math.floor(Date.now() / 1000)) {
    const keyId = randomId('key', 8);
    const rawSecret = randomId('vk_live', 24);
    const keyPrefix = rawSecret.slice(0, 16);
    const keyHash = sha256Hex(rawSecret);

    this.ledger.db
      .prepare(
        `INSERT INTO merchant_api_keys (key_id, merchant_id, key_prefix, key_hash_sha256, scopes_json, revoked_at, created_at)
         VALUES (?, ?, ?, ?, ?, NULL, ?)`,
      )
      .run(keyId, merchantId, keyPrefix, keyHash, JSON.stringify(scopes), now);

    return { keyId, apiKey: rawSecret, scopes };
  }

  issueMerchantApiKey(merchantId: string, scopes: string[]) {
    return this.ledger.runSerializable(() => this.issueMerchantApiKeyInternal(merchantId, scopes));
  }

  revokeMerchantApiKey(merchantId: string, keyId: string): { keyId: string; revoked: true } {
    const now = Math.floor(Date.now() / 1000);
    this.ledger.db
      .prepare('UPDATE merchant_api_keys SET revoked_at = ? WHERE merchant_id = ? AND key_id = ?')
      .run(now, merchantId, keyId);
    return { keyId, revoked: true };
  }

  authorizeServiceAction(
    serviceName: string,
    requiredScope: string,
    authHeader?: string,
  ): { authorized: boolean; status?: number; reason?: string } {
    if (this.adminKey && authHeader === `Bearer ${this.adminKey}`) {
      return { authorized: true };
    }

    const merchant = this.ledger.db
      .prepare('SELECT merchant_id AS merchantId FROM merchants WHERE service_name = ?')
      .get(serviceName) as { merchantId: string } | undefined;

    if (!merchant) {
      // Unregistered sandbox service: enforce global adminKey only if configured
      if (this.adminKey) {
        return { authorized: false, status: 401, reason: 'ERR_UNAUTHORIZED: Invalid admin token' };
      }
      return { authorized: true };
    }

    if (!authHeader?.startsWith('Bearer vk_live_')) {
      return {
        authorized: false,
        status: 401,
        reason: `ERR_UNAUTHORIZED_MERCHANT: Service "${serviceName}" requires a valid Bearer vk_live_* API key`,
      };
    }

    const token = authHeader.slice('Bearer '.length).trim();
    const tokenHash = sha256Hex(token);
    const keyRow = this.ledger.db
      .prepare(
        `SELECT merchant_id AS merchantId, scopes_json AS scopesJson, revoked_at AS revokedAt
         FROM merchant_api_keys WHERE key_hash_sha256 = ?`,
      )
      .get(tokenHash) as { merchantId: string; scopesJson: string; revokedAt: number | null } | undefined;

    if (!keyRow || keyRow.revokedAt !== null) {
      return { authorized: false, status: 401, reason: 'ERR_INVALID_API_KEY: API key unknown or revoked' };
    }
    if (keyRow.merchantId !== merchant.merchantId) {
      return {
        authorized: false,
        status: 403,
        reason: `ERR_TENANT_FORBIDDEN: API key belongs to another merchant tenant, not "${serviceName}"`,
      };
    }

    const scopes = JSON.parse(keyRow.scopesJson) as string[];
    if (!scopes.includes('*') && !scopes.includes(requiredScope)) {
      return {
        authorized: false,
        status: 403,
        reason: `ERR_INSUFFICIENT_SCOPE: Key lacks required scope "${requiredScope}"`,
      };
    }
    return { authorized: true };
  }

  // ─── Federated Cross-Facilitator Peering (vfv1) ──────────────────────────

  registerPeerFacilitator(input: {
    peerId: string;
    issuerUrl: string;
    kid: string;
    publicKeyBase64Url: string;
    creditLimitUsdMicro?: number;
  }) {
    const cleanUrl = input.issuerUrl.replace(/\/$/, '');
    const limit = input.creditLimitUsdMicro ?? 1_000_000_000; // $1,000 default bilateral credit line
    const now = Math.floor(Date.now() / 1000);
    this.ledger.db
      .prepare(
        `INSERT INTO federation_peers (peer_id, issuer_url, kid, public_key_b64url, credit_limit_usd_micro, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(issuer_url) DO UPDATE SET
           peer_id = excluded.peer_id,
           kid = excluded.kid,
           public_key_b64url = excluded.public_key_b64url,
           credit_limit_usd_micro = excluded.credit_limit_usd_micro`,
      )
      .run(input.peerId, cleanUrl, input.kid, input.publicKeyBase64Url, limit, now);
    return { peerId: input.peerId, issuerUrl: cleanUrl, kid: input.kid, creditLimitUsdMicro: limit };
  }

  private getPeerByUrl(url: string) {
    return this.ledger.db
      .prepare(
        `SELECT peer_id AS peerId, issuer_url AS issuerUrl, kid, public_key_b64url AS publicKeyBase64Url,
                credit_limit_usd_micro AS creditLimitUsdMicro
         FROM federation_peers WHERE issuer_url = ?`,
      )
      .get(url.replace(/\/$/, '')) as
      | { peerId: string; issuerUrl: string; kid: string; publicKeyBase64Url: string; creditLimitUsdMicro: number }
      | undefined;
  }

  private getPeerByIssuer(issuerUrl: string) {
    return this.getPeerByUrl(issuerUrl);
  }

  settleInboundFederationVoucher(voucherToken: string) {
    const parts = voucherToken.trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'vfv1') {
      throw new Error('ERR_MALFORMED_FEDERATION_VOUCHER');
    }
    const [, payloadB64, sigB64] = parts as [string, string, string];
    const claims = JSON.parse(Buffer.from(base64UrlDecode(payloadB64)).toString('utf8')) as {
      voucherId: string;
      peerIssuer: string;
      targetIssuer: string;
      agentId: string;
      challenge: PaymentChallenge;
      rail: string;
      issuedAt: number;
      expiresAt: number;
    };

    const peer = this.getPeerByIssuer(claims.peerIssuer);
    if (!peer) {
      throw new Error(`ERR_UNTRUSTED_FEDERATION_PEER: ${claims.peerIssuer} is not a registered peer`);
    }
    if (!ed25519Verify(peer.publicKeyBase64Url, `vfv1.${payloadB64}`, sigB64)) {
      throw new Error('ERR_INVALID_FEDERATION_SIGNATURE: Peer Ed25519 signature invalid');
    }

    const now = Math.floor(Date.now() / 1000);
    if (now > claims.expiresAt + 10) {
      throw new Error('ERR_FEDERATION_VOUCHER_EXPIRED');
    }

    const chg = claims.challenge;
    const cur = chg.currency.toUpperCase();
    const usdEquiv = this.adapters.fx.quoteTargetAmount(chg.amount, cur, 'USD', now).sourceAmount;

    return this.ledger.runSerializable(() => {
      // Enforce bilateral peer credit limit in USD micro-units
      const currentReceivableInCur = this.ledger.getAccountBalance(
        `asset:peer_receivable:${peer.peerId}`,
        cur,
      );
      const currentReceivableUsd = this.adapters.fx.quoteTargetAmount(
        currentReceivableInCur,
        cur,
        'USD',
        now,
      ).sourceAmount;

      if (currentReceivableUsd + usdEquiv > peer.creditLimitUsdMicro) {
        throw new Error(
          `ERR_PEER_CREDIT_LIMIT_EXCEEDED: Peer ${peer.peerId} receivable would exceed ${peer.creditLimitUsdMicro} micro-USD`,
        );
      }

      const fee = Math.floor((chg.amount * this.feeBps) / 10_000);
      const merchantNet = chg.amount - fee;

      const postings: JournalPostingInput[] = [
        {
          accountCode: `asset:peer_receivable:${peer.peerId}`,
          accountType: 'asset',
          currency: cur,
          decimals: chg.decimals,
          debit: chg.amount,
          credit: 0,
        },
        {
          accountCode: `liability:merchant_payable:${chg.service}`,
          accountType: 'liability',
          currency: cur,
          decimals: chg.decimals,
          debit: 0,
          credit: merchantNet,
        },
      ];
      if (fee > 0) {
        postings.push({
          accountCode: 'revenue:facilitator_fee',
          accountType: 'revenue',
          currency: cur,
          decimals: chg.decimals,
          debit: 0,
          credit: fee,
        });
      }

      const txId = this.ledger.postJournal({
        idempotencyKey: `fed_in:${chg.challengeId}`,
        txKind: 'FEDERATION_INBOUND_SETTLE',
        description: `Inbound federated settlement from ${peer.peerId} for ${chg.service}`,
        inExistingTransaction: true,
        postings,
      });

      const { token, claims: vrtClaims } = signVrt(
        {
          iss: this.issuerUrl,
          sub: claims.agentId,
          aud: chg.service,
          chg: chg.challengeId,
          req: chg.reqHash,
          amt: chg.amount,
          cur,
          dec: chg.decimals,
          rail: claims.rail,
          mode: 'instant',
          iat: now,
          ttlSeconds: 120,
        },
        this.keyPair,
      );

      return {
        status: 'CLEARED' as const,
        vrt: token,
        receiptId: vrtClaims.jti,
        txId,
        peerId: peer.peerId,
      };
    });
  }

  getFederationPositions() {
    const peers = this.ledger.db
      .prepare('SELECT peer_id AS peerId, issuer_url AS issuerUrl, kid, credit_limit_usd_micro AS creditLimitUsdMicro FROM federation_peers')
      .all() as Array<{ peerId: string; issuerUrl: string; kid: string; creditLimitUsdMicro: number }>;

    const accounts = this.ledger.db
      .prepare(
        "SELECT account_code AS accountCode, currency, decimals, account_type AS accountType, debit_total AS debitTotal, credit_total AS creditTotal FROM accounts WHERE account_code LIKE 'asset:peer_receivable:%' OR account_code LIKE 'liability:peer_payable:%'",
      )
      .all() as Array<{
      accountCode: string;
      currency: string;
      decimals: number;
      accountType: string;
      debitTotal: number;
      creditTotal: number;
    }>;

    return {
      peers,
      positions: accounts.map((a) => ({
        accountCode: a.accountCode,
        currency: a.currency,
        decimals: a.decimals,
        balance: a.accountType === 'asset' ? a.debitTotal - a.creditTotal : a.creditTotal - a.debitTotal,
      })),
    };
  }

  // ─── Global A2A Service Discovery Index & Search Engine ───────────────────

  async indexDomainManifest(
    domainBaseUrl: string,
    fetchImpl: typeof fetch = fetch,
  ): Promise<{
    baseUrl: string;
    serviceName: string;
    indexedRoutes: number;
    acceptedRails: string[];
  }> {
    const cleanBase = domainBaseUrl.trim().replace(/\/$/, '');
    const manifestUrl = cleanBase.endsWith('.json')
      ? cleanBase
      : `${cleanBase}/.well-known/vectoll.json`;
    const serviceOrigin = cleanBase.replace(/\/\.well-known\/vectoll\.json$/, '');

    const res = await fetchImpl(manifestUrl, { headers: { Accept: 'application/json' } });
    if (!res.ok) {
      throw new Error(`ERR_DISCOVERY_FETCH_${res.status}: Could not load ${manifestUrl}`);
    }

    const doc = (await res.json()) as {
      vectollVersion?: string;
      service?: { name?: string; description?: string; mcpEndpoint?: string | null };
      settlement?: { facilitatorUrl?: string; acceptedRails?: string[] };
      routes?: Array<{
        path: string;
        method: string;
        amount: number;
        currency: string;
        decimals: number;
        mcpTool?: { name: string; description?: string } | null;
      }>;
    };

    if (!doc.vectollVersion || !doc.service?.name || !Array.isArray(doc.routes)) {
      throw new Error('ERR_INVALID_MANIFEST: Missing vectollVersion, service.name, or routes');
    }

    const serviceName = doc.service.name;
    const serviceDesc = doc.service.description ?? serviceName;
    const facUrl = doc.settlement?.facilitatorUrl ?? this.issuerUrl;
    const rails = doc.settlement?.acceptedRails ?? [];
    const now = Math.floor(Date.now() / 1000);

    this.ledger.runSerializable(() => {
      this.ledger.db.prepare('DELETE FROM discovery_tools WHERE base_url = ?').run(serviceOrigin);
      this.ledger.db
        .prepare(
          `INSERT INTO discovery_services (
             base_url, service_name, description, mcp_endpoint, facilitator_url,
             accepted_rails_json, manifest_json, last_indexed_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(base_url) DO UPDATE SET
             service_name = excluded.service_name,
             description = excluded.description,
             mcp_endpoint = excluded.mcp_endpoint,
             facilitator_url = excluded.facilitator_url,
             accepted_rails_json = excluded.accepted_rails_json,
             manifest_json = excluded.manifest_json,
             last_indexed_at = excluded.last_indexed_at`,
        )
        .run(
          serviceOrigin,
          serviceName,
          serviceDesc,
          doc.service?.mcpEndpoint ?? null,
          facUrl,
          JSON.stringify(rails),
          JSON.stringify(doc),
          now,
        );

      const insTool = this.ledger.db.prepare(
        `INSERT INTO discovery_tools (
           base_url, service_name, route_path, http_method, mcp_tool_name, description,
           amount, currency, decimals, price_usd_micro, accepted_rails_json
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );

      for (const r of doc.routes ?? []) {
        const cur = (r.currency ?? 'USD').toUpperCase();
        const dec = getCurrencyDecimals(cur, r.decimals);
        const usdMicro = this.adapters.fx.quoteTargetAmount(r.amount ?? 0, cur, 'USD', now).sourceAmount;
        const toolDesc = r.mcpTool?.description ?? `${serviceDesc} (${r.method} ${r.path})`;
        insTool.run(
          serviceOrigin,
          serviceName,
          r.path,
          r.method.toUpperCase(),
          r.mcpTool?.name ?? null,
          toolDesc,
          r.amount ?? 0,
          cur,
          dec,
          usdMicro,
          JSON.stringify(rails),
        );
      }
    });

    return {
      baseUrl: serviceOrigin,
      serviceName,
      indexedRoutes: doc.routes.length,
      acceptedRails: rails,
    };
  }

  searchDiscoveryIndex(query: {
    q?: string;
    rail?: string;
    maxPriceUsdMicro?: number;
    limit?: number;
  } = {}) {
    const rows = this.ledger.db
      .prepare(
        `SELECT
           t.base_url AS baseUrl,
           t.service_name AS serviceName,
           s.mcp_endpoint AS mcpEndpoint,
           s.facilitator_url AS facilitatorUrl,
           t.route_path AS routePath,
           t.http_method AS method,
           t.mcp_tool_name AS mcpToolName,
           t.description,
           t.amount,
           t.currency,
           t.decimals,
           t.price_usd_micro AS priceUsdMicro,
           t.accepted_rails_json AS acceptedRailsJson
         FROM discovery_tools t
         JOIN discovery_services s ON s.base_url = t.base_url
         ORDER BY t.price_usd_micro ASC`,
      )
      .all() as Array<{
      baseUrl: string;
      serviceName: string;
      mcpEndpoint: string | null;
      facilitatorUrl: string;
      routePath: string;
      method: string;
      mcpToolName: string | null;
      description: string;
      amount: number;
      currency: string;
      decimals: number;
      priceUsdMicro: number;
      acceptedRailsJson: string;
    }>;

    const kw = query.q?.trim().toLowerCase();
    const filtered = rows
      .map((r) => ({
        baseUrl: r.baseUrl,
        serviceName: r.serviceName,
        mcpEndpoint: r.mcpEndpoint,
        facilitatorUrl: r.facilitatorUrl,
        routePath: r.routePath,
        method: r.method,
        mcpToolName: r.mcpToolName,
        description: r.description,
        amount: r.amount,
        currency: r.currency,
        decimals: r.decimals,
        priceUsdMicro: r.priceUsdMicro,
        acceptedRails: JSON.parse(r.acceptedRailsJson) as string[],
      }))
      .filter((item) => {
        if (kw) {
          const hay = `${item.serviceName} ${item.mcpToolName ?? ''} ${item.routePath} ${item.description}`.toLowerCase();
          if (!hay.includes(kw)) return false;
        }
        if (query.rail && !item.acceptedRails.includes(query.rail)) {
          return false;
        }
        if (typeof query.maxPriceUsdMicro === 'number' && item.priceUsdMicro > query.maxPriceUsdMicro) {
          return false;
        }
        return true;
      });

    return filtered.slice(0, query.limit ?? 50);
  }

  async topUpWallet(input: {
    agentId: string;
    amount: number;
    currency: string;
    decimals?: number;
    rail: string;
    idempotencyKey?: string;
    metadata?: Record<string, string>;
  }): Promise<{
    txId: string;
    agentId: string;
    creditedAmount: number;
    currency: string;
    decimals: number;
    newBalance: number;
    providerRef: string;
  }> {
    const cur = input.currency.toUpperCase();
    const dec = getCurrencyDecimals(cur, input.decimals);
    const idem = input.idempotencyKey ?? randomId('topup', 10);

    const cached = this.ledger.getExistingResult<{
      txId: string;
      agentId: string;
      creditedAmount: number;
      currency: string;
      decimals: number;
      newBalance: number;
      providerRef: string;
    }>(idem);
    if (cached) return cached;

    const adapter = this.adapters.get(input.rail);
    const auth = await adapter.authorize({
      agentId: input.agentId,
      amount: input.amount,
      currency: cur,
      decimals: dec,
      referenceId: idem,
      metadata: input.metadata,
    });

    return this.ledger.runSerializable(() => {
      const txId = this.ledger.postJournal({
        idempotencyKey: idem,
        txKind: 'WALLET_TOPUP',
        description: `Top-up ${input.amount} ${cur} via ${input.rail} (${auth.providerRef})`,
        inExistingTransaction: true,
        postings: [
          {
            accountCode: `asset:rail_clearing:${input.rail}:${cur}`,
            accountType: 'asset',
            currency: cur,
            decimals: dec,
            debit: input.amount,
            credit: 0,
          },
          {
            accountCode: `liability:agent_float:${input.agentId}`,
            accountType: 'liability',
            currency: cur,
            decimals: dec,
            debit: 0,
            credit: input.amount,
          },
        ],
      });
      const newBalance = this.ledger.getAccountBalance(`liability:agent_float:${input.agentId}`, cur);
      const res = {
        txId,
        agentId: input.agentId,
        creditedAmount: input.amount,
        currency: cur,
        decimals: dec,
        newBalance,
        providerRef: auth.providerRef,
      };
      this.ledger.setTransactionResult(txId, res);
      this.ledger.recordTelemetry({
        eventType: 'WALLET_TOPUP',
        service: 'facilitator',
        route: '/v1/wallets/topup',
        agentId: input.agentId,
        rail: input.rail,
        amount: input.amount,
        currency: cur,
      });
      return res;
    });
  }

  async clearChallenge(body: ClearRequestBody): Promise<
    | {
        status: 'CLEARED';
        vrt: string;
        receiptId: string;
        txId: string;
        mode: 'instant' | 'escrow';
        escrowId?: string;
        debitedAmount: number;
        debitedCurrency: string;
        settledAmount: number;
        settledCurrency: string;
        clearingMs: number;
      }
    | {
        status: 'PENDING_HITL';
        approvalId: string;
        pollUrl: string;
        reason: string;
        expiresAt: number;
      }
  > {
    const t0 = performance.now();
    const { challenge } = body;
    const now = Math.floor(Date.now() / 1000);

    // Idempotency by challengeId
    const cached = this.ledger.getExistingResult<{
      status: 'CLEARED';
      vrt: string;
      receiptId: string;
      txId: string;
      mode: 'instant' | 'escrow';
      escrowId?: string;
      debitedAmount: number;
      debitedCurrency: string;
      settledAmount: number;
      settledCurrency: string;
      clearingMs: number;
    }>(`clear:${challenge.challengeId}`);
    if (cached) return cached;

    if (now > challenge.expiresAt + 5) {
      throw new Error('ERR_CHALLENGE_EXPIRED: 402 challenge TTL exceeded');
    }
    if (!challenge.acceptedRails.includes(body.rail)) {
      throw new Error(`ERR_RAIL_NOT_ACCEPTED: ${body.rail} is not accepted by ${challenge.service}`);
    }

    // 1. Verify Agent Ed25519 Clearing Signature
    const sigCheck = verifyClearingIntent(
      {
        agentId: body.agentId,
        challengeId: challenge.challengeId,
        reqHash: challenge.reqHash,
        maxAcceptedAmount: body.maxAcceptedAmount,
        rail: body.rail,
        timestamp: body.timestamp,
      },
      body.agentSignature,
      now,
    );
    if (!sigCheck.valid) {
      throw new Error(`ERR_AGENT_SIGNATURE: ${sigCheck.reason}`);
    }

    // 2. If rail === 'voucher' and voucherToken provided, auto-credit voucher to agent wallet first
    if (body.rail === 'voucher' && body.voucherToken) {
      await this.topUpWallet({
        agentId: body.agentId,
        amount: challenge.amount,
        currency: challenge.currency,
        decimals: challenge.decimals,
        rail: 'voucher',
        idempotencyKey: `vcv_auto:${challenge.challengeId}`,
        metadata: { voucherToken: body.voucherToken },
      });
    }

    // 3. Determine wallet currency & quote FX if cross-currency
    const targetCur = challenge.currency.toUpperCase();
    const walletCur = (body.walletCurrency ?? targetCur).toUpperCase();
    const fxQuote = this.adapters.fx.quoteTargetAmount(challenge.amount, targetCur, walletCur, now);

    if (fxQuote.sourceAmount > body.maxAcceptedAmount) {
      throw new Error(
        `ERR_SLIPPAGE_EXCEEDED: Required ${fxQuote.sourceAmount} ${walletCur} exceeds maxAcceptedAmount ${body.maxAcceptedAmount}`,
      );
    }

    // 4. Verify Spend Mandate (required when challenge.requireMandate === true OR when supplied)
    if (challenge.requireMandate && !body.mandateToken) {
      throw new Error('ERR_MANDATE_REQUIRED: Route requires a Principal-signed Spend Mandate (vsm1)');
    }

    let mandateRequiresHitl = false;
    let verifiedMandateId: string | null = null;
    let debitInMandateCur = challenge.amount;
    let mandateCurrency = targetCur;

    if (body.mandateToken) {
      // Peek mandate currency via initial structural check
      const prelim = verifySpendMandate(body.mandateToken, {
        expectedAgentId: body.agentId,
        service: challenge.service,
        rail: body.rail,
        nowSeconds: now,
      });
      if (!prelim.valid) {
        throw new Error(`${prelim.code}: ${prelim.reason}`);
      }
      if (this.ledger.isMandateRevoked(prelim.claims.mandateId)) {
        throw new Error(`ERR_MANDATE_REVOKED: Spend mandate ${prelim.claims.mandateId} has been revoked`);
      }
      mandateCurrency = prelim.claims.currency;
      const mandateQuote = this.adapters.fx.quoteTargetAmount(
        challenge.amount,
        targetCur,
        mandateCurrency,
        now,
      );
      debitInMandateCur = mandateQuote.sourceAmount;
      const spent24h = this.ledger.getMandateSpendLast24h(prelim.claims.mandateId, mandateCurrency, now);

      const fullCheck = verifySpendMandate(body.mandateToken, {
        expectedAgentId: body.agentId,
        service: challenge.service,
        rail: body.rail,
        debitAmountInMandateCurrency: debitInMandateCur,
        spentLast24hInMandateCurrency: spent24h,
        nowSeconds: now,
      });
      if (!fullCheck.valid) {
        throw new Error(`${fullCheck.code}: ${fullCheck.reason}`);
      }
      mandateRequiresHitl = fullCheck.requiresHitl;
      verifiedMandateId = fullCheck.claims.mandateId;
    }

    const routeRequiresHitl =
      typeof challenge.hitlThreshold === 'number' && challenge.amount >= challenge.hitlThreshold;

    // 5. Check Human-in-the-Loop (HITL) Trigger
    if (routeRequiresHitl || mandateRequiresHitl) {
      const existingHitl = this.ledger.db
        .prepare('SELECT approval_id, status, vrt_token, reason, expires_at FROM hitl_approvals WHERE challenge_id = ?')
        .get(challenge.challengeId) as
        | { approval_id: string; status: string; vrt_token: string | null; reason: string; expires_at: number }
        | undefined;

      if (existingHitl) {
        if (existingHitl.status === 'APPROVED' && existingHitl.vrt_token) {
          return {
            status: 'CLEARED',
            vrt: existingHitl.vrt_token,
            receiptId: 'hitl_approved',
            txId: 'hitl_tx',
            mode: challenge.settlementMode,
            debitedAmount: fxQuote.sourceAmount,
            debitedCurrency: walletCur,
            settledAmount: challenge.amount,
            settledCurrency: targetCur,
            clearingMs: Number((performance.now() - t0).toFixed(3)),
          };
        }
        return {
          status: 'PENDING_HITL',
          approvalId: existingHitl.approval_id,
          pollUrl: `/v1/hitl/${existingHitl.approval_id}`,
          reason: existingHitl.reason,
          expiresAt: existingHitl.expires_at,
        };
      }

      const approvalId = randomId('hitl', 8);
      const expiresAt = now + 900;
      const reason = `Transaction of ${challenge.amount} ${targetCur} on ${challenge.service} (${challenge.resource}) requires human approval`;
      this.ledger.db
        .prepare(
          `INSERT INTO hitl_approvals (
             approval_id, challenge_id, agent_id, service, resource, method, req_hash,
             amount, currency, decimals, settlement_mode, rail, wallet_currency, mandate_id,
             status, vrt_token, reason, created_at, expires_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_HITL', NULL, ?, ?, ?)`,
        )
        .run(
          approvalId,
          challenge.challengeId,
          body.agentId,
          challenge.service,
          challenge.resource,
          challenge.method,
          challenge.reqHash,
          challenge.amount,
          targetCur,
          challenge.decimals,
          challenge.settlementMode,
          body.rail,
          walletCur,
          verifiedMandateId,
          reason,
          now,
          expiresAt,
        );

      this.ledger.recordTelemetry({
        eventType: 'HITL_PAUSED',
        service: challenge.service,
        route: challenge.resource,
        agentId: body.agentId,
        rail: body.rail,
        amount: challenge.amount,
        currency: targetCur,
      });

      this.emitWebhook(this.hitlWebhookUrl ?? this.merchantWebhookUrl, 'hitl.requested', {
        approvalId,
        service: challenge.service,
        amount: challenge.amount,
        currency: targetCur,
        reason,
      });

      return {
        status: 'PENDING_HITL',
        approvalId,
        pollUrl: `/v1/hitl/${approvalId}`,
        reason,
        expiresAt,
      };
    }

    // 5b. Federated Outbound Clearing when challenge targets a peered remote Facilitator!
    const targetFacUrl = challenge.facilitatorUrl.replace(/\/$/, '');
    const selfUrl = this.issuerUrl.replace(/\/$/, '');
    const remotePeer = targetFacUrl !== selfUrl ? this.getPeerByUrl(targetFacUrl) : undefined;

    if (remotePeer && challenge.settlementMode === 'instant') {
      // Debit local agent float -> credit liability:peer_payable:<peerId>
      const outTxId = this.ledger.runSerializable(() => {
        const postings: JournalPostingInput[] =
          walletCur === targetCur
            ? [
                {
                  accountCode: `liability:agent_float:${body.agentId}`,
                  accountType: 'liability',
                  currency: walletCur,
                  decimals: fxQuote.sourceDecimals,
                  debit: fxQuote.sourceAmount,
                  credit: 0,
                },
                {
                  accountCode: `liability:peer_payable:${remotePeer.peerId}`,
                  accountType: 'liability',
                  currency: targetCur,
                  decimals: challenge.decimals,
                  debit: 0,
                  credit: challenge.amount,
                },
              ]
            : [
                {
                  accountCode: `liability:agent_float:${body.agentId}`,
                  accountType: 'liability',
                  currency: walletCur,
                  decimals: fxQuote.sourceDecimals,
                  debit: fxQuote.sourceAmount,
                  credit: 0,
                },
                {
                  accountCode: 'asset:fx_bridge',
                  accountType: 'asset',
                  currency: walletCur,
                  decimals: fxQuote.sourceDecimals,
                  debit: 0,
                  credit: fxQuote.sourceAmount,
                },
                {
                  accountCode: 'asset:fx_bridge',
                  accountType: 'asset',
                  currency: targetCur,
                  decimals: challenge.decimals,
                  debit: challenge.amount,
                  credit: 0,
                },
                {
                  accountCode: `liability:peer_payable:${remotePeer.peerId}`,
                  accountType: 'liability',
                  currency: targetCur,
                  decimals: challenge.decimals,
                  debit: 0,
                  credit: challenge.amount,
                },
              ];

        const id = this.ledger.postJournal({
          idempotencyKey: `fed_out:${challenge.challengeId}`,
          txKind: 'FEDERATION_OUTBOUND_CLEAR',
          description: `Outbound federated clear to ${remotePeer.peerId} (${targetFacUrl})`,
          inExistingTransaction: true,
          postings,
        });
        if (verifiedMandateId) {
          this.ledger.recordMandateSpend(
            verifiedMandateId,
            body.agentId,
            debitInMandateCur,
            mandateCurrency,
            now,
          );
        }
        return id;
      });

      const voucherClaims = {
        voucherId: randomId('vfv', 10),
        peerIssuer: selfUrl,
        targetIssuer: targetFacUrl,
        agentId: body.agentId,
        challenge,
        rail: body.rail,
        issuedAt: now,
        expiresAt: now + 60,
      };
      const vPayload = base64UrlEncode(JSON.stringify(voucherClaims));
      const vSig = base64UrlEncode(ed25519Sign(this.keyPair.privateSeedBytes, `vfv1.${vPayload}`));
      const vfvToken = `vfv1.${vPayload}.${vSig}`;

      const peerRes = await fetch(`${targetFacUrl}/v1/federation/settle-inbound`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ voucherToken: vfvToken }),
      });
      if (!peerRes.ok) {
        throw new Error(`ERR_FEDERATION_PEER_REJECTED (${peerRes.status}): ${await peerRes.text()}`);
      }
      const settledRemote = (await peerRes.json()) as { vrt: string; receiptId: string };
      const clearingMs = Number((performance.now() - t0).toFixed(3));
      const res = {
        status: 'CLEARED' as const,
        vrt: settledRemote.vrt,
        receiptId: settledRemote.receiptId,
        txId: outTxId,
        mode: 'instant' as const,
        debitedAmount: fxQuote.sourceAmount,
        debitedCurrency: walletCur,
        settledAmount: challenge.amount,
        settledCurrency: targetCur,
        clearingMs,
      };
      this.ledger.setTransactionResult(outTxId, res);
      return res;
    }

    // 6. Execute Atomic Double-Entry Debit (Instant or Escrow) + Mint Signed VRT
    return this.executeAtomicSettlement({
      challengeId: challenge.challengeId,
      service: challenge.service,
      resource: challenge.resource,
      reqHash: challenge.reqHash,
      agentId: body.agentId,
      rail: body.rail,
      settlementMode: challenge.settlementMode,
      targetAmount: challenge.amount,
      targetCurrency: targetCur,
      targetDecimals: challenge.decimals,
      sourceAmount: fxQuote.sourceAmount,
      sourceCurrency: walletCur,
      sourceDecimals: fxQuote.sourceDecimals,
      mandateId: verifiedMandateId,
      mandateAmount: debitInMandateCur,
      mandateCurrency,
      t0,
    });
  }

  private executeAtomicSettlement(params: {
    challengeId: string;
    service: string;
    resource: string;
    reqHash: string;
    agentId: string;
    rail: string;
    settlementMode: 'instant' | 'escrow';
    targetAmount: number;
    targetCurrency: string;
    targetDecimals: number;
    sourceAmount: number;
    sourceCurrency: string;
    sourceDecimals: number;
    mandateId: string | null;
    mandateAmount: number;
    mandateCurrency: string;
    t0: number;
  }) {
    const now = Math.floor(Date.now() / 1000);
    return this.ledger.runSerializable(() => {
      const escrowId = params.settlementMode === 'escrow' ? randomId('esc', 10) : undefined;
      const feeAmount =
        params.settlementMode === 'instant'
          ? Math.floor((params.targetAmount * this.feeBps) / 10_000)
          : 0;
      const merchantNet = params.targetAmount - feeAmount;

      const postings: JournalPostingInput[] = [];

      if (params.sourceCurrency === params.targetCurrency) {
        postings.push({
          accountCode: `liability:agent_float:${params.agentId}`,
          accountType: 'liability',
          currency: params.sourceCurrency,
          decimals: params.sourceDecimals,
          debit: params.sourceAmount,
          credit: 0,
        });
      } else {
        // Cross-currency atomic FX bridge legs
        postings.push(
          {
            accountCode: `liability:agent_float:${params.agentId}`,
            accountType: 'liability',
            currency: params.sourceCurrency,
            decimals: params.sourceDecimals,
            debit: params.sourceAmount,
            credit: 0,
          },
          {
            accountCode: 'asset:fx_bridge',
            accountType: 'asset',
            currency: params.sourceCurrency,
            decimals: params.sourceDecimals,
            debit: 0,
            credit: params.sourceAmount,
          },
          {
            accountCode: 'asset:fx_bridge',
            accountType: 'asset',
            currency: params.targetCurrency,
            decimals: params.targetDecimals,
            debit: params.targetAmount,
            credit: 0,
          },
        );
      }

      if (params.settlementMode === 'escrow' && escrowId) {
        postings.push({
          accountCode: `liability:escrow:${escrowId}`,
          accountType: 'liability',
          currency: params.targetCurrency,
          decimals: params.targetDecimals,
          debit: 0,
          credit: params.targetAmount,
        });
      } else {
        postings.push({
          accountCode: `liability:merchant_payable:${params.service}`,
          accountType: 'liability',
          currency: params.targetCurrency,
          decimals: params.targetDecimals,
          debit: 0,
          credit: merchantNet,
        });
        if (feeAmount > 0) {
          postings.push({
            accountCode: 'revenue:facilitator_fee',
            accountType: 'revenue',
            currency: params.targetCurrency,
            decimals: params.targetDecimals,
            debit: 0,
            credit: feeAmount,
          });
        }
      }

      const txId = this.ledger.postJournal({
        idempotencyKey: `clear:${params.challengeId}`,
        txKind: params.settlementMode === 'escrow' ? 'ESCROW_LOCK' : 'INSTANT_CLEAR',
        description: `Clear ${params.service} ${params.resource} (${params.targetAmount} ${params.targetCurrency})`,
        inExistingTransaction: true,
        postings,
      });

      if (params.mandateId) {
        this.ledger.recordMandateSpend(
          params.mandateId,
          params.agentId,
          params.mandateAmount,
          params.mandateCurrency,
          now,
        );
      }

      if (params.settlementMode === 'escrow' && escrowId) {
        this.ledger.db
          .prepare(
            `INSERT INTO escrows (escrow_id, challenge_id, agent_id, service, amount, currency, decimals, rail, status, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'AUTHORIZED', ?, ?)`,
          )
          .run(
            escrowId,
            params.challengeId,
            params.agentId,
            params.service,
            params.targetAmount,
            params.targetCurrency,
            params.targetDecimals,
            params.rail,
            now,
            now,
          );
      }

      const { token, claims } = signVrt(
        {
          iss: this.issuerUrl,
          sub: params.agentId,
          aud: params.service,
          chg: params.challengeId,
          req: params.reqHash,
          amt: params.targetAmount,
          cur: params.targetCurrency,
          dec: params.targetDecimals,
          rail: params.rail,
          mode: params.settlementMode,
          ...(escrowId ? { esc: escrowId } : {}),
          iat: now,
          ttlSeconds: 120,
        },
        this.keyPair,
      );

      const clearingMs = Number((performance.now() - params.t0).toFixed(3));
      const res = {
        status: 'CLEARED' as const,
        vrt: token,
        receiptId: claims.jti,
        txId,
        mode: params.settlementMode,
        ...(escrowId ? { escrowId } : {}),
        debitedAmount: params.sourceAmount,
        debitedCurrency: params.sourceCurrency,
        settledAmount: params.targetAmount,
        settledCurrency: params.targetCurrency,
        clearingMs,
      };

      this.ledger.setTransactionResult(txId, res);
      this.ledger.recordTelemetry({
        eventType: 'CHALLENGE_CLEARED',
        service: params.service,
        route: params.resource,
        agentId: params.agentId,
        rail: params.rail,
        amount: params.targetAmount,
        currency: params.targetCurrency,
        latencyMs: clearingMs,
      });

      this.emitWebhook(this.merchantWebhookUrl, 'payment.cleared', res);

      return res;
    });
  }

  decideHitl(approvalId: string, decision: 'approve' | 'reject') {
    const t0 = performance.now();
    const row = this.ledger.db
      .prepare(
        `SELECT
           approval_id AS approvalId, challenge_id AS challengeId, agent_id AS agentId,
           service, resource, method, req_hash AS reqHash, amount, currency, decimals,
           settlement_mode AS settlementMode, rail, wallet_currency AS walletCurrency,
           mandate_id AS mandateId, status, vrt_token AS vrtToken, reason,
           created_at AS createdAt, expires_at AS expiresAt, decided_at AS decidedAt
         FROM hitl_approvals WHERE approval_id = ?`,
      )
      .get(approvalId) as HitlRecord | undefined;

    if (!row) throw new Error(`Unknown HITL approvalId: ${approvalId}`);
    if (row.status !== 'PENDING_HITL') {
      return { approvalId, status: row.status, vrt: row.vrtToken };
    }

    const now = Math.floor(Date.now() / 1000);
    if (decision === 'reject') {
      this.ledger.db
        .prepare("UPDATE hitl_approvals SET status = 'REJECTED', decided_at = ? WHERE approval_id = ?")
        .run(now, approvalId);
      return { approvalId, status: 'REJECTED' as const, vrt: null };
    }

    const fxQuote = this.adapters.fx.quoteTargetAmount(row.amount, row.currency, row.walletCurrency, now);
    const cleared = this.executeAtomicSettlement({
      challengeId: row.challengeId,
      service: row.service,
      resource: row.resource,
      reqHash: row.reqHash,
      agentId: row.agentId,
      rail: row.rail,
      settlementMode: row.settlementMode,
      targetAmount: row.amount,
      targetCurrency: row.currency,
      targetDecimals: row.decimals,
      sourceAmount: fxQuote.sourceAmount,
      sourceCurrency: row.walletCurrency,
      sourceDecimals: fxQuote.sourceDecimals,
      mandateId: row.mandateId,
      mandateAmount: row.amount,
      mandateCurrency: row.currency,
      t0,
    });

    this.ledger.db
      .prepare(
        "UPDATE hitl_approvals SET status = 'APPROVED', vrt_token = ?, decided_at = ? WHERE approval_id = ?",
      )
      .run(cleared.vrt, now, approvalId);

    return {
      approvalId,
      status: 'APPROVED' as const,
      vrt: cleared.vrt,
      escrowId: cleared.escrowId,
      txId: cleared.txId,
    };
  }

  fulfillEscrow(escrowId: string, fulfillmentRef: string) {
    return this.ledger.runSerializable(() => {
      const esc = this.ledger.db
        .prepare(
          `SELECT escrow_id AS escrowId, challenge_id AS challengeId, agent_id AS agentId,
                  service, amount, currency, decimals, rail, status, fulfillment_ref AS fulfillmentRef,
                  created_at AS createdAt, updated_at AS updatedAt
           FROM escrows WHERE escrow_id = ?`,
        )
        .get(escrowId) as EscrowRecord | undefined;

      if (!esc) throw new Error(`Escrow not found: ${escrowId}`);
      if (esc.status === 'SETTLED') return esc;
      if (esc.status !== 'AUTHORIZED') throw new Error(`Cannot fulfill escrow in state ${esc.status}`);

      const fee = Math.floor((esc.amount * this.feeBps) / 10_000);
      const net = esc.amount - fee;
      const postings: JournalPostingInput[] = [
        {
          accountCode: `liability:escrow:${esc.escrowId}`,
          accountType: 'liability',
          currency: esc.currency,
          decimals: esc.decimals,
          debit: esc.amount,
          credit: 0,
        },
        {
          accountCode: `liability:merchant_payable:${esc.service}`,
          accountType: 'liability',
          currency: esc.currency,
          decimals: esc.decimals,
          debit: 0,
          credit: net,
        },
      ];
      if (fee > 0) {
        postings.push({
          accountCode: 'revenue:facilitator_fee',
          accountType: 'revenue',
          currency: esc.currency,
          decimals: esc.decimals,
          debit: 0,
          credit: fee,
        });
      }

      this.ledger.postJournal({
        idempotencyKey: `escrow_fulfill:${esc.escrowId}`,
        txKind: 'ESCROW_SETTLE',
        description: `Fulfill escrow ${esc.escrowId} (ref: ${fulfillmentRef})`,
        inExistingTransaction: true,
        postings,
      });

      const now = Math.floor(Date.now() / 1000);
      this.ledger.db
        .prepare("UPDATE escrows SET status = 'SETTLED', fulfillment_ref = ?, updated_at = ? WHERE escrow_id = ?")
        .run(fulfillmentRef, now, esc.escrowId);

      return { ...esc, status: 'SETTLED' as const, fulfillmentRef, updatedAt: now };
    });
  }

  refundEscrow(escrowId: string, reason = 'cancelled') {
    return this.ledger.runSerializable(() => {
      const esc = this.ledger.db
        .prepare(
          `SELECT escrow_id AS escrowId, challenge_id AS challengeId, agent_id AS agentId,
                  service, amount, currency, decimals, rail, status, fulfillment_ref AS fulfillmentRef,
                  created_at AS createdAt, updated_at AS updatedAt
           FROM escrows WHERE escrow_id = ?`,
        )
        .get(escrowId) as EscrowRecord | undefined;

      if (!esc) throw new Error(`Escrow not found: ${escrowId}`);
      if (esc.status === 'REFUNDED') return esc;
      if (esc.status !== 'AUTHORIZED') throw new Error(`Cannot refund escrow in state ${esc.status}`);

      this.ledger.postJournal({
        idempotencyKey: `escrow_refund:${esc.escrowId}`,
        txKind: 'ESCROW_REFUND',
        description: `Refund escrow ${esc.escrowId} (${reason})`,
        inExistingTransaction: true,
        postings: [
          {
            accountCode: `liability:escrow:${esc.escrowId}`,
            accountType: 'liability',
            currency: esc.currency,
            decimals: esc.decimals,
            debit: esc.amount,
            credit: 0,
          },
          {
            accountCode: `liability:agent_float:${esc.agentId}`,
            accountType: 'liability',
            currency: esc.currency,
            decimals: esc.decimals,
            debit: 0,
            credit: esc.amount,
          },
        ],
      });

      const now = Math.floor(Date.now() / 1000);
      this.ledger.db
        .prepare("UPDATE escrows SET status = 'REFUNDED', updated_at = ? WHERE escrow_id = ?")
        .run(now, esc.escrowId);

      return { ...esc, status: 'REFUNDED' as const, updatedAt: now };
    });
  }

  async payoutMerchant(input: {
    service: string;
    destinationAccount: string;
    rail: string;
    currency: string;
    amount?: number;
  }) {
    const cur = input.currency.toUpperCase();
    const dec = getCurrencyDecimals(cur);
    const payableAccount = `liability:merchant_payable:${input.service}`;
    const available = this.ledger.getAccountBalance(payableAccount, cur);
    const amount = input.amount ?? available;
    if (amount <= 0 || amount > available) {
      throw new Error(`Insufficient merchant payable balance: requested=${amount}, available=${available} ${cur}`);
    }

    const batchId = randomId('batch', 8);
    const adapter = this.adapters.get(input.rail);
    const disb = await adapter.payout({
      merchantService: input.service,
      destinationAccount: input.destinationAccount,
      amount,
      currency: cur,
      decimals: dec,
      batchId,
    });

    const txId = this.ledger.postJournal({
      idempotencyKey: `payout:${batchId}`,
      txKind: 'MERCHANT_PAYOUT',
      description: `Merchant payout to ${input.service} (${input.destinationAccount}) via ${input.rail}`,
      postings: [
        {
          accountCode: payableAccount,
          accountType: 'liability',
          currency: cur,
          decimals: dec,
          debit: amount,
          credit: 0,
        },
        {
          accountCode: `asset:rail_clearing:${input.rail}:${cur}`,
          accountType: 'asset',
          currency: cur,
          decimals: dec,
          debit: 0,
          credit: amount,
        },
      ],
    });

    return {
      txId,
      payoutId: disb.payoutId,
      providerDisbursementRef: disb.providerDisbursementRef,
      service: input.service,
      amount,
      currency: cur,
      remainingPayable: this.ledger.getAccountBalance(payableAccount, cur),
    };
  }

  getTelemetrySummary() {
    const integrity = this.ledger.verifyIntegrity();
    const hitlPending = (
      this.ledger.db
        .prepare("SELECT COUNT(*) AS cnt FROM hitl_approvals WHERE status = 'PENDING_HITL'")
        .get() as { cnt: number }
    ).cnt;
    const hitlList = this.ledger.db
      .prepare(
        `SELECT approval_id AS approvalId, challenge_id AS challengeId, agent_id AS agentId,
                service, resource, method, amount, currency, decimals, settlement_mode AS settlementMode,
                rail, status, reason, created_at AS createdAt, expires_at AS expiresAt
         FROM hitl_approvals ORDER BY created_at DESC LIMIT 25`,
      )
      .all();
    const escrowsList = this.ledger.db
      .prepare(
        `SELECT escrow_id AS escrowId, service, agent_id AS agentId, amount, currency, rail, status, fulfillment_ref AS fulfillmentRef, created_at AS createdAt
         FROM escrows ORDER BY created_at DESC LIMIT 25`,
      )
      .all();
    const merchantBalances = this.ledger.db
      .prepare(
        "SELECT account_code AS accountCode, currency, decimals, (credit_total - debit_total) AS balance FROM accounts WHERE account_code LIKE 'liability:merchant_payable:%'",
      )
      .all();
    const eventStats = this.ledger.db
      .prepare(
        `SELECT event_type AS eventType, COUNT(*) AS count, ROUND(AVG(latency_ms), 3) AS avgLatencyMs
         FROM telemetry_events GROUP BY event_type`,
      )
      .all();

    return {
      facilitatorDid: this.keyPair.did,
      facilitatorKid: this.keyPair.kid,
      facilitatorPublicKey: this.keyPair.publicKeyBase64Url,
      feeBps: this.feeBps,
      supportedRails: this.adapters.list().map((a) => ({
        railId: a.railId,
        displayName: a.displayName,
        region: a.region,
        currencies: a.supportedCurrencies,
      })),
      fxCurrencies: this.adapters.fx.listSupportedCurrencies(),
      ledgerIntegrity: integrity,
      hitlPendingCount: hitlPending,
      hitlApprovals: hitlList,
      escrows: escrowsList,
      merchantPayables: merchantBalances,
      eventStats,
      recentEntries: this.ledger.listJournalEntries(30),
    };
  }

  createHttpServer(): http.Server {
    const readJson = async <T>(req: http.IncomingMessage): Promise<T> => {
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buf.length;
        if (size > 1_048_576) throw new Error('Payload too large');
        chunks.push(buf);
      }
      return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as T;
    };

    const sendJson = (res: http.ServerResponse, status: number, body: unknown) => {
      res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      });
      res.end(JSON.stringify(body));
    };

    const checkAdmin = (req: http.IncomingMessage): boolean => {
      if (!this.adminKey) return true;
      return req.headers.authorization === `Bearer ${this.adminKey}`;
    };

    return http.createServer(async (req, res) => {
      try {
        if (req.method === 'OPTIONS') {
          res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          });
          res.end();
          return;
        }

        const url = new URL(req.url ?? '/', 'http://localhost');
        const pathname = url.pathname;

        if (req.method === 'GET' && pathname === '/') {
          const summary = this.getTelemetrySummary();
          const endpoints = [
            { method: 'GET', path: '/health', description: 'Node health & active Ed25519 public key' },
            { method: 'GET', path: '/.well-known/jwks.json', description: 'Public Ed25519 JWKS for Gate offline VRT verification' },
            { method: 'GET', path: '/v1/fx/rates', description: 'Global multi-currency reference FX rates (23 currencies)' },
            { method: 'GET', path: '/v1/fx/quote?targetAmount=5000&targetCurrency=USD&sourceCurrency=EUR', description: 'Lossless integer FX quote calculator' },
            { method: 'POST', path: '/v1/wallets/topup', description: 'Credit agent prepaid float via any global rail' },
            { method: 'GET', path: '/v1/wallets/:agentDid', description: 'Inspect multi-currency agent wallet balances' },
            { method: 'POST', path: '/v1/clear', description: 'Sub-5ms atomic float debit / escrow lock & VRT issuance' },
            { method: 'GET', path: '/v1/hitl', description: 'List Human-in-the-Loop guardrail approvals' },
            { method: 'GET', path: '/v1/telemetry/summary', description: 'Real-time clearing metrics, escrows & payables' },
            { method: 'GET', path: '/v1/ledger/export?format=json', description: 'Export double-entry journal ledger (JSON or CSV)' },
          ];

          if ((req.headers.accept ?? '').includes('text/html')) {
            const railsHtml = summary.supportedRails
              .map(
                (r) =>
                  `<tr><td><strong>${r.railId}</strong></td><td>${r.region}</td><td>${r.displayName}</td><td>${r.currencies.join(', ')}</td></tr>`,
              )
              .join('');
            const epHtml = endpoints
              .map(
                (e) =>
                  `<tr><td><span class="m">${e.method}</span></td><td>${
                    e.method === 'GET' && !e.path.includes(':')
                      ? `<a href="${e.path}">${e.path}</a>`
                      : `<code>${e.path}</code>`
                  }</td><td>${e.description}</td></tr>`,
              )
              .join('');
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><title>Vectoll Facilitator — Global Clearing Engine</title>
<style>
  body{margin:0;background:#090d16;color:#f3f4f6;font-family:Inter,system-ui,sans-serif;padding:28px;}
  .wrap{max-width:1180px;margin:0 auto;display:grid;gap:20px;}
  .card{background:#111827;border:1px solid #1f2937;border-radius:8px;padding:20px;}
  h1{margin:0;font-size:20px;display:flex;align-items:center;gap:12px;}
  h2{margin:0 0 12px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#9ca3af;}
  .ok{font-size:12px;font-family:monospace;padding:4px 10px;border-radius:4px;background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.35);}
  table{width:100%;border-collapse:collapse;font-family:ui-monospace,monospace;font-size:12.5px;}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1f2937;}
  th{color:#9ca3af;font-size:11px;text-transform:uppercase;}
  a{color:#38bdf8;text-decoration:none;} a:hover{text-decoration:underline;}
  .m{padding:2px 6px;border-radius:3px;background:#1f2937;color:#10b981;font-weight:700;}
  .meta{font-family:ui-monospace,monospace;font-size:12px;color:#9ca3af;margin-top:8px;}
</style></head><body><div class="wrap">
  <div class="card">
    <h1>VECTOLL FACILITATOR <span class="ok">ONLINE · LEDGER ${summary.ledgerIntegrity.balanced ? 'BALANCED' : 'CHECK'}</span></h1>
    <div class="meta">DID: ${summary.facilitatorDid} · KID: ${summary.facilitatorKid} · Fee: ${summary.feeBps} bps · Currencies: ${summary.fxCurrencies.length} Global Assets</div>
  </div>
  <div class="card"><h2>Global Multi-Rail Settlement Adapters (${summary.supportedRails.length})</h2>
    <table><thead><tr><th>Rail ID</th><th>Region</th><th>Network</th><th>Supported Currencies</th></tr></thead><tbody>${railsHtml}</tbody></table>
  </div>
  <div class="card"><h2>Facilitator HTTP API Explorer</h2>
    <table><thead><tr><th>Method</th><th>Endpoint</th><th>Description</th></tr></thead><tbody>${epHtml}</tbody></table>
  </div>
</div></body></html>`);
            return;
          }

          sendJson(res, 200, {
            service: 'vectoll-facilitator',
            version: '0.1.0',
            status: 'online',
            facilitatorDid: this.keyPair.did,
            facilitatorKid: this.keyPair.kid,
            ledgerBalanced: summary.ledgerIntegrity.balanced,
            supportedRailsCount: summary.supportedRails.length,
            supportedCurrenciesCount: summary.fxCurrencies.length,
            endpoints,
          });
          return;
        }

        if (req.method === 'GET' && pathname === '/v1/fx/rates') {
          sendJson(res, 200, {
            base: 'USD',
            currencies: this.adapters.fx.listSupportedCurrencies(),
          });
          return;
        }

        if (req.method === 'GET' && pathname === '/v1/fx/quote') {
          const targetAmount = Number(url.searchParams.get('targetAmount') ?? 5000);
          const targetCurrency = url.searchParams.get('targetCurrency') ?? 'USD';
          const sourceCurrency = url.searchParams.get('sourceCurrency') ?? 'EUR';
          sendJson(
            res,
            200,
            this.adapters.fx.quoteTargetAmount(targetAmount, targetCurrency, sourceCurrency),
          );
          return;
        }

        if (req.method === 'GET' && pathname === '/health') {
          sendJson(res, 200, {
            status: 'ok',
            service: 'vectoll-facilitator',
            version: '1.0.0',
            kid: this.keyPair.kid,
            publicKey: this.keyPair.publicKeyBase64Url,
          });
          return;
        }

        if (req.method === 'GET' && pathname === '/metrics') {
          const summary = this.getTelemetrySummary();
          const lines: string[] = [
            '# HELP vectoll_facilitator_ledger_balanced 1 if double-entry debits equal credits across all currencies',
            '# TYPE vectoll_facilitator_ledger_balanced gauge',
            `vectoll_facilitator_ledger_balanced ${summary.ledgerIntegrity.balanced ? 1 : 0}`,
            '# HELP vectoll_facilitator_hitl_pending_total Pending Human-in-the-Loop approvals',
            '# TYPE vectoll_facilitator_hitl_pending_total gauge',
            `vectoll_facilitator_hitl_pending_total ${summary.hitlPendingCount}`,
            '# HELP vectoll_facilitator_supported_rails_total Number of registered payment rail adapters',
            '# TYPE vectoll_facilitator_supported_rails_total gauge',
            `vectoll_facilitator_supported_rails_total ${summary.supportedRails.length}`,
            '# HELP vectoll_facilitator_fx_currencies_total Number of supported FX currencies',
            '# TYPE vectoll_facilitator_fx_currencies_total gauge',
            `vectoll_facilitator_fx_currencies_total ${summary.fxCurrencies.length}`,
          ];
          for (const st of summary.eventStats as Array<{ eventType: string; count: number; avgLatencyMs: number }>) {
            lines.push(
              `vectoll_facilitator_events_total{type="${st.eventType}"} ${st.count}`,
              `vectoll_facilitator_latency_ms_avg{type="${st.eventType}"} ${st.avgLatencyMs ?? 0}`,
            );
          }
          res.writeHead(200, {
            'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
          });
          res.end(lines.join('\n') + '\n');
          return;
        }

        if (req.method === 'GET' && pathname === '/.well-known/jwks.json') {
          sendJson(res, 200, this.getJwks());
          return;
        }

        if (req.method === 'POST' && pathname === '/v1/wallets/topup') {
          const body = await readJson<{
            agentId: string;
            amount: number;
            currency: string;
            decimals?: number;
            rail: string;
            idempotencyKey?: string;
            metadata?: Record<string, string>;
          }>(req);
          const out = await this.topUpWallet(body);
          sendJson(res, 200, out);
          return;
        }

        if (req.method === 'GET' && pathname.startsWith('/v1/wallets/')) {
          const agentId = decodeURIComponent(pathname.slice('/v1/wallets/'.length));
          sendJson(res, 200, {
            agentId,
            balances: this.ledger.getWalletBalances(agentId),
          });
          return;
        }

        if (req.method === 'POST' && pathname === '/v1/clear') {
          const body = await readJson<ClearRequestBody>(req);
          const out = await this.clearChallenge(body);
          sendJson(res, out.status === 'PENDING_HITL' ? 202 : 200, out);
          return;
        }

        if (req.method === 'POST' && pathname === '/v1/mandates/revoke') {
          const body = await readJson<{
            mandateId: string;
            principalId: string;
            reason?: string;
            timestamp?: number;
            principalSignature?: string;
          }>(req);
          sendJson(res, 200, this.revokeSpendMandate(body));
          return;
        }

        if (req.method === 'GET' && pathname === '/v1/mandates/revoked') {
          sendJson(res, 200, { revokedMandates: this.ledger.listRevokedMandates() });
          return;
        }

        if (req.method === 'GET' && pathname === '/v1/hitl') {
          sendJson(res, 200, { approvals: this.getTelemetrySummary().hitlApprovals });
          return;
        }

        const hitlDecideMatch = pathname.match(/^\/v1\/hitl\/([^/]+)\/decide$/);
        if (req.method === 'POST' && hitlDecideMatch) {
          const hitlRow = this.ledger.db
            .prepare('SELECT service FROM hitl_approvals WHERE approval_id = ?')
            .get(hitlDecideMatch[1]!) as { service: string } | undefined;
          if (!hitlRow) {
            sendJson(res, 404, { error: 'HITL record not found' });
            return;
          }
          const authz = this.authorizeServiceAction(hitlRow.service, 'hitl:decide', req.headers.authorization);
          if (!authz.authorized) {
            sendJson(res, authz.status ?? 401, { error: authz.reason });
            return;
          }
          const body = await readJson<{ decision: 'approve' | 'reject' }>(req);
          const out = this.decideHitl(hitlDecideMatch[1]!, body.decision);
          sendJson(res, 200, out);
          return;
        }

        const hitlPollMatch = pathname.match(/^\/v1\/hitl\/([^/]+)$/);
        if (req.method === 'GET' && hitlPollMatch) {
          const row = this.ledger.db
            .prepare(
              'SELECT approval_id AS approvalId, status, vrt_token AS vrt, reason, expires_at AS expiresAt FROM hitl_approvals WHERE approval_id = ?',
            )
            .get(hitlPollMatch[1]!);
          if (!row) {
            sendJson(res, 404, { error: 'HITL record not found' });
            return;
          }
          sendJson(res, 200, row);
          return;
        }

        const escFulfillMatch = pathname.match(/^\/v1\/escrow\/([^/]+)\/fulfill$/);
        if (req.method === 'POST' && escFulfillMatch) {
          const body = await readJson<{ fulfillmentRef: string }>(req);
          const out = this.fulfillEscrow(escFulfillMatch[1]!, body.fulfillmentRef ?? 'confirmed');
          sendJson(res, 200, out);
          return;
        }

        const escRefundMatch = pathname.match(/^\/v1\/escrow\/([^/]+)\/refund$/);
        if (req.method === 'POST' && escRefundMatch) {
          const body = await readJson<{ reason?: string }>(req);
          const out = this.refundEscrow(escRefundMatch[1]!, body.reason);
          sendJson(res, 200, out);
          return;
        }

        if (req.method === 'POST' && pathname === '/v1/payouts') {
          const body = await readJson<{
            service: string;
            destinationAccount: string;
            rail: string;
            currency: string;
            amount?: number;
          }>(req);
          const authz = this.authorizeServiceAction(body.service, 'payouts:write', req.headers.authorization);
          if (!authz.authorized) {
            sendJson(res, authz.status ?? 401, { error: authz.reason });
            return;
          }
          const out = await this.payoutMerchant(body);
          sendJson(res, 200, out);
          return;
        }

        if (req.method === 'POST' && pathname === '/v1/merchants/register') {
          const body = await readJson<{
            orgName: string;
            serviceName: string;
            webhookUrl?: string;
            payoutAccount?: string;
            scopes?: string[];
          }>(req);
          sendJson(res, 201, this.registerMerchant(body));
          return;
        }

        const mchKeysMatch = pathname.match(/^\/v1\/merchants\/([^/]+)\/keys$/);
        if (req.method === 'POST' && mchKeysMatch) {
          if (!checkAdmin(req)) {
            sendJson(res, 401, { error: 'Unauthorized' });
            return;
          }
          const body = await readJson<{ scopes?: string[] }>(req);
          sendJson(res, 201, this.issueMerchantApiKey(mchKeysMatch[1]!, body.scopes ?? ['ledger:read']));
          return;
        }

        if (req.method === 'POST' && pathname === '/v1/federation/peers') {
          if (!checkAdmin(req)) {
            sendJson(res, 401, { error: 'Unauthorized' });
            return;
          }
          const body = await readJson<{
            peerId: string;
            issuerUrl: string;
            kid: string;
            publicKeyBase64Url: string;
            creditLimitUsdMicro?: number;
          }>(req);
          sendJson(res, 201, this.registerPeerFacilitator(body));
          return;
        }

        if (req.method === 'POST' && pathname === '/v1/federation/settle-inbound') {
          const body = await readJson<{ voucherToken: string }>(req);
          sendJson(res, 200, this.settleInboundFederationVoucher(body.voucherToken));
          return;
        }

        if (req.method === 'GET' && pathname === '/v1/federation/positions') {
          sendJson(res, 200, this.getFederationPositions());
          return;
        }

        if (req.method === 'POST' && pathname === '/v1/discovery/index') {
          const body = await readJson<{ url: string }>(req);
          const indexed = await this.indexDomainManifest(body.url);
          sendJson(res, 200, indexed);
          return;
        }

        if (req.method === 'GET' && pathname === '/v1/discovery/search') {
          const q = url.searchParams.get('q') ?? undefined;
          const rail = url.searchParams.get('rail') ?? undefined;
          const maxRaw = url.searchParams.get('maxPriceUsdMicro');
          const maxPriceUsdMicro = maxRaw !== null ? Number(maxRaw) : undefined;
          const results = this.searchDiscoveryIndex({ q, rail, maxPriceUsdMicro });
          sendJson(res, 200, { count: results.length, results });
          return;
        }

        if (req.method === 'GET' && pathname === '/v1/ledger/entries') {
          const limit = Number(url.searchParams.get('limit') ?? 100);
          sendJson(res, 200, {
            integrity: this.ledger.verifyIntegrity(),
            entries: this.ledger.listJournalEntries(limit),
          });
          return;
        }

        if (req.method === 'GET' && pathname === '/v1/ledger/export') {
          const fmt = url.searchParams.get('format') ?? 'csv';
          if (fmt === 'json') {
            sendJson(res, 200, {
              integrity: this.ledger.verifyIntegrity(),
              entries: this.ledger.listJournalEntries(1000),
            });
            return;
          }
          const csv = this.ledger.exportCsv(1000);
          res.writeHead(200, {
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition': 'attachment; filename="vectoll-ledger.csv"',
            'Access-Control-Allow-Origin': '*',
          });
          res.end(csv);
          return;
        }

        if (req.method === 'GET' && pathname === '/v1/telemetry/summary') {
          sendJson(res, 200, this.getTelemetrySummary());
          return;
        }

        sendJson(res, 404, { error: `Unknown endpoint ${req.method} ${pathname}` });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const status = msg.startsWith('ERR_INSUFFICIENT_FUNDS')
          ? 402
          : msg.startsWith('ERR_')
            ? 400
            : 500;
        sendJson(res, status, { error: msg });
      }
    });
  }
}
