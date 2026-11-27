import crypto from 'node:crypto';
import {
  base64UrlDecode,
  base64UrlEncode,
  ed25519Sign,
  ed25519Verify,
  randomId,
} from './crypto.js';
import { verifyPasskeyAssertion } from './passkey.js';
import {
  assertSafeMinorAmount,
  type CreditVoucherClaims,
  type PaymentChallenge,
  type PaymentResponseHeader,
  type SettlementMode,
  type SpendMandateClaims,
  type VectollKeyPair,
  type VrtClaims,
} from './types.js';

// ─── Vectoll Receipt Token (vrt1) ──────────────────────────────────────────

export function signVrt(
  claimsInput: Omit<VrtClaims, 'v' | 'jti' | 'kid' | 'iat' | 'exp'> & {
    jti?: string;
    iat?: number;
    exp?: number;
    ttlSeconds?: number;
  },
  facilitatorKey: VectollKeyPair,
): { token: string; claims: VrtClaims } {
  assertSafeMinorAmount(claimsInput.amt, 'vrt.amt');
  const now = claimsInput.iat ?? Math.floor(Date.now() / 1000);
  const ttl = claimsInput.ttlSeconds ?? 60;
  const claims: VrtClaims = {
    v: 1,
    jti: claimsInput.jti ?? randomId('vrt', 12),
    kid: facilitatorKey.kid,
    iss: claimsInput.iss,
    sub: claimsInput.sub,
    aud: claimsInput.aud,
    chg: claimsInput.chg,
    req: claimsInput.req,
    amt: claimsInput.amt,
    cur: claimsInput.cur.toUpperCase(),
    dec: claimsInput.dec,
    rail: claimsInput.rail,
    mode: claimsInput.mode,
    ...(claimsInput.esc ? { esc: claimsInput.esc } : {}),
    iat: now,
    exp: claimsInput.exp ?? now + ttl,
  };

  const payloadB64 = base64UrlEncode(JSON.stringify(claims));
  const signingInput = `vrt1.${payloadB64}`;
  const sigB64 = base64UrlEncode(ed25519Sign(facilitatorKey.privateSeedBytes, signingInput));
  return {
    token: `${signingInput}.${sigB64}`,
    claims,
  };
}

export interface VerifyVrtOptions {
  expectedAudience?: string;
  expectedReqHash?: string;
  minAmount?: number;
  expectedCurrency?: string;
  nowSeconds?: number;
  clockSkewSeconds?: number;
}

export type VerifyVrtResult =
  | { valid: true; claims: VrtClaims }
  | { valid: false; code: string; reason: string };

export function decodeVrtUnsafe(token: string): VrtClaims {
  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts[0] !== 'vrt1') {
    throw new Error('Malformed VRT token: expected vrt1.<payload>.<signature>');
  }
  const jsonStr = Buffer.from(base64UrlDecode(parts[1]!)).toString('utf8');
  return JSON.parse(jsonStr) as VrtClaims;
}

export function verifyVrt(
  token: string,
  facilitatorPublicKey: Uint8Array | string | Record<string, Uint8Array | string>,
  options: VerifyVrtOptions = {},
): VerifyVrtResult {
  const trimmed = token.trim().replace(/^Vectoll\s+/i, '');
  const parts = trimmed.split('.');
  if (parts.length !== 3 || parts[0] !== 'vrt1') {
    return { valid: false, code: 'ERR_MALFORMED_VRT', reason: 'Expected vrt1.<payload>.<signature>' };
  }

  const [, payloadB64, sigB64] = parts as [string, string, string];
  const signingInput = `vrt1.${payloadB64}`;

  // Resolve key: if key map by kid is supplied, peek kid safely or try matching key
  let resolvedKey: Uint8Array | string | undefined;
  if (
    typeof facilitatorPublicKey === 'object' &&
    !(facilitatorPublicKey instanceof Uint8Array)
  ) {
    try {
      const peek = JSON.parse(Buffer.from(base64UrlDecode(payloadB64)).toString('utf8')) as { kid?: string };
      if (peek.kid && facilitatorPublicKey[peek.kid]) {
        resolvedKey = facilitatorPublicKey[peek.kid];
      }
    } catch {
      return { valid: false, code: 'ERR_INVALID_PAYLOAD', reason: 'Unable to decode VRT payload' };
    }
    if (!resolvedKey) {
      return { valid: false, code: 'ERR_UNKNOWN_KID', reason: 'Unknown facilitator key ID (kid)' };
    }
  } else {
    resolvedKey = facilitatorPublicKey;
  }

  // Step 1: Verify Ed25519 signature BEFORE trusting claims
  if (!ed25519Verify(resolvedKey, signingInput, sigB64)) {
    return { valid: false, code: 'ERR_INVALID_RECEIPT_SIGNATURE', reason: 'Ed25519 signature verification failed' };
  }

  let claims: VrtClaims;
  try {
    claims = JSON.parse(Buffer.from(base64UrlDecode(payloadB64)).toString('utf8')) as VrtClaims;
  } catch {
    return { valid: false, code: 'ERR_INVALID_PAYLOAD', reason: 'Invalid JSON in VRT payload' };
  }

  if (claims.v !== 1 || !claims.jti || !claims.req || !claims.aud) {
    return { valid: false, code: 'ERR_INVALID_CLAIMS', reason: 'Missing required VRT v1 claims' };
  }

  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const skew = options.clockSkewSeconds ?? 5;
  if (now > claims.exp + skew) {
    return { valid: false, code: 'ERR_RECEIPT_EXPIRED', reason: `VRT expired at ${claims.exp} (now=${now})` };
  }

  if (options.expectedAudience && claims.aud !== options.expectedAudience) {
    return {
      valid: false,
      code: 'ERR_AUDIENCE_MISMATCH',
      reason: `Expected aud=${options.expectedAudience}, got ${claims.aud}`,
    };
  }

  if (options.expectedReqHash) {
    const a = Buffer.from(claims.req, 'utf8');
    const b = Buffer.from(options.expectedReqHash, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return {
        valid: false,
        code: 'ERR_REQUEST_HASH_MISMATCH',
        reason: 'Receipt request hash does not match incoming HTTP request',
      };
    }
  }

  if (options.expectedCurrency && claims.cur.toUpperCase() !== options.expectedCurrency.toUpperCase()) {
    return {
      valid: false,
      code: 'ERR_CURRENCY_MISMATCH',
      reason: `Expected currency ${options.expectedCurrency}, got ${claims.cur}`,
    };
  }

  if (typeof options.minAmount === 'number' && claims.amt < options.minAmount) {
    return {
      valid: false,
      code: 'ERR_INSUFFICIENT_RECEIPT_AMOUNT',
      reason: `Receipt amount ${claims.amt} is less than required ${options.minAmount}`,
    };
  }

  return { valid: true, claims };
}

// ─── Spend Mandates (vsm1) ─────────────────────────────────────────────────

export interface CreateSpendMandateInput {
  principalKeyPair: VectollKeyPair;
  agentId: string;
  mandateId?: string;
  currency: string;
  decimals: number;
  maxPerCall: number;
  maxDaily: number;
  allowedServices?: string[];
  allowedRails?: string[];
  hitlThreshold?: number | null;
  purpose?: string;
  issuedAt?: number;
  expiresAt?: number;
  ttlSeconds?: number;
}

export function createSpendMandate(input: CreateSpendMandateInput): {
  token: string;
  claims: SpendMandateClaims;
} {
  assertSafeMinorAmount(input.maxPerCall, 'maxPerCall');
  assertSafeMinorAmount(input.maxDaily, 'maxDaily');
  if (input.maxPerCall <= 0 || input.maxDaily < input.maxPerCall) {
    throw new Error('Spend mandate requires 0 < maxPerCall <= maxDaily');
  }
  const now = input.issuedAt ?? Math.floor(Date.now() / 1000);
  const claims: SpendMandateClaims = {
    v: 1,
    mandateId: input.mandateId ?? randomId('mnd', 10),
    principalId: input.principalKeyPair.did,
    agentId: input.agentId,
    currency: input.currency.toUpperCase(),
    decimals: input.decimals,
    maxPerCall: input.maxPerCall,
    maxDaily: input.maxDaily,
    allowedServices: input.allowedServices ?? ['*'],
    allowedRails: input.allowedRails ?? ['*'],
    hitlThreshold: input.hitlThreshold ?? null,
    ...(input.purpose ? { purpose: input.purpose } : {}),
    issuedAt: now,
    expiresAt: input.expiresAt ?? now + (input.ttlSeconds ?? 86400 * 30),
  };

  const payloadB64 = base64UrlEncode(JSON.stringify(claims));
  const signingInput = `vsm1.${payloadB64}`;
  const sigB64 = base64UrlEncode(ed25519Sign(input.principalKeyPair.privateSeedBytes, signingInput));
  return {
    token: `${signingInput}.${sigB64}`,
    claims,
  };
}

export interface VerifySpendMandateContext {
  expectedAgentId?: string;
  service?: string;
  rail?: string;
  debitAmountInMandateCurrency?: number;
  spentLast24hInMandateCurrency?: number;
  nowSeconds?: number;
}

export type VerifySpendMandateResult =
  | { valid: true; claims: SpendMandateClaims; requiresHitl: boolean }
  | { valid: false; code: string; reason: string };

export function verifySpendMandate(
  token: string,
  ctx: VerifySpendMandateContext = {},
): VerifySpendMandateResult {
  const parts = token.trim().split('.');
  if (parts.length !== 3 || (parts[0] !== 'vsm1' && parts[0] !== 'vsm1p')) {
    return { valid: false, code: 'ERR_MALFORMED_MANDATE', reason: 'Expected vsm1 or vsm1p mandate token' };
  }
  const [prefix, payloadB64, sigOrProofB64] = parts as [string, string, string];
  let claims: SpendMandateClaims;
  try {
    claims = JSON.parse(Buffer.from(base64UrlDecode(payloadB64)).toString('utf8')) as SpendMandateClaims;
  } catch {
    return { valid: false, code: 'ERR_MALFORMED_MANDATE', reason: 'Invalid JSON in mandate payload' };
  }

  if (prefix === 'vsm1p') {
    if (!claims.principalId?.startsWith('did:passkey:')) {
      return { valid: false, code: 'ERR_INVALID_PRINCIPAL_DID', reason: 'vsm1p principalId must be did:passkey' };
    }
    const pkCheck = verifyPasskeyAssertion(payloadB64, sigOrProofB64, claims.principalId);
    if (!pkCheck.valid) {
      return {
        valid: false,
        code: 'ERR_INVALID_MANDATE_SIGNATURE',
        reason: pkCheck.reason ?? 'Passkey signature verification failed',
      };
    }
  } else {
    if (!claims.principalId?.startsWith('did:key:z')) {
      return { valid: false, code: 'ERR_INVALID_PRINCIPAL_DID', reason: 'Mandate principalId must be did:key' };
    }
    const signingInput = `vsm1.${payloadB64}`;
    if (!ed25519Verify(claims.principalId, signingInput, sigOrProofB64)) {
      return {
        valid: false,
        code: 'ERR_INVALID_MANDATE_SIGNATURE',
        reason: 'Principal Ed25519 signature verification failed',
      };
    }
  }

  const now = ctx.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (now < claims.issuedAt - 10 || now > claims.expiresAt) {
    return { valid: false, code: 'ERR_MANDATE_EXPIRED', reason: 'Spend mandate is expired or not yet valid' };
  }

  if (ctx.expectedAgentId && claims.agentId !== ctx.expectedAgentId) {
    return {
      valid: false,
      code: 'ERR_MANDATE_AGENT_MISMATCH',
      reason: `Mandate delegated to ${claims.agentId}, not ${ctx.expectedAgentId}`,
    };
  }

  if (
    ctx.service &&
    !claims.allowedServices.includes('*') &&
    !claims.allowedServices.includes(ctx.service)
  ) {
    return {
      valid: false,
      code: 'ERR_MANDATE_SERVICE_FORBIDDEN',
      reason: `Service ${ctx.service} is not in mandate allowedServices`,
    };
  }

  if (ctx.rail && !claims.allowedRails.includes('*') && !claims.allowedRails.includes(ctx.rail)) {
    return {
      valid: false,
      code: 'ERR_MANDATE_RAIL_FORBIDDEN',
      reason: `Rail ${ctx.rail} is not in mandate allowedRails`,
    };
  }

  if (typeof ctx.debitAmountInMandateCurrency === 'number') {
    if (ctx.debitAmountInMandateCurrency > claims.maxPerCall) {
      return {
        valid: false,
        code: 'ERR_MANDATE_MAX_PER_CALL_EXCEEDED',
        reason: `Amount ${ctx.debitAmountInMandateCurrency} exceeds mandate maxPerCall ${claims.maxPerCall}`,
      };
    }
    const spent24h = ctx.spentLast24hInMandateCurrency ?? 0;
    if (spent24h + ctx.debitAmountInMandateCurrency > claims.maxDaily) {
      return {
        valid: false,
        code: 'ERR_MANDATE_DAILY_CAP_EXCEEDED',
        reason: `24h spend ${spent24h + ctx.debitAmountInMandateCurrency} exceeds maxDaily ${claims.maxDaily}`,
      };
    }
  }

  const requiresHitl =
    typeof claims.hitlThreshold === 'number' &&
    typeof ctx.debitAmountInMandateCurrency === 'number' &&
    ctx.debitAmountInMandateCurrency >= claims.hitlThreshold;

  return { valid: true, claims, requiresHitl };
}

// ─── Enterprise Credit Vouchers (vcv1) ─────────────────────────────────────

export function createCreditVoucher(input: {
  issuerKeyPair: VectollKeyPair;
  beneficiaryDid: string;
  service: string;
  amount: number;
  currency: string;
  decimals: number;
  voucherId?: string;
  issuedAt?: number;
  expiresAt?: number;
}): { token: string; claims: CreditVoucherClaims } {
  assertSafeMinorAmount(input.amount, 'voucher.amount');
  const now = input.issuedAt ?? Math.floor(Date.now() / 1000);
  const claims: CreditVoucherClaims = {
    v: 1,
    voucherId: input.voucherId ?? randomId('vcv', 10),
    issuerDid: input.issuerKeyPair.did,
    beneficiaryDid: input.beneficiaryDid,
    service: input.service,
    amount: input.amount,
    currency: input.currency.toUpperCase(),
    decimals: input.decimals,
    issuedAt: now,
    expiresAt: input.expiresAt ?? now + 86400 * 30,
  };
  const payloadB64 = base64UrlEncode(JSON.stringify(claims));
  const signingInput = `vcv1.${payloadB64}`;
  const sigB64 = base64UrlEncode(ed25519Sign(input.issuerKeyPair.privateSeedBytes, signingInput));
  return { token: `${signingInput}.${sigB64}`, claims };
}

export function verifyCreditVoucher(token: string, nowSeconds?: number): {
  valid: boolean;
  claims?: CreditVoucherClaims;
  reason?: string;
} {
  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts[0] !== 'vcv1') {
    return { valid: false, reason: 'Expected vcv1.<payload>.<signature>' };
  }
  const [, payloadB64, sigB64] = parts as [string, string, string];
  let claims: CreditVoucherClaims;
  try {
    claims = JSON.parse(Buffer.from(base64UrlDecode(payloadB64)).toString('utf8')) as CreditVoucherClaims;
  } catch {
    return { valid: false, reason: 'Malformed JSON in credit voucher' };
  }
  if (!ed25519Verify(claims.issuerDid, `vcv1.${payloadB64}`, sigB64)) {
    return { valid: false, reason: 'Invalid credit voucher signature' };
  }
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  if (now > claims.expiresAt) {
    return { valid: false, reason: 'Credit voucher expired' };
  }
  return { valid: true, claims };
}

// ─── Agent Clearing & RFC 9421 Request Signatures ──────────────────────────

export interface ClearingIntentPayload {
  agentId: string;
  challengeId: string;
  reqHash: string;
  maxAcceptedAmount: number;
  rail: string;
  timestamp: number;
}

export function buildClearingSigningInput(intent: ClearingIntentPayload): string {
  return [
    'vectoll-clear/v1',
    intent.agentId,
    intent.challengeId,
    intent.reqHash,
    String(intent.maxAcceptedAmount),
    intent.rail,
    String(intent.timestamp),
  ].join('\n');
}

export function signClearingIntent(intent: ClearingIntentPayload, agentKey: VectollKeyPair): string {
  return base64UrlEncode(ed25519Sign(agentKey.privateSeedBytes, buildClearingSigningInput(intent)));
}

export function verifyClearingIntent(
  intent: ClearingIntentPayload,
  signatureB64Url: string,
  nowSeconds = Math.floor(Date.now() / 1000),
  maxSkewSeconds = 60,
): { valid: boolean; reason?: string } {
  if (Math.abs(nowSeconds - intent.timestamp) > maxSkewSeconds) {
    return { valid: false, reason: 'Clearing signature timestamp outside ±60s window' };
  }
  const ok = ed25519Verify(intent.agentId, buildClearingSigningInput(intent), signatureB64Url);
  return ok ? { valid: true } : { valid: false, reason: 'Invalid Ed25519 agent clearing signature' };
}

export function signAgentHttpHeaders(
  reqHash: string,
  agentKey: VectollKeyPair,
  timestamp = Math.floor(Date.now() / 1000),
): Record<string, string> {
  const sigInput = `vectoll-agent-sig/v1\n${agentKey.did}\n${timestamp}\n${reqHash}`;
  const sig = base64UrlEncode(ed25519Sign(agentKey.privateSeedBytes, sigInput));
  return {
    'X-Vectoll-Agent-Id': agentKey.did,
    'X-Vectoll-Timestamp': String(timestamp),
    'X-Vectoll-Signature': sig,
    'Signature-Input': `vectoll=("@method" "@target-uri" "content-digest");created=${timestamp};keyid="${agentKey.did}";alg="ed25519"`,
    Signature: `vectoll=:${Buffer.from(base64UrlDecode(sig)).toString('base64')}:`,
  };
}

export function verifyAgentHttpHeaders(
  headers: Record<string, string | undefined>,
  expectedReqHash: string,
  nowSeconds = Math.floor(Date.now() / 1000),
): { valid: boolean; agentId?: string; reason?: string } {
  const norm: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(headers)) {
    norm[k.toLowerCase()] = v;
  }
  const agentId = norm['x-vectoll-agent-id'];
  const tsRaw = norm['x-vectoll-timestamp'];
  const sig = norm['x-vectoll-signature'];
  if (!agentId || !tsRaw || !sig) {
    return { valid: false, reason: 'Missing X-Vectoll-Agent-Id, X-Vectoll-Timestamp, or X-Vectoll-Signature' };
  }
  const ts = Number(tsRaw);
  if (!Number.isFinite(ts) || Math.abs(nowSeconds - ts) > 60) {
    return { valid: false, reason: 'Timestamp skew exceeded' };
  }
  const sigInput = `vectoll-agent-sig/v1\n${agentId}\n${ts}\n${expectedReqHash}`;
  if (!ed25519Verify(agentId, sigInput, sig)) {
    return { valid: false, reason: 'Invalid Ed25519 HTTP signature' };
  }
  return { valid: true, agentId };
}

// ─── x402 V2 Challenge & Header Helpers ────────────────────────────────────

export function createPaymentChallenge(input: {
  service: string;
  resource: string;
  method: string;
  reqHash: string;
  amount: number;
  currency: string;
  decimals: number;
  settlementMode?: SettlementMode;
  requireMandate?: boolean;
  hitlThreshold?: number | null;
  facilitatorUrl: string;
  facilitatorKid: string;
  acceptedRails: string[];
  challengeId?: string;
  issuedAt?: number;
  ttlSeconds?: number;
}): PaymentChallenge {
  assertSafeMinorAmount(input.amount, 'challenge.amount');
  const now = input.issuedAt ?? Math.floor(Date.now() / 1000);
  return {
    x402Version: 2,
    protocol: 'vectoll/0.1',
    challengeId: input.challengeId ?? randomId('chg', 12),
    service: input.service,
    resource: input.resource,
    method: input.method.toUpperCase(),
    reqHash: input.reqHash,
    amount: input.amount,
    currency: input.currency.toUpperCase(),
    decimals: input.decimals,
    settlementMode: input.settlementMode ?? 'instant',
    requireMandate: input.requireMandate ?? false,
    hitlThreshold: input.hitlThreshold ?? null,
    facilitatorUrl: input.facilitatorUrl,
    facilitatorKid: input.facilitatorKid,
    acceptedRails: input.acceptedRails,
    issuedAt: now,
    expiresAt: now + (input.ttlSeconds ?? 60),
  };
}

export function encodePaymentHeader(payload: PaymentChallenge | PaymentResponseHeader): string {
  return base64UrlEncode(JSON.stringify(payload));
}

export function decodePaymentHeader<T = PaymentChallenge>(headerValue: string): T {
  const json = Buffer.from(base64UrlDecode(headerValue.trim())).toString('utf8');
  return JSON.parse(json) as T;
}

export function createPaymentResponseHeader(claims: VrtClaims, nowSeconds = Math.floor(Date.now() / 1000)): string {
  const summary: PaymentResponseHeader = {
    x402Version: 2,
    protocol: 'vectoll/0.1',
    receiptId: claims.jti,
    settled: claims.mode === 'instant',
    mode: claims.mode,
    ...(claims.esc ? { escrowId: claims.esc } : {}),
    amount: claims.amt,
    currency: claims.cur,
    decimals: claims.dec,
    rail: claims.rail,
    verifiedAt: nowSeconds,
  };
  return encodePaymentHeader(summary);
}
