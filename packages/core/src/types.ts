export interface VectollKeyPair {
  kid: string;
  did: string;
  seedHex: string;
  publicKeyBase64Url: string;
  privateSeedBytes: Uint8Array;
  publicKeyBytes: Uint8Array;
}

export interface JsonWebKeyEd25519 {
  kty: 'OKP';
  crv: 'Ed25519';
  kid: string;
  use: 'sig';
  alg: 'EdDSA';
  x: string;
}

export type SettlementMode = 'instant' | 'escrow';
export type PricingMode = 'fixed' | 'dynamic_quote';
export type AgentTransformMode = 'none' | 'structured' | 'markdown';

export interface PaymentChallenge {
  x402Version: 2;
  protocol: 'vectoll/0.1';
  challengeId: string;
  service: string;
  resource: string;
  method: string;
  reqHash: string;
  amount: number;
  currency: string;
  decimals: number;
  settlementMode: SettlementMode;
  requireMandate: boolean;
  hitlThreshold: number | null;
  facilitatorUrl: string;
  facilitatorKid: string;
  acceptedRails: string[];
  issuedAt: number;
  expiresAt: number;
}

export interface VrtClaims {
  v: 1;
  jti: string;
  kid: string;
  iss: string;
  sub: string;
  aud: string;
  chg: string;
  req: string;
  amt: number;
  cur: string;
  dec: number;
  rail: string;
  mode: SettlementMode;
  esc?: string;
  iat: number;
  exp: number;
}

export interface SpendMandateClaims {
  v: 1;
  mandateId: string;
  principalId: string;
  agentId: string;
  currency: string;
  decimals: number;
  maxPerCall: number;
  maxDaily: number;
  allowedServices: string[];
  allowedRails: string[];
  hitlThreshold: number | null;
  purpose?: string;
  issuedAt: number;
  expiresAt: number;
}

export interface CreditVoucherClaims {
  v: 1;
  voucherId: string;
  issuerDid: string;
  beneficiaryDid: string;
  service: string;
  amount: number;
  currency: string;
  decimals: number;
  issuedAt: number;
  expiresAt: number;
}

export interface PaymentResponseHeader {
  x402Version: 2;
  protocol: 'vectoll/0.1';
  receiptId: string;
  settled: boolean;
  mode: SettlementMode;
  escrowId?: string;
  amount: number;
  currency: string;
  decimals: number;
  rail: string;
  verifiedAt: number;
}

export interface VectollRouteConfig {
  path: string;
  method: string;
  pricing_mode?: PricingMode;
  price: number;
  currency?: string;
  decimals?: number;
  settlement_mode?: SettlementMode;
  require_mandate?: boolean;
  hitl_threshold?: number | null;
  human_passthrough?: boolean;
  agent_transform?: AgentTransformMode;
  mcp_tool?: string;
  mcp_description?: string;
}

export interface VectollConfig {
  version: string;
  service: {
    name: string;
    description?: string;
    origin: string;
    listen?: string;
    discovery_path?: string;
    enable_mcp?: boolean;
  };
  security?: {
    rate_limit_rps?: number;
    max_body_bytes?: number;
    challenge_ttl_seconds?: number;
  };
  settlement: {
    facilitator_url: string;
    facilitator_kid?: string;
    facilitator_public_key?: string;
    default_currency: string;
    default_decimals?: number;
    accepted_rails: string[];
  };
  routes: VectollRouteConfig[];
}

export const CURRENCY_DECIMALS: Record<string, number> = {
  USD: 6,
  EUR: 6,
  GBP: 6,
  CHF: 6,
  CAD: 6,
  AUD: 6,
  SGD: 6,
  USDC: 6,
  USDT: 6,
  PYUSD: 6,
  JPY: 0,
  KRW: 0,
  INR: 2,
  BRL: 2,
  MXN: 2,
  AED: 2,
  ZAR: 2,
  KES: 2,
  NGN: 2,
  GHS: 2,
  TZS: 2,
  UGX: 0,
  RWF: 0,
};

export function getCurrencyDecimals(currency: string, explicit?: number): number {
  if (typeof explicit === 'number' && Number.isInteger(explicit) && explicit >= 0) {
    return explicit;
  }
  return CURRENCY_DECIMALS[currency.toUpperCase()] ?? 2;
}

export function formatMinorAmount(amount: number, currency: string, explicitDecimals?: number): string {
  const cur = currency.toUpperCase();
  const dec = getCurrencyDecimals(cur, explicitDecimals);
  if (dec === 0) {
    return `${amount.toLocaleString('en-US')} ${cur}`;
  }
  const factor = 10 ** dec;
  const val = amount / factor;
  const maxFrac = dec > 4 ? 6 : dec;
  const minFrac = dec === 2 ? 2 : 2;
  const formatted = val.toLocaleString('en-US', {
    minimumFractionDigits: minFrac,
    maximumFractionDigits: maxFrac,
  });
  return `${formatted} ${cur}`;
}

export function assertSafeMinorAmount(amount: number, label = 'amount'): void {
  if (!Number.isSafeInteger(amount) || amount < 0) {
    throw new Error(`Invalid ${label}: expected non-negative safe integer minor units, got ${String(amount)}`);
  }
}
