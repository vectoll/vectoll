import { assertSafeMinorAmount, getCurrencyDecimals } from './types.js';

const SYMBOL_TO_CURRENCY: Record<string, string> = {
  $: 'USD',
  '€': 'EUR',
  '£': 'GBP',
  '¥': 'JPY',
  '₹': 'INR',
};

export interface ParsedPrice {
  amount: number;
  currency: string;
  decimals: number;
}

/**
 * Losslessly parses human-readable price strings into integer minor units without floating-point math.
 * Examples:
 *   "$0.005"      -> { amount: 5000, currency: "USD", decimals: 6 }
 *   "0.02 USDC"   -> { amount: 20000, currency: "USDC", decimals: 6 }
 *   "€1.25"       -> { amount: 1250000, currency: "EUR", decimals: 6 }
 *   "₹10"         -> { amount: 1000, currency: "INR", decimals: 2 }
 *   "50 UGX"      -> { amount: 50, currency: "UGX", decimals: 0 }
 *   "free" | 0    -> { amount: 0, currency: fallbackCurrency, decimals }
 */
export function parsePrice(
  input: string | number,
  fallbackCurrency?: string,
  explicitDecimals?: number,
): ParsedPrice {
  const hasExplicitFallback = Boolean(fallbackCurrency && fallbackCurrency.trim().length > 0);
  const defaultCur = (fallbackCurrency ?? 'USD').toUpperCase();

  if (typeof input === 'number') {
    assertSafeMinorAmount(input, 'price');
    const dec = getCurrencyDecimals(defaultCur, explicitDecimals);
    return { amount: input, currency: defaultCur, decimals: dec };
  }

  const raw = input.trim();
  if (!raw || raw.toLowerCase() === 'free' || raw === '0') {
    const dec = getCurrencyDecimals(defaultCur, explicitDecimals);
    return { amount: 0, currency: defaultCur, decimals: dec };
  }

  let currency = defaultCur;
  let numericPart = raw;

  // Leading currency symbol: $0.005, €1.50, £2, ¥100, ₹25
  const firstChar = raw[0]!;
  if (SYMBOL_TO_CURRENCY[firstChar]) {
    // Dollar sign '$' is shared across USD, USDC, CAD, AUD, SGD; keep explicit currency if caller passed one
    if (!hasExplicitFallback || firstChar !== '$') {
      currency = SYMBOL_TO_CURRENCY[firstChar]!;
    }
    numericPart = raw.slice(1).trim();
    // Optional trailing code e.g. "$0.005 USD"
    const trailingMatch = numericPart.match(/^([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]{3,5})?$/);
    if (!trailingMatch) {
      throw new Error(`Invalid price string: "${input}"`);
    }
    numericPart = trailingMatch[1]!;
    if (trailingMatch[2]) {
      currency = trailingMatch[2].toUpperCase();
    }
  } else {
    // Format: "0.005 USD", "50 UGX", "USD 0.005", or plain decimal "0.005"
    const codeAfter = raw.match(/^([0-9]+(?:\.[0-9]+)?)\s+([A-Za-z]{3,5})$/);
    const codeBefore = raw.match(/^([A-Za-z]{3,5})\s+([0-9]+(?:\.[0-9]+)?)$/);
    const plainNum = raw.match(/^([0-9]+(?:\.[0-9]+)?)$/);
    if (codeAfter) {
      numericPart = codeAfter[1]!;
      currency = codeAfter[2]!.toUpperCase();
    } else if (codeBefore) {
      currency = codeBefore[1]!.toUpperCase();
      numericPart = codeBefore[2]!;
    } else if (plainNum) {
      numericPart = plainNum[1]!;
    } else {
      throw new Error(
        `Invalid price format "${input}". Expected examples: "$0.005", "0.01 USD", "€0.50", "50 UGX", or "free"`,
      );
    }
  }

  const decimals = getCurrencyDecimals(currency, explicitDecimals);
  const [wholeStr = '0', fracStr = ''] = numericPart.split('.');

  if (fracStr.length > decimals) {
    throw new Error(
      `Price "${input}" has ${fracStr.length} decimal places, exceeding ${currency} precision (${decimals})`,
    );
  }

  const paddedFrac = fracStr.padEnd(decimals, '0');
  const combined = `${wholeStr}${paddedFrac}`.replace(/^0+(?=\d)/, '');
  const amountBig = BigInt(combined || '0');
  if (amountBig > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`Price "${input}" exceeds safe integer minor units`);
  }
  const amount = Number(amountBig);
  assertSafeMinorAmount(amount, 'parsedPrice');

  return { amount, currency, decimals };
}

/**
 * Parses a concise route key like "GET /api/search" or "/api/search" (defaults to GET).
 */
export function parseRouteKey(routeKey: string): { method: string; path: string } {
  const trimmed = routeKey.trim();
  const spaceIdx = trimmed.indexOf(' ');
  if (spaceIdx === -1) {
    return { method: 'GET', path: trimmed.startsWith('/') ? trimmed : `/${trimmed}` };
  }
  const method = trimmed.slice(0, spaceIdx).trim().toUpperCase();
  const path = trimmed.slice(spaceIdx + 1).trim();
  return { method, path: path.startsWith('/') ? path : `/${path}` };
}
