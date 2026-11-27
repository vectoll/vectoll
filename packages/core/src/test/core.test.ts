import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  classifyTraffic,
  computeRequestHash,
  createPaymentChallenge,
  createSpendMandate,
  decodePaymentHeader,
  didKeyToPublicKey,
  encodePaymentHeader,
  keyPairFromSeed,
  parsePrice,
  parseVectollConfig,
  signAgentHttpHeaders,
  signClearingIntent,
  signVrt,
  verifyAgentHttpHeaders,
  verifyClearingIntent,
  verifySpendMandate,
  verifyVrt,
} from '../index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectorsPath = path.resolve(__dirname, '../../../../spec/test-vectors/crypto-vectors.json');

describe('@vectoll/core deterministic cryptography & wire protocol', () => {
  const facSeed = '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
  const principalSeed = '2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40';
  const agentSeed = '4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60';

  const facKey = keyPairFromSeed(facSeed, 'fac-vec-1');
  const principalKey = keyPairFromSeed(principalSeed, 'prin-vec-1');
  const agentKey = keyPairFromSeed(agentSeed, 'agent-vec-1');

  it('roundtrips did:key multicodec Ed25519 public keys accurately', () => {
    const pub = didKeyToPublicKey(agentKey.did);
    assert.deepEqual(pub, agentKey.publicKeyBytes);
    assert.ok(agentKey.did.startsWith('did:key:z6Mk'));
  });

  it('computes canonical request hashes deterministically and binds body/query', () => {
    const hGet = computeRequestHash('GET', '/api/v1/rooms/availability?adults=2', '');
    const hGetTampered = computeRequestHash('GET', '/api/v1/rooms/availability?adults=3', '');
    const hPost = computeRequestHash('POST', '/api/v1/rooms/book', '{"room":"deluxe","nights":2}');
    assert.match(hGet, /^sha256:[0-9a-f]{64}$/);
    assert.notEqual(hGet, hGetTampered);
    assert.notEqual(hGet, hPost);
  });

  it('signs and verifies vrt1 receipts and rejects tampered payloads, wrong reqHash, or expiry', () => {
    const reqHash = computeRequestHash('GET', '/api/v1/rooms/availability?adults=2', '');
    const { token, claims } = signVrt(
      {
        jti: 'vrt_vector_0001',
        iss: 'https://facilitator.vectoll.org',
        sub: agentKey.did,
        aud: 'acme-hospitality-api',
        chg: 'chg_vector_0001',
        req: reqHash,
        amt: 50,
        cur: 'UGX',
        dec: 0,
        rail: 'momo',
        mode: 'instant',
        iat: 1795753800,
        exp: 1795753860,
      },
      facKey,
    );

    const ok = verifyVrt(token, facKey.publicKeyBase64Url, {
      expectedAudience: 'acme-hospitality-api',
      expectedReqHash: reqHash,
      minAmount: 50,
      expectedCurrency: 'UGX',
      nowSeconds: 1795753810,
    });
    assert.equal(ok.valid, true);
    if (ok.valid) assert.equal(ok.claims.jti, claims.jti);

    // Reject body/query swap
    const badReq = verifyVrt(token, facKey.publicKeyBase64Url, {
      expectedAudience: 'acme-hospitality-api',
      expectedReqHash: computeRequestHash('POST', '/api/v1/rooms/book', '{}'),
      nowSeconds: 1795753810,
    });
    assert.equal(badReq.valid, false);
    if (!badReq.valid) assert.equal(badReq.code, 'ERR_REQUEST_HASH_MISMATCH');

    // Reject expired receipt
    const expired = verifyVrt(token, facKey.publicKeyBase64Url, {
      nowSeconds: 1795753900,
    });
    assert.equal(expired.valid, false);
    if (!expired.valid) assert.equal(expired.code, 'ERR_RECEIPT_EXPIRED');

    // Reject wrong key
    const wrongKey = verifyVrt(token, agentKey.publicKeyBase64Url, { nowSeconds: 1795753810 });
    assert.equal(wrongKey.valid, false);
    if (!wrongKey.valid) assert.equal(wrongKey.code, 'ERR_INVALID_RECEIPT_SIGNATURE');
  });

  it('enforces Spend Mandates (vsm1) per-call, daily cap, service allowlist, and HITL trigger', () => {
    const { token } = createSpendMandate({
      principalKeyPair: principalKey,
      agentId: agentKey.did,
      mandateId: 'mnd_vector_0001',
      currency: 'UGX',
      decimals: 0,
      maxPerCall: 600_000,
      maxDaily: 1_000_000,
      allowedServices: ['acme-hospitality-api'],
      allowedRails: ['momo', 'x402_usdc'],
      hitlThreshold: 500_000,
      issuedAt: 1795750000,
      expiresAt: 1795850000,
    });

    // Normal 50 UGX query -> valid, no HITL
    const res1 = verifySpendMandate(token, {
      expectedAgentId: agentKey.did,
      service: 'acme-hospitality-api',
      rail: 'momo',
      debitAmountInMandateCurrency: 50,
      spentLast24hInMandateCurrency: 0,
      nowSeconds: 1795753800,
    });
    assert.equal(res1.valid, true);
    if (res1.valid) assert.equal(res1.requiresHitl, false);

    // 550,000 UGX booking -> valid, requiresHitl = true
    const resHitl = verifySpendMandate(token, {
      expectedAgentId: agentKey.did,
      service: 'acme-hospitality-api',
      rail: 'momo',
      debitAmountInMandateCurrency: 550_000,
      spentLast24hInMandateCurrency: 0,
      nowSeconds: 1795753800,
    });
    assert.equal(resHitl.valid, true);
    if (resHitl.valid) assert.equal(resHitl.requiresHitl, true);

    // 700,000 UGX -> exceeds maxPerCall
    const overCall = verifySpendMandate(token, {
      expectedAgentId: agentKey.did,
      service: 'acme-hospitality-api',
      rail: 'momo',
      debitAmountInMandateCurrency: 700_000,
      nowSeconds: 1795753800,
    });
    assert.equal(overCall.valid, false);
    if (!overCall.valid) assert.equal(overCall.code, 'ERR_MANDATE_MAX_PER_CALL_EXCEEDED');

    // Rolling 24h cap exceeded
    const overDaily = verifySpendMandate(token, {
      expectedAgentId: agentKey.did,
      service: 'acme-hospitality-api',
      rail: 'momo',
      debitAmountInMandateCurrency: 500_000,
      spentLast24hInMandateCurrency: 600_000,
      nowSeconds: 1795753800,
    });
    assert.equal(overDaily.valid, false);
    if (!overDaily.valid) assert.equal(overDaily.code, 'ERR_MANDATE_DAILY_CAP_EXCEEDED');
  });

  it('verifies clearing signatures, RFC 9421 headers, x402 headers, YAML config, and matches shared test vectors', () => {
    const reqHash = computeRequestHash('GET', '/api/v1/rooms/availability?adults=2', '');
    const intent = {
      agentId: agentKey.did,
      challengeId: 'chg_vector_0001',
      reqHash,
      maxAcceptedAmount: 50,
      rail: 'momo',
      timestamp: 1795753805,
    };
    const clearSig = signClearingIntent(intent, agentKey);
    assert.equal(verifyClearingIntent(intent, clearSig, 1795753810).valid, true);

    const httpHeaders = signAgentHttpHeaders(reqHash, agentKey, 1795753805);
    assert.equal(verifyAgentHttpHeaders(httpHeaders, reqHash, 1795753810).valid, true);

    const chg = createPaymentChallenge({
      challengeId: 'chg_vector_0001',
      service: 'acme-hospitality-api',
      resource: '/api/v1/rooms/availability?adults=2',
      method: 'GET',
      reqHash,
      amount: 50,
      currency: 'UGX',
      decimals: 0,
      facilitatorUrl: 'https://facilitator.vectoll.org',
      facilitatorKid: facKey.kid,
      acceptedRails: ['momo', 'x402_usdc'],
      issuedAt: 1795753800,
    });
    const encoded = encodePaymentHeader(chg);
    assert.deepEqual(decodePaymentHeader(encoded), chg);

    // Human vs Agent traffic classifier
    assert.equal(
      classifyTraffic(
        {
          'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
          accept: 'text/html,application/xhtml+xml',
        },
        true,
        '/articles/2026',
      ),
      'human',
    );
    assert.equal(
      classifyTraffic({ 'user-agent': 'GPTBot/1.2', accept: 'text/html' }, true, '/articles/2026'),
      'agent',
    );

    const cfg = parseVectollConfig(`
version: "1.0"
service:
  name: "acme-hospitality-api"
  origin: "http://127.0.0.1:8080"
settlement:
  facilitator_url: "http://127.0.0.1:4021"
  default_currency: "UGX"
  accepted_rails:
    - "momo"
    - "x402_usdc"
routes:
  - path: "/api/v1/rooms/availability"
    method: "GET"
    price: 50
    human_passthrough: true
`);
    assert.equal(cfg.service.name, 'acme-hospitality-api');
    assert.equal(cfg.routes[0]?.price, 50);

    // Human-readable price strings + 6-line shorthand vectoll.yaml!
    assert.deepEqual(parsePrice('$0.005'), { amount: 5000, currency: 'USD', decimals: 6 });
    assert.deepEqual(parsePrice('€1.25'), { amount: 1_250_000, currency: 'EUR', decimals: 6 });
    assert.deepEqual(parsePrice('₹10'), { amount: 1000, currency: 'INR', decimals: 2 });
    assert.deepEqual(parsePrice('50 UGX'), { amount: 50, currency: 'UGX', decimals: 0 });
    assert.deepEqual(parsePrice('free'), { amount: 0, currency: 'USD', decimals: 6 });

    const shortCfg = parseVectollConfig(`
origin: "http://localhost:3000"
routes:
  GET /api/search: "$0.005"
  GET /blog/*: { price: "$0.001", browsers: "free" }
`);
    assert.equal(shortCfg.service.origin, 'http://localhost:3000');
    assert.equal(shortCfg.settlement.accepted_rails.length, 9);
    assert.equal(shortCfg.routes[0]?.path, '/api/search');
    assert.equal(shortCfg.routes[0]?.price, 5000);
    assert.equal(shortCfg.routes[0]?.mcp_tool, 'get_search');
    assert.equal(shortCfg.routes[1]?.human_passthrough, true);

    // Verify deterministic cross-language vectors match on disk
    const vrtOut = signVrt(
      {
        jti: 'vrt_vector_0001',
        iss: 'https://facilitator.vectoll.org',
        sub: agentKey.did,
        aud: 'acme-hospitality-api',
        chg: 'chg_vector_0001',
        req: reqHash,
        amt: 50,
        cur: 'UGX',
        dec: 0,
        rail: 'momo',
        mode: 'instant',
        iat: 1795753800,
        exp: 1795753860,
      },
      facKey,
    );
    const mandateOut = createSpendMandate({
      principalKeyPair: principalKey,
      agentId: agentKey.did,
      mandateId: 'mnd_vector_0001',
      currency: 'UGX',
      decimals: 0,
      maxPerCall: 600_000,
      maxDaily: 1_000_000,
      allowedServices: ['acme-hospitality-api'],
      allowedRails: ['momo', 'x402_usdc'],
      hitlThreshold: 500_000,
      issuedAt: 1795750000,
      expiresAt: 1795850000,
    });

    const expectedVectors = {
      version: 'vectoll/0.1',
      keys: {
        facilitator: {
          kid: facKey.kid,
          seedHex: facSeed,
          did: facKey.did,
          publicKeyBase64Url: facKey.publicKeyBase64Url,
        },
        principal: {
          kid: principalKey.kid,
          seedHex: principalSeed,
          did: principalKey.did,
          publicKeyBase64Url: principalKey.publicKeyBase64Url,
        },
        agent: {
          kid: agentKey.kid,
          seedHex: agentSeed,
          did: agentKey.did,
          publicKeyBase64Url: agentKey.publicKeyBase64Url,
        },
      },
      requestHashes: [
        {
          method: 'GET',
          target: '/api/v1/rooms/availability?adults=2',
          bodyUtf8: '',
          expectedReqHash: reqHash,
        },
        {
          method: 'POST',
          target: '/api/v1/rooms/book',
          bodyUtf8: '{"room":"deluxe","nights":2}',
          expectedReqHash: computeRequestHash('POST', '/api/v1/rooms/book', '{"room":"deluxe","nights":2}'),
        },
      ],
      vrtVector: {
        token: vrtOut.token,
        claims: vrtOut.claims,
      },
      mandateVector: {
        token: mandateOut.token,
        claims: mandateOut.claims,
      },
      clearingIntentVector: {
        intent,
        signatureBase64Url: clearSig,
      },
    };

    if (!fs.existsSync(vectorsPath)) {
      fs.mkdirSync(path.dirname(vectorsPath), { recursive: true });
      fs.writeFileSync(vectorsPath, JSON.stringify(expectedVectors, null, 2) + '\n', 'utf8');
    } else {
      const diskVectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
      assert.deepEqual(diskVectors, expectedVectors);
    }
  });
});
