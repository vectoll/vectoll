import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeRequestHash,
  createPaymentChallenge,
  createSpendMandate,
  generateKeyPair,
  signClearingIntent,
  verifyVrt,
} from '@vectoll/core';
import { PostgresLedgerStore, VectollFacilitator, type PgPoolLike, type PgQueryResult } from '../index.js';

describe('@vectoll/facilitator double-entry clearing, cross-currency FX, Escrow & HITL', () => {
  it('clears instant UGX float, cross-currency USD->UGX, escrow + HITL approval, and merchant MoMo payouts with 0 ledger drift', async () => {
    const fac = new VectollFacilitator({ dbPath: ':memory:', feeBps: 200 }); // 2% fee
    const principal = generateKeyPair();
    const agent = generateKeyPair();

    // 1. Top up 1,000,000 UGX via MTN MoMo + 10.00 USD (10,000,000 micro-USD) via Stripe
    await fac.topUpWallet({ agentId: agent.did, amount: 1_000_000, currency: 'UGX', rail: 'momo' });
    await fac.topUpWallet({ agentId: agent.did, amount: 10_000_000, currency: 'USD', rail: 'stripe' });

    // 2. Instant 50 UGX availability call paid from USD wallet (cross-currency FX!)
    const reqHash1 = computeRequestHash('GET', '/api/v1/rooms/availability', '');
    const chg1 = createPaymentChallenge({
      service: 'acme-hospitality-api',
      resource: '/api/v1/rooms/availability',
      method: 'GET',
      reqHash: reqHash1,
      amount: 50,
      currency: 'UGX',
      decimals: 0,
      facilitatorUrl: fac.issuerUrl,
      facilitatorKid: fac.keyPair.kid,
      acceptedRails: ['momo', 'stripe'],
    });
    const ts = Math.floor(Date.now() / 1000);
    const sig1 = signClearingIntent(
      {
        agentId: agent.did,
        challengeId: chg1.challengeId,
        reqHash: reqHash1,
        maxAcceptedAmount: 50_000, // micro-USD ceiling
        rail: 'stripe',
        timestamp: ts,
      },
      agent,
    );

    const clear1 = await fac.clearChallenge({
      challenge: chg1,
      agentId: agent.did,
      rail: 'stripe',
      walletCurrency: 'USD',
      maxAcceptedAmount: 50_000,
      timestamp: ts,
      agentSignature: sig1,
    });
    assert.equal(clear1.status, 'CLEARED');
    if (clear1.status === 'CLEARED') {
      const vrtCheck = verifyVrt(clear1.vrt, fac.keyPair.publicKeyBase64Url, {
        expectedAudience: 'acme-hospitality-api',
        expectedReqHash: reqHash1,
        minAmount: 50,
        expectedCurrency: 'UGX',
      });
      assert.equal(vrtCheck.valid, true);
    }

    // 3. High-value 550,000 UGX hotel booking with Mandate + Escrow + HITL threshold (500,000 UGX)
    const mandate = createSpendMandate({
      principalKeyPair: principal,
      agentId: agent.did,
      currency: 'UGX',
      decimals: 0,
      maxPerCall: 600_000,
      maxDaily: 1_500_000,
      allowedServices: ['acme-hospitality-api'],
      allowedRails: ['momo'],
      hitlThreshold: 500_000,
    });

    const reqHash2 = computeRequestHash('POST', '/api/v1/rooms/book', '{"room":"suite"}');
    const chg2 = createPaymentChallenge({
      service: 'acme-hospitality-api',
      resource: '/api/v1/rooms/book',
      method: 'POST',
      reqHash: reqHash2,
      amount: 550_000,
      currency: 'UGX',
      decimals: 0,
      settlementMode: 'escrow',
      requireMandate: true,
      hitlThreshold: 500_000,
      facilitatorUrl: fac.issuerUrl,
      facilitatorKid: fac.keyPair.kid,
      acceptedRails: ['momo'],
    });
    const sig2 = signClearingIntent(
      {
        agentId: agent.did,
        challengeId: chg2.challengeId,
        reqHash: reqHash2,
        maxAcceptedAmount: 550_000,
        rail: 'momo',
        timestamp: ts,
      },
      agent,
    );

    const clear2 = await fac.clearChallenge({
      challenge: chg2,
      agentId: agent.did,
      rail: 'momo',
      walletCurrency: 'UGX',
      maxAcceptedAmount: 550_000,
      timestamp: ts,
      agentSignature: sig2,
      mandateToken: mandate.token,
    });
    assert.equal(clear2.status, 'PENDING_HITL');

    if (clear2.status === 'PENDING_HITL') {
      // Business owner approves HITL -> funds lock in escrow & VRT minted!
      const approved = fac.decideHitl(clear2.approvalId, 'approve');
      assert.equal(approved.status, 'APPROVED');
      assert.ok(approved.vrt);
      assert.ok(approved.escrowId);

      // Origin confirms room reservation -> Escrow settles to Merchant Payable + Platform Fee!
      const settled = fac.fulfillEscrow(approved.escrowId!, 'RES-KLA-9921');
      assert.equal(settled.status, 'SETTLED');
    }

    // 4. Merchant sweeps accumulated UGX payable to MTN MoMo
    const payout = await fac.payoutMerchant({
      service: 'acme-hospitality-api',
      destinationAccount: '+256772123456',
      rail: 'momo',
      currency: 'UGX',
    });
    // 50 UGX * 98% = 49 UGX + 550,000 UGX * 98% = 539,000 UGX => 539,049 UGX!
    assert.equal(payout.amount, 539_049);
    assert.equal(payout.remainingPayable, 0);

    // 5. Verify strict mathematical double-entry balance across ALL currencies
    const integrity = fac.ledger.verifyIntegrity();
    assert.equal(integrity.balanced, true);
    fac.ledger.close();
  });

  it('executes SERIALIZABLE double-entry postings, idempotency, and rollback on PostgresLedgerStore', async () => {
    const txs = new Map<string, string>();
    const accounts = new Map<string, { type: 'asset' | 'liability' | 'revenue'; debit: number; credit: number }>();
    const entries: Array<{ currency: string; debit: number; credit: number }> = [];
    let snapshotAccounts = new Map(accounts);
    let snapshotEntries = [...entries];
    let sawSerializableBegin = false;

    const mockPool: PgPoolLike = {
      async connect() {
        return {
          release() {},
          async query<TRow = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<PgQueryResult<TRow>> {
            if (sql.startsWith('BEGIN ISOLATION LEVEL SERIALIZABLE')) {
              sawSerializableBegin = true;
              snapshotAccounts = new Map(
                Array.from(accounts.entries()).map(([k, v]) => [k, { ...v }]),
              );
              snapshotEntries = [...entries];
              return { rows: [] };
            }
            if (sql === 'ROLLBACK') {
              accounts.clear();
              for (const [k, v] of snapshotAccounts) accounts.set(k, v);
              entries.length = 0;
              entries.push(...snapshotEntries);
              return { rows: [] };
            }
            if (sql === 'COMMIT') return { rows: [] };
            if (sql.includes('FROM journal_transactions WHERE idempotency_key')) {
              const found = txs.get(String(params[0]));
              return { rows: (found ? [{ tx_id: found }] : []) as unknown as TRow[] };
            }
            if (sql.startsWith('INSERT INTO journal_transactions')) {
              txs.set(String(params[1]), String(params[0]));
              return { rows: [] };
            }
            if (sql.startsWith('INSERT INTO accounts')) {
              const key = `${params[0]}:${params[1]}`;
              const cur = accounts.get(key) ?? {
                type: params[3] as 'asset' | 'liability' | 'revenue',
                debit: 0,
                credit: 0,
              };
              cur.debit += Number(params[4]);
              cur.credit += Number(params[5]);
              accounts.set(key, cur);
              return {
                rows: [
                  { debit_total: cur.debit, credit_total: cur.credit, account_type: cur.type },
                ] as unknown as TRow[],
              };
            }
            if (sql.startsWith('INSERT INTO journal_entries')) {
              entries.push({
                currency: String(params[3]),
                debit: Number(params[5]),
                credit: Number(params[6]),
              });
              return { rows: [] };
            }
            return { rows: [] };
          },
        };
      },
      async query<TRow = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<PgQueryResult<TRow>> {
        if (sql.includes('FROM accounts WHERE account_code')) {
          const row = accounts.get(`${params[0]}:${params[1]}`);
          return {
            rows: (row
              ? [{ account_type: row.type, debit_total: row.debit, credit_total: row.credit }]
              : []) as unknown as TRow[],
          };
        }
        if (sql.includes('SUM(debit) AS total_debit')) {
          let d = 0;
          let c = 0;
          for (const e of entries) {
            d += e.debit;
            c += e.credit;
          }
          return { rows: [{ currency: 'USD', total_debit: d, total_credit: c }] as unknown as TRow[] };
        }
        return { rows: [] };
      },
    };

    const pgLedger = new PostgresLedgerStore(mockPool);
    const r1 = await pgLedger.postJournal({
      idempotencyKey: 'pg-topup-1',
      txKind: 'WALLET_TOPUP',
      description: 'Fund 10 USD',
      postings: [
        { accountCode: 'asset:rail_clearing:stripe:USD', accountType: 'asset', currency: 'USD', debit: 10_000_000, credit: 0 },
        { accountCode: 'liability:agent_float:did:key:z6MkPg', accountType: 'liability', currency: 'USD', debit: 0, credit: 10_000_000 },
      ],
    });
    assert.equal(sawSerializableBegin, true);
    assert.equal(r1.deduplicated, false);

    // Idempotency replay returns same txId without double-crediting!
    const rDup = await pgLedger.postJournal({
      idempotencyKey: 'pg-topup-1',
      txKind: 'WALLET_TOPUP',
      description: 'Fund 10 USD',
      postings: [
        { accountCode: 'asset:rail_clearing:stripe:USD', accountType: 'asset', currency: 'USD', debit: 10_000_000, credit: 0 },
        { accountCode: 'liability:agent_float:did:key:z6MkPg', accountType: 'liability', currency: 'USD', debit: 0, credit: 10_000_000 },
      ],
    });
    assert.equal(rDup.deduplicated, true);
    assert.equal(rDup.txId, r1.txId);
    assert.equal(await pgLedger.getAccountBalance('liability:agent_float:did:key:z6MkPg', 'USD'), 10_000_000);

    // Overdraft attempt rolls back cleanly!
    await assert.rejects(
      () =>
        pgLedger.postJournal({
          idempotencyKey: 'pg-overdraft',
          txKind: 'INSTANT_CLEAR',
          description: 'Overspend',
          postings: [
            { accountCode: 'liability:agent_float:did:key:z6MkPg', accountType: 'liability', currency: 'USD', debit: 50_000_000, credit: 0 },
            { accountCode: 'liability:merchant_payable:svc', accountType: 'liability', currency: 'USD', debit: 0, credit: 50_000_000 },
          ],
        }),
      /ERR_INSUFFICIENT_FUNDS/,
    );
    assert.equal(await pgLedger.getAccountBalance('liability:agent_float:did:key:z6MkPg', 'USD'), 10_000_000);
    assert.equal((await pgLedger.verifyIntegrity()).balanced, true);
  });
});
