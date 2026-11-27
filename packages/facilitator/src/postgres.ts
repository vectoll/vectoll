import { assertSafeMinorAmount, getCurrencyDecimals, randomId } from '@vectoll/core';
import type { AccountType, JournalPostingInput } from './ledger.js';

/**
 * Minimal pg.Pool-compatible interface so production deployments plug in `pg`
 * (`new Pool({ connectionString: process.env.VECTOLL_POSTGRES_URL })`) without
 * forcing native/heavy Postgres driver dependencies on lightweight SQLite users.
 */
export interface PgQueryResult<TRow = Record<string, unknown>> {
  rows: TRow[];
  rowCount?: number | null;
}

export interface PgPoolClient {
  query<TRow = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<PgQueryResult<TRow>>;
  release(): void;
}

export interface PgPoolLike {
  connect(): Promise<PgPoolClient>;
  query<TRow = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<PgQueryResult<TRow>>;
}

export class PostgresLedgerStore {
  private readonly pool: PgPoolLike;

  constructor(pool: PgPoolLike) {
    this.pool = pool;
  }

  async postJournal(input: {
    idempotencyKey: string;
    txKind: string;
    description: string;
    postings: JournalPostingInput[];
    metadata?: Record<string, unknown>;
    resultToStore?: unknown;
    nowSeconds?: number;
  }): Promise<{ txId: string; deduplicated: boolean }> {
    if (input.postings.length < 2) {
      throw new Error('Double-entry transaction requires at least 2 postings');
    }

    // Application-layer pre-check of SUM(debit) === SUM(credit) per currency
    const sums = new Map<string, { debit: bigint; credit: bigint }>();
    for (const p of input.postings) {
      assertSafeMinorAmount(p.debit, 'posting.debit');
      assertSafeMinorAmount(p.credit, 'posting.credit');
      if (p.debit === 0 && p.credit === 0) continue;
      if (p.debit > 0 && p.credit > 0) {
        throw new Error(`Posting on ${p.accountCode} cannot have both debit and credit > 0`);
      }
      const cur = p.currency.toUpperCase();
      const s = sums.get(cur) ?? { debit: 0n, credit: 0n };
      s.debit += BigInt(p.debit);
      s.credit += BigInt(p.credit);
      sums.set(cur, s);
    }

    for (const [cur, totals] of sums.entries()) {
      if (totals.debit !== totals.credit) {
        throw new Error(
          `LEDGER_IMBALANCE in ${cur}: debit=${totals.debit.toString()} !== credit=${totals.credit.toString()}`,
        );
      }
    }

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

      const existing = await client.query<{ tx_id: string }>(
        'SELECT tx_id FROM journal_transactions WHERE idempotency_key = $1',
        [input.idempotencyKey],
      );
      if (existing.rows[0]?.tx_id) {
        await client.query('COMMIT');
        return { txId: existing.rows[0].tx_id, deduplicated: true };
      }

      const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
      const txId = randomId('jtx', 10);

      await client.query(
        `INSERT INTO journal_transactions (tx_id, idempotency_key, tx_kind, description, metadata_json, result_json, created_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)`,
        [
          txId,
          input.idempotencyKey,
          input.txKind,
          input.description,
          JSON.stringify(input.metadata ?? {}),
          input.resultToStore !== undefined ? JSON.stringify(input.resultToStore) : null,
          now,
        ],
      );

      // Sort postings deterministically by (accountCode, currency) to eliminate lock-order deadlocks
      const sorted = [...input.postings]
        .filter((p) => p.debit > 0 || p.credit > 0)
        .sort((a, b) =>
          `${a.accountCode}:${a.currency}`.localeCompare(`${b.accountCode}:${b.currency}`),
        );

      for (const p of sorted) {
        const cur = p.currency.toUpperCase();
        const dec = getCurrencyDecimals(cur, p.decimals);

        const acctRes = await client.query<{
          debit_total: string | number;
          credit_total: string | number;
          account_type: AccountType;
        }>(
          `INSERT INTO accounts (account_code, currency, decimals, account_type, debit_total, credit_total)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (account_code, currency) DO UPDATE SET
             debit_total = accounts.debit_total + EXCLUDED.debit_total,
             credit_total = accounts.credit_total + EXCLUDED.credit_total
           RETURNING debit_total, credit_total, account_type`,
          [p.accountCode, cur, dec, p.accountType, p.debit, p.credit],
        );

        const updated = acctRes.rows[0]!;
        if (updated.account_type === 'liability' || updated.account_type === 'revenue') {
          const net = BigInt(updated.credit_total) - BigInt(updated.debit_total);
          if (net < 0n) {
            throw new Error(
              `ERR_INSUFFICIENT_FUNDS: Account ${p.accountCode} (${cur}) balance would become ${net.toString()}`,
            );
          }
        }

        await client.query(
          `INSERT INTO journal_entries (tx_id, account_code, account_type, currency, decimals, debit, credit, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [txId, p.accountCode, p.accountType, cur, dec, p.debit, p.credit, now],
        );
      }

      await client.query('COMMIT');
      return { txId, deduplicated: false };
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async getAccountBalance(accountCode: string, currency: string): Promise<number> {
    const res = await this.pool.query<{
      account_type: AccountType;
      debit_total: string | number;
      credit_total: string | number;
    }>(
      'SELECT account_type, debit_total, credit_total FROM accounts WHERE account_code = $1 AND currency = $2',
      [accountCode, currency.toUpperCase()],
    );
    const row = res.rows[0];
    if (!row) return 0;
    const d = Number(row.debit_total);
    const c = Number(row.credit_total);
    return row.account_type === 'asset' ? d - c : c - d;
  }

  async verifyIntegrity(): Promise<{ balanced: boolean; currencies: Record<string, { debit: number; credit: number }> }> {
    const res = await this.pool.query<{ currency: string; total_debit: string | number; total_credit: string | number }>(
      'SELECT currency, SUM(debit) AS total_debit, SUM(credit) AS total_credit FROM journal_entries GROUP BY currency',
    );
    let balanced = true;
    const currencies: Record<string, { debit: number; credit: number }> = {};
    for (const r of res.rows) {
      const d = Number(r.total_debit);
      const c = Number(r.total_credit);
      currencies[r.currency] = { debit: d, credit: c };
      if (d !== c) balanced = false;
    }
    return { balanced, currencies };
  }
}
