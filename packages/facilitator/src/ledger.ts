import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { assertSafeMinorAmount, getCurrencyDecimals, randomId } from '@vectoll/core';

export type AccountType = 'asset' | 'liability' | 'revenue';

export interface JournalPostingInput {
  accountCode: string;
  accountType: AccountType;
  currency: string;
  decimals?: number;
  debit: number;
  credit: number;
}

export interface JournalEntryRow {
  id: number;
  txId: string;
  idempotencyKey: string;
  txKind: string;
  accountCode: string;
  accountType: AccountType;
  currency: string;
  decimals: number;
  debit: number;
  credit: number;
  description: string;
  createdAt: number;
}

export interface EscrowRecord {
  escrowId: string;
  challengeId: string;
  agentId: string;
  service: string;
  amount: number;
  currency: string;
  decimals: number;
  rail: string;
  status: 'AUTHORIZED' | 'SETTLED' | 'REFUNDED' | 'DISPUTED';
  fulfillmentRef: string | null;
  createdAt: number;
  updatedAt: number;
}

export interface HitlRecord {
  approvalId: string;
  challengeId: string;
  agentId: string;
  service: string;
  resource: string;
  method: string;
  reqHash: string;
  amount: number;
  currency: string;
  decimals: number;
  settlementMode: 'instant' | 'escrow';
  rail: string;
  walletCurrency: string;
  mandateId: string | null;
  status: 'PENDING_HITL' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
  vrtToken: string | null;
  reason: string;
  createdAt: number;
  expiresAt: number;
  decidedAt: number | null;
}

export class DoubleEntryLedger {
  readonly db: DatabaseSync;

  constructor(dbPath = ':memory:') {
    if (dbPath !== ':memory:') {
      fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
    }
    this.db = new DatabaseSync(dbPath);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      PRAGMA foreign_keys = ON;

      CREATE TABLE IF NOT EXISTS accounts (
        account_code TEXT NOT NULL,
        currency TEXT NOT NULL,
        decimals INTEGER NOT NULL,
        account_type TEXT NOT NULL,
        debit_total INTEGER NOT NULL DEFAULT 0,
        credit_total INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (account_code, currency)
      );

      CREATE TABLE IF NOT EXISTS journal_transactions (
        tx_id TEXT PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        tx_kind TEXT NOT NULL,
        description TEXT NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        result_json TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS journal_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tx_id TEXT NOT NULL REFERENCES journal_transactions(tx_id),
        account_code TEXT NOT NULL,
        account_type TEXT NOT NULL,
        currency TEXT NOT NULL,
        decimals INTEGER NOT NULL,
        debit INTEGER NOT NULL,
        credit INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS mandate_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mandate_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        amount INTEGER NOT NULL,
        currency TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS revoked_mandates (
        mandate_id TEXT PRIMARY KEY,
        principal_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        revoked_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS merchants (
        merchant_id TEXT PRIMARY KEY,
        org_name TEXT NOT NULL,
        service_name TEXT NOT NULL UNIQUE,
        webhook_url TEXT,
        payout_account TEXT,
        domain_verify_token TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS merchant_api_keys (
        key_id TEXT PRIMARY KEY,
        merchant_id TEXT NOT NULL REFERENCES merchants(merchant_id),
        key_prefix TEXT NOT NULL,
        key_hash_sha256 TEXT NOT NULL UNIQUE,
        scopes_json TEXT NOT NULL,
        revoked_at INTEGER,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS federation_peers (
        peer_id TEXT PRIMARY KEY,
        issuer_url TEXT NOT NULL UNIQUE,
        kid TEXT NOT NULL,
        public_key_b64url TEXT NOT NULL,
        credit_limit_usd_micro INTEGER NOT NULL DEFAULT 1000000000,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS discovery_services (
        base_url TEXT PRIMARY KEY,
        service_name TEXT NOT NULL,
        description TEXT NOT NULL,
        mcp_endpoint TEXT,
        facilitator_url TEXT NOT NULL,
        accepted_rails_json TEXT NOT NULL,
        manifest_json TEXT NOT NULL,
        last_indexed_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS discovery_tools (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        base_url TEXT NOT NULL REFERENCES discovery_services(base_url) ON DELETE CASCADE,
        service_name TEXT NOT NULL,
        route_path TEXT NOT NULL,
        http_method TEXT NOT NULL,
        mcp_tool_name TEXT,
        description TEXT NOT NULL,
        amount INTEGER NOT NULL,
        currency TEXT NOT NULL,
        decimals INTEGER NOT NULL,
        price_usd_micro INTEGER NOT NULL,
        accepted_rails_json TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS escrows (
        escrow_id TEXT PRIMARY KEY,
        challenge_id TEXT NOT NULL UNIQUE,
        agent_id TEXT NOT NULL,
        service TEXT NOT NULL,
        amount INTEGER NOT NULL,
        currency TEXT NOT NULL,
        decimals INTEGER NOT NULL,
        rail TEXT NOT NULL,
        status TEXT NOT NULL,
        fulfillment_ref TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS hitl_approvals (
        approval_id TEXT PRIMARY KEY,
        challenge_id TEXT NOT NULL UNIQUE,
        agent_id TEXT NOT NULL,
        service TEXT NOT NULL,
        resource TEXT NOT NULL,
        method TEXT NOT NULL,
        req_hash TEXT NOT NULL,
        amount INTEGER NOT NULL,
        currency TEXT NOT NULL,
        decimals INTEGER NOT NULL,
        settlement_mode TEXT NOT NULL,
        rail TEXT NOT NULL,
        wallet_currency TEXT NOT NULL,
        mandate_id TEXT,
        status TEXT NOT NULL,
        vrt_token TEXT,
        reason TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        decided_at INTEGER
      );

      CREATE TABLE IF NOT EXISTS telemetry_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        service TEXT NOT NULL,
        route TEXT NOT NULL,
        agent_id TEXT,
        rail TEXT,
        amount INTEGER NOT NULL DEFAULT 0,
        currency TEXT NOT NULL DEFAULT 'USD',
        latency_ms REAL NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );
    `);
  }

  runSerializable<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // ignore rollback error if already rolled back
      }
      throw err;
    }
  }

  getExistingResult<T>(idempotencyKey: string): T | null {
    const row = this.db
      .prepare('SELECT result_json FROM journal_transactions WHERE idempotency_key = ?')
      .get(idempotencyKey) as { result_json: string | null } | undefined;
    if (!row?.result_json) return null;
    return JSON.parse(row.result_json) as T;
  }

  /**
   * Posts a balanced double-entry journal batch inside the caller's transaction (or creates one).
   * Enforces:
   * 1. sum(debits) === sum(credits) per currency
   * 2. Liability/Revenue balances (credit - debit) >= 0
   */
  postJournal(input: {
    idempotencyKey: string;
    txKind: string;
    description: string;
    postings: JournalPostingInput[];
    metadata?: Record<string, unknown>;
    resultToStore?: unknown;
    nowSeconds?: number;
    inExistingTransaction?: boolean;
  }): string {
    const exec = (): string => {
      const existing = this.db
        .prepare('SELECT tx_id FROM journal_transactions WHERE idempotency_key = ?')
        .get(input.idempotencyKey) as { tx_id: string } | undefined;
      if (existing) return existing.tx_id;

      if (input.postings.length < 2) {
        throw new Error('Double-entry transaction requires at least 2 postings');
      }

      const sumsByCurrency = new Map<string, { debit: bigint; credit: bigint }>();
      for (const p of input.postings) {
        assertSafeMinorAmount(p.debit, 'posting.debit');
        assertSafeMinorAmount(p.credit, 'posting.credit');
        if (p.debit === 0 && p.credit === 0) continue;
        if (p.debit > 0 && p.credit > 0) {
          throw new Error(`Posting on ${p.accountCode} cannot have both debit and credit > 0`);
        }
        const cur = p.currency.toUpperCase();
        const curSum = sumsByCurrency.get(cur) ?? { debit: 0n, credit: 0n };
        curSum.debit += BigInt(p.debit);
        curSum.credit += BigInt(p.credit);
        sumsByCurrency.set(cur, curSum);
      }

      for (const [cur, totals] of sumsByCurrency.entries()) {
        if (totals.debit !== totals.credit) {
          throw new Error(
            `LEDGER_IMBALANCE in ${cur}: debit=${totals.debit.toString()} !== credit=${totals.credit.toString()}`,
          );
        }
      }

      const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
      const txId = randomId('jtx', 10);

      this.db
        .prepare(
          `INSERT INTO journal_transactions (tx_id, idempotency_key, tx_kind, description, metadata_json, result_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          txId,
          input.idempotencyKey,
          input.txKind,
          input.description,
          JSON.stringify(input.metadata ?? {}),
          input.resultToStore !== undefined ? JSON.stringify(input.resultToStore) : null,
          now,
        );

      const upsertAcct = this.db.prepare(`
        INSERT INTO accounts (account_code, currency, decimals, account_type, debit_total, credit_total)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(account_code, currency) DO UPDATE SET
          debit_total = debit_total + excluded.debit_total,
          credit_total = credit_total + excluded.credit_total
      `);

      const getAcct = this.db.prepare(
        'SELECT debit_total, credit_total, account_type FROM accounts WHERE account_code = ? AND currency = ?',
      );

      const insertEntry = this.db.prepare(`
        INSERT INTO journal_entries (tx_id, account_code, account_type, currency, decimals, debit, credit, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const p of input.postings) {
        if (p.debit === 0 && p.credit === 0) continue;
        const cur = p.currency.toUpperCase();
        const dec = getCurrencyDecimals(cur, p.decimals);
        upsertAcct.run(p.accountCode, cur, dec, p.accountType, p.debit, p.credit);

        const updated = getAcct.get(p.accountCode, cur) as {
          debit_total: number;
          credit_total: number;
          account_type: AccountType;
        };

        if (updated.account_type === 'liability' || updated.account_type === 'revenue') {
          const netCredit = updated.credit_total - updated.debit_total;
          if (netCredit < 0) {
            throw new Error(
              `ERR_INSUFFICIENT_FUNDS: Account ${p.accountCode} (${cur}) balance would become ${netCredit}`,
            );
          }
        }

        insertEntry.run(txId, p.accountCode, p.accountType, cur, dec, p.debit, p.credit, now);
      }

      return txId;
    };

    return input.inExistingTransaction ? exec() : this.runSerializable(exec);
  }

  setTransactionResult(txId: string, result: unknown): void {
    this.db
      .prepare('UPDATE journal_transactions SET result_json = ? WHERE tx_id = ?')
      .run(JSON.stringify(result), txId);
  }

  getAccountBalance(accountCode: string, currency: string): number {
    const row = this.db
      .prepare('SELECT account_type, debit_total, credit_total FROM accounts WHERE account_code = ? AND currency = ?')
      .get(accountCode, currency.toUpperCase()) as
      | { account_type: AccountType; debit_total: number; credit_total: number }
      | undefined;
    if (!row) return 0;
    return row.account_type === 'asset'
      ? row.debit_total - row.credit_total
      : row.credit_total - row.debit_total;
  }

  getWalletBalances(agentId: string): Array<{ currency: string; decimals: number; balance: number }> {
    const prefix = `liability:agent_float:${agentId}`;
    const rows = this.db
      .prepare(
        'SELECT currency, decimals, (credit_total - debit_total) AS balance FROM accounts WHERE account_code = ? ORDER BY currency',
      )
      .all(prefix) as Array<{ currency: string; decimals: number; balance: number }>;
    return rows;
  }

  getMandateSpendLast24h(mandateId: string, currency: string, nowSeconds = Math.floor(Date.now() / 1000)): number {
    const cutoff = nowSeconds - 86400;
    const row = this.db
      .prepare(
        'SELECT COALESCE(SUM(amount), 0) AS spent FROM mandate_usage WHERE mandate_id = ? AND currency = ? AND created_at >= ?',
      )
      .get(mandateId, currency.toUpperCase(), cutoff) as { spent: number };
    return row.spent;
  }

  recordMandateSpend(mandateId: string, agentId: string, amount: number, currency: string, nowSeconds: number): void {
    this.db
      .prepare(
        'INSERT INTO mandate_usage (mandate_id, agent_id, amount, currency, created_at) VALUES (?, ?, ?, ?, ?)',
      )
      .run(mandateId, agentId, amount, currency.toUpperCase(), nowSeconds);
  }

  revokeMandate(mandateId: string, principalId: string, reason = 'revoked_by_principal', nowSeconds = Math.floor(Date.now() / 1000)): void {
    this.db
      .prepare(
        `INSERT INTO revoked_mandates (mandate_id, principal_id, reason, revoked_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(mandate_id) DO NOTHING`,
      )
      .run(mandateId, principalId, reason, nowSeconds);
  }

  isMandateRevoked(mandateId: string): boolean {
    const row = this.db
      .prepare('SELECT mandate_id FROM revoked_mandates WHERE mandate_id = ?')
      .get(mandateId);
    return Boolean(row);
  }

  listRevokedMandates(): Array<{ mandateId: string; principalId: string; reason: string; revokedAt: number }> {
    return this.db
      .prepare(
        'SELECT mandate_id AS mandateId, principal_id AS principalId, reason, revoked_at AS revokedAt FROM revoked_mandates ORDER BY revoked_at DESC',
      )
      .all() as Array<{ mandateId: string; principalId: string; reason: string; revokedAt: number }>;
  }

  verifyIntegrity(): { balanced: boolean; currencies: Record<string, { debit: number; credit: number }> } {
    const rows = this.db
      .prepare(
        'SELECT currency, SUM(debit) AS total_debit, SUM(credit) AS total_credit FROM journal_entries GROUP BY currency',
      )
      .all() as Array<{ currency: string; total_debit: number; total_credit: number }>;

    let balanced = true;
    const currencies: Record<string, { debit: number; credit: number }> = {};
    for (const r of rows) {
      currencies[r.currency] = { debit: r.total_debit, credit: r.total_credit };
      if (r.total_debit !== r.total_credit) balanced = false;
    }
    return { balanced, currencies };
  }

  listJournalEntries(limit = 100): JournalEntryRow[] {
    return this.db
      .prepare(
        `SELECT
           e.id,
           e.tx_id AS txId,
           t.idempotency_key AS idempotencyKey,
           t.tx_kind AS txKind,
           e.account_code AS accountCode,
           e.account_type AS accountType,
           e.currency,
           e.decimals,
           e.debit,
           e.credit,
           t.description,
           e.created_at AS createdAt
         FROM journal_entries e
         JOIN journal_transactions t ON t.tx_id = e.tx_id
         ORDER BY e.id DESC
         LIMIT ?`,
      )
      .all(limit) as unknown as JournalEntryRow[];
  }

  exportCsv(limit = 1000): string {
    const rows = this.listJournalEntries(limit);
    const header = 'id,tx_id,tx_kind,account_code,account_type,currency,decimals,debit,credit,description,created_at';
    const escape = (v: string | number) => {
      const s = String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const lines = rows.map((r) =>
      [
        r.id,
        r.txId,
        r.txKind,
        r.accountCode,
        r.accountType,
        r.currency,
        r.decimals,
        r.debit,
        r.credit,
        r.description,
        r.createdAt,
      ]
        .map(escape)
        .join(','),
    );
    return [header, ...lines].join('\n') + '\n';
  }

  recordTelemetry(ev: {
    eventType: string;
    service: string;
    route: string;
    agentId?: string;
    rail?: string;
    amount?: number;
    currency?: string;
    latencyMs?: number;
  }): void {
    this.db
      .prepare(
        `INSERT INTO telemetry_events (event_type, service, route, agent_id, rail, amount, currency, latency_ms, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        ev.eventType,
        ev.service,
        ev.route,
        ev.agentId ?? null,
        ev.rail ?? null,
        ev.amount ?? 0,
        (ev.currency ?? 'UGX').toUpperCase(),
        ev.latencyMs ?? 0,
        Math.floor(Date.now() / 1000),
      );
  }

  close(): void {
    this.db.close();
  }
}
