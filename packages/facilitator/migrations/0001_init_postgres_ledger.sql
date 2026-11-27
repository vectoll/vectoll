-- Vectoll Production PostgreSQL Double-Entry Ledger Migration (0001)
-- Enforces integer minor-unit accounting, non-negative liability balances,
-- and commit-time deferred SUM(debit) == SUM(credit) transaction invariants.

BEGIN;

CREATE TABLE IF NOT EXISTS accounts (
  account_code  TEXT        NOT NULL,
  currency      TEXT        NOT NULL,
  decimals      SMALLINT    NOT NULL CHECK (decimals >= 0 AND decimals <= 18),
  account_type  TEXT        NOT NULL CHECK (account_type IN ('asset', 'liability', 'revenue')),
  debit_total   BIGINT      NOT NULL DEFAULT 0 CHECK (debit_total >= 0),
  credit_total  BIGINT      NOT NULL DEFAULT 0 CHECK (credit_total >= 0),
  PRIMARY KEY (account_code, currency),
  CONSTRAINT chk_non_negative_liability CHECK (
    account_type = 'asset' OR credit_total >= debit_total
  )
);

CREATE TABLE IF NOT EXISTS journal_transactions (
  tx_id           TEXT        PRIMARY KEY,
  idempotency_key TEXT        NOT NULL UNIQUE,
  tx_kind         TEXT        NOT NULL,
  description     TEXT        NOT NULL,
  metadata_json   JSONB       NOT NULL DEFAULT '{}'::jsonb,
  result_json     JSONB,
  created_at      BIGINT      NOT NULL
);

CREATE TABLE IF NOT EXISTS journal_entries (
  id            BIGSERIAL   PRIMARY KEY,
  tx_id         TEXT        NOT NULL REFERENCES journal_transactions(tx_id) ON DELETE RESTRICT,
  account_code  TEXT        NOT NULL,
  account_type  TEXT        NOT NULL CHECK (account_type IN ('asset', 'liability', 'revenue')),
  currency      TEXT        NOT NULL,
  decimals      SMALLINT    NOT NULL,
  debit         BIGINT      NOT NULL CHECK (debit >= 0),
  credit        BIGINT      NOT NULL CHECK (credit >= 0),
  created_at    BIGINT      NOT NULL,
  CONSTRAINT chk_single_sided_entry CHECK (NOT (debit > 0 AND credit > 0))
);

CREATE INDEX IF NOT EXISTS idx_journal_entries_tx_id ON journal_entries(tx_id);

-- Deferred commit-time trigger enforcing SUM(debit) == SUM(credit) per currency on every tx
CREATE OR REPLACE FUNCTION verify_vectoll_tx_balance() RETURNS TRIGGER AS $$
DECLARE
  rec RECORD;
BEGIN
  FOR rec IN
    SELECT currency, SUM(debit) AS d_sum, SUM(credit) AS c_sum
    FROM journal_entries
    WHERE tx_id = NEW.tx_id
    GROUP BY currency
  LOOP
    IF rec.d_sum <> rec.c_sum THEN
      RAISE EXCEPTION 'LEDGER_IMBALANCE on tx % (%): debit % != credit %',
        NEW.tx_id, rec.currency, rec.d_sum, rec.c_sum;
    END IF;
  END LOOP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_verify_vectoll_tx_balance ON journal_entries;
CREATE CONSTRAINT TRIGGER trg_verify_vectoll_tx_balance
  AFTER INSERT ON journal_entries
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION verify_vectoll_tx_balance();

CREATE TABLE IF NOT EXISTS revoked_mandates (
  mandate_id    TEXT PRIMARY KEY,
  principal_id  TEXT NOT NULL,
  reason        TEXT NOT NULL,
  revoked_at    BIGINT NOT NULL
);

COMMIT;
