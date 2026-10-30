-- TEST ONLY: run exclusively after fixed endpoint/server/freshness guards in fixture.ts.
-- Synthetic GUCs model trusted identity, not Supabase JWT verification or a product adapter.
CREATE ROLE jls_command_actor NOSUPERUSER NOBYPASSRLS NOLOGIN NOINHERIT;
CREATE SCHEMA jls_command_proof;
REVOKE ALL ON SCHEMA jls_command_proof FROM PUBLIC;
CREATE TABLE jls_command_proof.fixture_marker (marker text PRIMARY KEY CHECK (marker = 'jls-command-proof-v1'));
INSERT INTO jls_command_proof.fixture_marker VALUES ('jls-command-proof-v1');
CREATE TABLE jls_command_proof.owners (
  owner_id uuid PRIMARY KEY, active boolean NOT NULL, current_epoch uuid NOT NULL, lock_token integer NOT NULL DEFAULT 0
);
CREATE TABLE jls_command_proof.datasets (
  owner_id uuid NOT NULL REFERENCES jls_command_proof.owners(owner_id), dataset_epoch uuid NOT NULL,
  active boolean NOT NULL, lock_token integer NOT NULL DEFAULT 0,
  PRIMARY KEY (owner_id, dataset_epoch)
);
CREATE TABLE jls_command_proof.aggregates (
  owner_id uuid NOT NULL, dataset_epoch uuid NOT NULL, aggregate_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version BETWEEN 0 AND 9007199254740991),
  state text NOT NULL CHECK (state IN ('open', 'closed')), content text NOT NULL,
  PRIMARY KEY (owner_id, dataset_epoch, aggregate_id),
  FOREIGN KEY (owner_id, dataset_epoch) REFERENCES jls_command_proof.datasets(owner_id, dataset_epoch)
);
CREATE TABLE jls_command_proof.receipts (
  owner_id uuid NOT NULL, dataset_epoch uuid NOT NULL, operation_id uuid NOT NULL, aggregate_id uuid NOT NULL,
  policy text NOT NULL, fingerprint text NOT NULL, receipt jsonb NOT NULL,
  PRIMARY KEY (owner_id, dataset_epoch, operation_id),
  FOREIGN KEY (owner_id, dataset_epoch, aggregate_id) REFERENCES jls_command_proof.aggregates(owner_id, dataset_epoch, aggregate_id)
);
CREATE TABLE jls_command_proof.outbox (
  owner_id uuid NOT NULL, dataset_epoch uuid NOT NULL, operation_id uuid NOT NULL, aggregate_id uuid NOT NULL,
  acknowledgement jsonb NOT NULL,
  PRIMARY KEY (owner_id, dataset_epoch, operation_id),
  FOREIGN KEY (owner_id, dataset_epoch, aggregate_id) REFERENCES jls_command_proof.aggregates(owner_id, dataset_epoch, aggregate_id)
);
CREATE TABLE jls_command_proof.proposals (
  owner_id uuid NOT NULL, dataset_epoch uuid NOT NULL, proposal_id uuid NOT NULL, operation_id uuid NOT NULL, aggregate_id uuid NOT NULL,
  proposed_content text NOT NULL,
  PRIMARY KEY (owner_id, dataset_epoch, proposal_id), UNIQUE (owner_id, dataset_epoch, operation_id),
  FOREIGN KEY (owner_id, dataset_epoch, aggregate_id) REFERENCES jls_command_proof.aggregates(owner_id, dataset_epoch, aggregate_id)
);
GRANT USAGE ON SCHEMA jls_command_proof TO jls_command_actor;
GRANT SELECT ON jls_command_proof.owners, jls_command_proof.datasets, jls_command_proof.aggregates, jls_command_proof.receipts, jls_command_proof.outbox, jls_command_proof.proposals TO jls_command_actor;
-- PG requires UPDATE privilege on at least one column for row locking. A harmless lock token
-- grants that capability without allowing active/current_epoch updates. No UPDATE policy exists.
GRANT UPDATE (lock_token) ON jls_command_proof.owners, jls_command_proof.datasets TO jls_command_actor;
GRANT UPDATE (version, state, content) ON jls_command_proof.aggregates TO jls_command_actor;
GRANT INSERT ON jls_command_proof.receipts, jls_command_proof.outbox, jls_command_proof.proposals TO jls_command_actor;
ALTER TABLE jls_command_proof.owners ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_command_proof.owners FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_read ON jls_command_proof.owners FOR SELECT TO jls_command_actor
USING (owner_id::text = nullif(current_setting('jls.subject', true), '') AND active);
ALTER TABLE jls_command_proof.datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_command_proof.datasets FORCE ROW LEVEL SECURITY;
CREATE POLICY dataset_read ON jls_command_proof.datasets FOR SELECT TO jls_command_actor
USING (owner_id::text = nullif(current_setting('jls.subject', true), '') AND dataset_epoch::text = nullif(current_setting('jls.epoch', true), '') AND active
AND EXISTS (SELECT 1 FROM jls_command_proof.owners o WHERE o.owner_id = datasets.owner_id AND o.active AND o.current_epoch = datasets.dataset_epoch));
ALTER TABLE jls_command_proof.aggregates ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_command_proof.aggregates FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_command_proof.receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_command_proof.receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_command_proof.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_command_proof.outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_command_proof.proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_command_proof.proposals FORCE ROW LEVEL SECURITY;
CREATE POLICY aggregate_scope ON jls_command_proof.aggregates TO jls_command_actor
USING (EXISTS (SELECT 1 FROM jls_command_proof.datasets d WHERE d.owner_id = aggregates.owner_id AND d.dataset_epoch = aggregates.dataset_epoch))
WITH CHECK (EXISTS (SELECT 1 FROM jls_command_proof.datasets d WHERE d.owner_id = aggregates.owner_id AND d.dataset_epoch = aggregates.dataset_epoch));
CREATE POLICY receipt_scope ON jls_command_proof.receipts TO jls_command_actor
USING (EXISTS (SELECT 1 FROM jls_command_proof.datasets d WHERE d.owner_id = receipts.owner_id AND d.dataset_epoch = receipts.dataset_epoch))
WITH CHECK (EXISTS (SELECT 1 FROM jls_command_proof.datasets d WHERE d.owner_id = receipts.owner_id AND d.dataset_epoch = receipts.dataset_epoch));
CREATE POLICY outbox_scope ON jls_command_proof.outbox TO jls_command_actor
USING (EXISTS (SELECT 1 FROM jls_command_proof.datasets d WHERE d.owner_id = outbox.owner_id AND d.dataset_epoch = outbox.dataset_epoch))
WITH CHECK (EXISTS (SELECT 1 FROM jls_command_proof.datasets d WHERE d.owner_id = outbox.owner_id AND d.dataset_epoch = outbox.dataset_epoch));
CREATE POLICY proposal_scope ON jls_command_proof.proposals TO jls_command_actor
USING (EXISTS (SELECT 1 FROM jls_command_proof.datasets d WHERE d.owner_id = proposals.owner_id AND d.dataset_epoch = proposals.dataset_epoch))
WITH CHECK (EXISTS (SELECT 1 FROM jls_command_proof.datasets d WHERE d.owner_id = proposals.owner_id AND d.dataset_epoch = proposals.dataset_epoch));
-- Locking SELECTs may also require UPDATE USING policy. WITH CHECK false denies even lock-token writes.
CREATE POLICY owner_lock ON jls_command_proof.owners FOR UPDATE TO jls_command_actor
USING (owner_id::text = nullif(current_setting('jls.subject', true), '') AND active) WITH CHECK (false);
CREATE POLICY dataset_lock ON jls_command_proof.datasets FOR UPDATE TO jls_command_actor
USING (owner_id::text = nullif(current_setting('jls.subject', true), '') AND dataset_epoch::text = nullif(current_setting('jls.epoch', true), '') AND active
AND EXISTS (SELECT 1 FROM jls_command_proof.owners o WHERE o.owner_id = datasets.owner_id AND o.active AND o.current_epoch = datasets.dataset_epoch)) WITH CHECK (false);
