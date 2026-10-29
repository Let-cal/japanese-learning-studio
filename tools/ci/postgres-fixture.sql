-- Synthetic PostgreSQL behavior check; never application migrations or Supabase proof.
\set ON_ERROR_STOP on
BEGIN;
DO $$
BEGIN
  IF current_database() <> 'task0_fixture'
     OR session_user <> 'fixture_admin' THEN
    RAISE EXCEPTION 'Disposable fixture connection required';
  END IF;
END $$;
CREATE ROLE task0_reader NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE SCHEMA task0;
CREATE TABLE task0.notes (owner_id text NOT NULL, body text NOT NULL);
INSERT INTO task0.notes VALUES ('owner_a', 'synthetic a'), ('owner_b', 'synthetic b');
ALTER TABLE task0.notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE task0.notes FORCE ROW LEVEL SECURITY;
GRANT USAGE ON SCHEMA task0 TO task0_reader;
GRANT SELECT, INSERT ON task0.notes TO task0_reader;
CREATE POLICY owner_isolation ON task0.notes TO task0_reader
  USING (owner_id = current_setting('task0.owner'))
  WITH CHECK (owner_id = current_setting('task0.owner'));
SET LOCAL ROLE task0_reader;
SET LOCAL task0.owner = 'owner_a';
DO $$
BEGIN
  IF (SELECT count(*) FROM task0.notes) <> 1
     OR (SELECT owner_id FROM task0.notes) <> 'owner_a' THEN
    RAISE EXCEPTION 'SELECT isolation failed';
  END IF;
  BEGIN
    INSERT INTO task0.notes VALUES ('owner_b', 'must be denied');
    RAISE EXCEPTION 'Cross-owner INSERT unexpectedly succeeded';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL; -- Expected RLS denial; every other error fails the fixture.
  END;
END $$;
SET LOCAL task0.owner = 'owner_b';
DO $$
BEGIN
  IF (SELECT count(*) FROM task0.notes) <> 1
     OR (SELECT owner_id FROM task0.notes) <> 'owner_b' THEN
    RAISE EXCEPTION 'Second owner SELECT isolation failed';
  END IF;
  INSERT INTO task0.notes VALUES ('owner_b', 'permitted synthetic insert');
END $$;
RESET ROLE;
ROLLBACK;
