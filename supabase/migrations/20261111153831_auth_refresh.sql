-- Durable refresh and local-scope cleanup. Keep jls_auth out of exposed_schemas.
BEGIN;

GRANT USAGE ON SCHEMA auth TO service_role;
GRANT SELECT (id,user_id,not_after) ON auth.sessions TO service_role;
DO $$
BEGIN
  IF NOT has_schema_privilege('service_role','auth','USAGE')
    OR NOT has_column_privilege('service_role','auth.sessions','id','SELECT')
    OR NOT has_column_privilege('service_role','auth.sessions','user_id','SELECT')
    OR NOT has_column_privilege('service_role','auth.sessions','not_after','SELECT')
    OR NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='service_role' AND rolbypassrls)
    THEN RAISE EXCEPTION 'Refresh requires the managed Auth session read grants and existing service_role BYPASSRLS'; END IF;
END $$;

CREATE TYPE jls_auth.refresh_binding AS (
  attempt_id uuid,
  request_fingerprint text,
  session_id uuid,
  browser_id uuid,
  browser_generation bigint,
  owner_id uuid,
  auth_subject uuid,
  upstream_session_id uuid,
  token_version bigint,
  control_version bigint,
  dataset_epoch uuid
);
REVOKE ALL ON TYPE jls_auth.refresh_binding FROM PUBLIC,anon,authenticated,service_role;
GRANT USAGE ON TYPE jls_auth.refresh_binding TO service_role;

CREATE TABLE jls_auth.refresh_attempts (
  binding jls_auth.refresh_binding NOT NULL CHECK (binding IS NOT NULL),
  attempt_id uuid GENERATED ALWAYS AS ((binding).attempt_id) STORED PRIMARY KEY,
  session_id uuid GENERATED ALWAYS AS ((binding).session_id) STORED
    REFERENCES jls_auth.app_sessions(session_id),
  claimed_at timestamptz NOT NULL,
  lease_expires_at timestamptz NOT NULL CHECK (lease_expires_at=claimed_at+interval '25 seconds'),
  transmission_intent_at timestamptz,
  state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','sent','released','unknown','committed')),
  late_pair_envelope text CHECK (late_pair_envelope IS NULL OR (octet_length(late_pair_envelope) BETWEEN 1 AND 49152
    AND late_pair_envelope ~ '^v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$')),
  CHECK ((state IN ('sent','unknown','committed'))=(transmission_intent_at IS NOT NULL)),
  CHECK (transmission_intent_at IS NULL OR transmission_intent_at>=claimed_at AND transmission_intent_at<lease_expires_at),
  CHECK (late_pair_envelope IS NULL OR state='unknown')
);
CREATE UNIQUE INDEX refresh_attempt_one_open ON jls_auth.refresh_attempts(session_id) WHERE state IN ('prepared','sent');
CREATE UNIQUE INDEX refresh_attempt_one_late_pair ON jls_auth.refresh_attempts(session_id) WHERE late_pair_envelope IS NOT NULL;

-- Typed operation payloads plus a digest of the exact encrypted pair. Keeping
-- the digest in history avoids retaining another copy of token ciphertext.
CREATE TABLE jls_auth.refresh_receipts (
  operation_id uuid PRIMARY KEY,
  attempt_id uuid NOT NULL REFERENCES jls_auth.refresh_attempts(attempt_id),
  fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  action text NOT NULL CHECK (action IN ('finish','pre_send','unknown','late_pair')),
  verified_subject uuid,
  verified_upstream_session_id uuid,
  pair_hash bytea CHECK (pair_hash IS NULL OR octet_length(pair_hash)=32),
  access_expires_at timestamptz,
  result text NOT NULL CHECK (
    (action,result) IN (('finish','committed'),('pre_send','released'),('unknown','closed'),('late_pair','late_pair_retained'))
  ),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (attempt_id,action),
  CHECK ((action IN ('finish','late_pair'))=(verified_subject IS NOT NULL)
    AND (action IN ('finish','late_pair'))=(verified_upstream_session_id IS NOT NULL)
    AND (action IN ('finish','late_pair'))=(pair_hash IS NOT NULL)
    AND (action='finish')=(access_expires_at IS NOT NULL))
);
ALTER TABLE jls_auth.refresh_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.refresh_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.refresh_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.refresh_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY service_control ON jls_auth.refresh_attempts TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.refresh_receipts TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON jls_auth.refresh_attempts,jls_auth.refresh_receipts FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT ON jls_auth.refresh_attempts,jls_auth.refresh_receipts TO service_role;
GRANT INSERT (binding,claimed_at,lease_expires_at) ON jls_auth.refresh_attempts TO service_role;
GRANT UPDATE (state,transmission_intent_at,late_pair_envelope) ON jls_auth.refresh_attempts TO service_role;
GRANT INSERT (operation_id,attempt_id,fingerprint,action,verified_subject,verified_upstream_session_id,pair_hash,access_expires_at,result)
  ON jls_auth.refresh_receipts TO service_role;
GRANT UPDATE (token_envelope,access_expires_at) ON jls_auth.session_credentials TO service_role;

ALTER TABLE jls_auth.cleanup_work
  ADD COLUMN revision bigint NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 9007199254740990),
  ADD COLUMN claim_revision bigint CHECK (claim_revision>=0 AND claim_revision<=revision),
  ADD COLUMN claim_history uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(claim_history)<=3);
-- Preserve any existing cleanup counters and prior claim ID.
UPDATE jls_auth.cleanup_work SET claim_revision=revision,claim_history=ARRAY[claim_id] WHERE claim_id IS NOT NULL;
GRANT UPDATE (token_envelope,state,attempts,claim_id,lease_expires_at,error_category,revision,claim_revision,claim_history)
  ON jls_auth.cleanup_work TO service_role;

CREATE FUNCTION jls_auth.refresh_lock(p_session_secret_hash text,p_browser_secret_hash text,p_binding jls_auth.refresh_binding)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
BEGIN
  IF NOT (p_binding IS NOT NULL)
    OR p_session_secret_hash IS NULL OR p_session_secret_hash !~ '^[0-9a-f]{64}$'
    OR p_browser_secret_hash IS NULL OR p_browser_secret_hash !~ '^[0-9a-f]{64}$'
    OR (p_binding).request_fingerprint !~ '^[0-9a-f]{64}$'
    OR (p_binding).browser_generation NOT BETWEEN 0 AND 9007199254740990
    OR (p_binding).token_version NOT BETWEEN 0 AND 9007199254740990
    OR (p_binding).control_version NOT BETWEEN 0 AND 9007199254740991
    THEN RETURN false; END IF;
  PERFORM browser_id FROM jls_auth.browser_bindings
    WHERE browser_id=(p_binding).browser_id AND secret_hash=p_browser_secret_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  -- Discovery is read-only. Bind the owner lock to this exact authenticated app session.
  PERFORM session_id FROM jls_auth.app_sessions
    WHERE session_id=(p_binding).session_id AND secret_hash=p_session_secret_hash
      AND browser_id=(p_binding).browser_id AND browser_generation=(p_binding).browser_generation
      AND owner_id=(p_binding).owner_id AND auth_subject=(p_binding).auth_subject AND upstream_session_id=(p_binding).upstream_session_id;
  IF NOT FOUND THEN RETURN false; END IF;
  PERFORM owner_id FROM jls_auth.owner_control WHERE owner_id=(p_binding).owner_id FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  PERFORM session_id FROM jls_auth.app_sessions
    WHERE session_id=(p_binding).session_id AND secret_hash=p_session_secret_hash
      AND browser_id=(p_binding).browser_id AND browser_generation=(p_binding).browser_generation
      AND owner_id=(p_binding).owner_id AND auth_subject=(p_binding).auth_subject AND upstream_session_id=(p_binding).upstream_session_id
    FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  PERFORM session_id FROM jls_auth.session_credentials WHERE session_id=(p_binding).session_id FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  PERFORM attempt_id FROM jls_auth.refresh_attempts
    WHERE session_id=(p_binding).session_id AND attempt_id=(p_binding).attempt_id FOR UPDATE;
  RETURN true;
END $$;

-- Call with the bound application rows locked and a clock read after all waits.
CREATE FUNCTION jls_auth.refresh_app_current(p_binding jls_auth.refresh_binding,p_now timestamptz)
RETURNS boolean LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$
  SELECT EXISTS (
    SELECT FROM jls_auth.app_sessions s
      JOIN jls_auth.browser_bindings b ON b.browser_id=s.browser_id
      JOIN jls_auth.owner_control o ON o.owner_id=s.owner_id
    WHERE s.session_id=(p_binding).session_id AND s.revoked_at IS NULL
      AND s.created_at<=p_now AND s.created_at>p_now-interval '7 days'
      AND s.last_activity_at<=p_now AND s.last_activity_at>p_now-interval '24 hours'
      AND b.current_session_id=s.session_id AND b.generation=(p_binding).browser_generation AND b.expires_at>p_now
      AND o.active AND o.auth_subject=(p_binding).auth_subject
      AND o.control_version=(p_binding).control_version AND o.current_dataset_epoch=(p_binding).dataset_epoch
  )
$$;

CREATE FUNCTION jls_auth.refresh_claim(p_session_secret_hash text,p_browser_secret_hash text,p_binding jls_auth.refresh_binding)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE a jls_auth.refresh_attempts; previous jls_auth.refresh_attempts; c jls_auth.session_credentials; v_now timestamptz;
BEGIN
  IF NOT jls_auth.refresh_lock(p_session_secret_hash,p_browser_secret_hash,p_binding)
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO c FROM jls_auth.session_credentials WHERE session_id=(p_binding).session_id;
  SELECT * INTO a FROM jls_auth.refresh_attempts WHERE session_id=c.session_id AND attempt_id=(p_binding).attempt_id;
  IF c.refresh_attempt_id IS NOT NULL THEN
    IF c.refresh_attempt_id=a.attempt_id THEN
      previous:=a;
    ELSE
      SELECT * INTO previous FROM jls_auth.refresh_attempts WHERE session_id=c.session_id AND attempt_id=c.refresh_attempt_id FOR UPDATE;
    END IF;
  END IF;
  v_now:=clock_timestamp();
  IF NOT jls_auth.refresh_app_current(p_binding,v_now) OR c.token_version<>(p_binding).token_version
    OR c.token_version>=9007199254740990 OR c.access_expires_at>v_now
    OR a.attempt_id IS NOT NULL AND a.binding IS DISTINCT FROM p_binding
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF c.state IN ('sent_or_unknown','uncertain','reauthentication_required') THEN
    IF c.state='sent_or_unknown' AND previous.state='sent' AND previous.lease_expires_at>v_now
      AND c.refresh_lease_expires_at=previous.lease_expires_at
      AND c.refresh_transmission_intent_at=previous.transmission_intent_at
      AND (previous.binding).token_version=(p_binding).token_version
      AND (previous.binding).control_version=(p_binding).control_version
      AND (previous.binding).dataset_epoch=(p_binding).dataset_epoch
      THEN RETURN '{"kind":"busy"}'::jsonb; END IF;
    RETURN '{"kind":"reauthentication_required"}'::jsonb;
  END IF;
  IF a.attempt_id IS NOT NULL THEN
    IF a.state='prepared' AND c.state='prepared' AND c.refresh_attempt_id=a.attempt_id
      AND c.refresh_lease_expires_at=a.lease_expires_at AND a.lease_expires_at>v_now
      THEN RETURN jsonb_build_object('kind','claimed','attemptId',a.attempt_id,'tokenEnvelope',c.token_envelope,
        'leaseExpiresAt',floor(extract(epoch FROM a.lease_expires_at)*1000)::bigint); END IF;
    RETURN '{"kind":"denied"}'::jsonb;
  END IF;
  IF c.state='prepared' THEN
    IF previous.state IS DISTINCT FROM 'prepared' OR c.refresh_lease_expires_at IS DISTINCT FROM previous.lease_expires_at
      OR (previous.binding).token_version IS DISTINCT FROM c.token_version
      THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    IF previous.lease_expires_at>v_now THEN RETURN '{"kind":"busy"}'::jsonb; END IF;
    -- Only an expired durable prepare can be replaced. The old ID remains spent.
    UPDATE jls_auth.refresh_attempts SET state='released' WHERE attempt_id=previous.attempt_id;
    UPDATE jls_auth.session_credentials SET state='usable',refresh_attempt_id=NULL,refresh_lease_expires_at=NULL,
      refresh_transmission_intent_at=NULL WHERE session_id=c.session_id;
  ELSIF c.state<>'usable' THEN RETURN '{"kind":"denied"}'::jsonb;
  END IF;
  INSERT INTO jls_auth.refresh_attempts(binding,claimed_at,lease_expires_at)
    VALUES (p_binding,v_now,v_now+interval '25 seconds') ON CONFLICT (attempt_id) DO NOTHING RETURNING * INTO a;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  UPDATE jls_auth.session_credentials SET state='prepared',refresh_attempt_id=a.attempt_id,refresh_lease_expires_at=a.lease_expires_at
    WHERE session_id=c.session_id;
  RETURN jsonb_build_object('kind','claimed','attemptId',a.attempt_id,'tokenEnvelope',c.token_envelope,
    'leaseExpiresAt',floor(extract(epoch FROM a.lease_expires_at)*1000)::bigint);
END $$;

CREATE FUNCTION jls_auth.refresh_mark_sent(p_session_secret_hash text,p_browser_secret_hash text,p_binding jls_auth.refresh_binding)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE a jls_auth.refresh_attempts; c jls_auth.session_credentials; v_now timestamptz;
BEGIN
  IF NOT jls_auth.refresh_lock(p_session_secret_hash,p_browser_secret_hash,p_binding)
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO a FROM jls_auth.refresh_attempts WHERE attempt_id=(p_binding).attempt_id AND session_id=(p_binding).session_id;
  IF NOT FOUND OR a.binding IS DISTINCT FROM p_binding THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF a.transmission_intent_at IS NOT NULL THEN RETURN '{"kind":"already_sent"}'::jsonb; END IF;
  SELECT * INTO c FROM jls_auth.session_credentials WHERE session_id=a.session_id;
  v_now:=clock_timestamp();
  IF a.state<>'prepared' OR a.lease_expires_at<=v_now OR NOT jls_auth.refresh_app_current(p_binding,v_now)
    OR c.state<>'prepared' OR c.refresh_attempt_id IS DISTINCT FROM a.attempt_id OR c.token_version<>(p_binding).token_version
    OR c.refresh_lease_expires_at IS DISTINCT FROM a.lease_expires_at
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  UPDATE jls_auth.refresh_attempts SET state='sent',transmission_intent_at=v_now WHERE attempt_id=a.attempt_id;
  UPDATE jls_auth.session_credentials SET state='sent_or_unknown',refresh_transmission_intent_at=v_now WHERE session_id=a.session_id;
  RETURN '{"kind":"transmit"}'::jsonb;
END $$;

CREATE FUNCTION jls_auth.refresh_pair_valid(p_envelope text) RETURNS boolean
LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path='' AS $$
  SELECT coalesce(octet_length(p_envelope) BETWEEN 1 AND 49152
    AND p_envelope ~ '^v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$',false)
$$;

-- Shared receipt comparison for finish retries, lost acknowledgements and close.
-- A historical receipt does not establish that any app or upstream session is live.
CREATE FUNCTION jls_auth.refresh_result(p_attempt_id uuid,p_session_id uuid,p_version bigint,
  p_operation_id uuid,p_fingerprint text,p_action text,p_subject uuid,p_upstream_id uuid,
  p_pair_hash bytea,p_access_expires_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE r jls_auth.refresh_receipts;
BEGIN
  SELECT * INTO r FROM jls_auth.refresh_receipts WHERE operation_id=p_operation_id;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF r.attempt_id IS DISTINCT FROM p_attempt_id OR r.fingerprint IS DISTINCT FROM p_fingerprint
    OR r.action IS DISTINCT FROM p_action OR r.verified_subject IS DISTINCT FROM p_subject
    OR r.verified_upstream_session_id IS DISTINCT FROM p_upstream_id OR r.pair_hash IS DISTINCT FROM p_pair_hash
    OR r.access_expires_at IS DISTINCT FROM p_access_expires_at THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF r.result='committed' THEN
    RETURN jsonb_build_object('kind',r.result,'attemptId',r.attempt_id,'sessionId',p_session_id,'tokenVersion',p_version+1);
  END IF;
  RETURN jsonb_build_object('kind',r.result);
END $$;

CREATE FUNCTION jls_auth.refresh_finish(p_session_secret_hash text,p_browser_secret_hash text,p_binding jls_auth.refresh_binding,
  p_finish_operation_id uuid,p_finish_fingerprint text,p_verified_subject uuid,p_verified_upstream_session_id uuid,
  p_token_envelope text,p_access_expires_at timestamptz,p_resolve_only boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE a jls_auth.refresh_attempts; c jls_auth.session_credentials; v_now timestamptz; v_pair_hash bytea; v_result jsonb;
  v_upstream_expires_at timestamptz;
BEGIN
  IF p_finish_operation_id IS NULL OR p_finish_fingerprint IS NULL OR p_finish_fingerprint !~ '^[0-9a-f]{64}$'
    OR p_verified_subject IS DISTINCT FROM (p_binding).auth_subject
    OR p_verified_upstream_session_id IS DISTINCT FROM (p_binding).upstream_session_id
    OR NOT jls_auth.refresh_pair_valid(p_token_envelope) OR p_access_expires_at IS NULL OR NOT isfinite(p_access_expires_at)
    OR NOT jls_auth.refresh_lock(p_session_secret_hash,p_browser_secret_hash,p_binding)
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO a FROM jls_auth.refresh_attempts WHERE attempt_id=(p_binding).attempt_id AND session_id=(p_binding).session_id;
  IF NOT FOUND OR a.binding IS DISTINCT FROM p_binding THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  -- Serialize a reused operation UUID before any validity checks dependent on time.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('jls-auth-refresh-operation-v1:'||p_finish_operation_id::text,0));
  v_pair_hash:=sha256(convert_to(p_token_envelope,'UTF8'));
  v_result:=jls_auth.refresh_result(a.attempt_id,a.session_id,(p_binding).token_version,p_finish_operation_id,
    p_finish_fingerprint,'finish',p_verified_subject,p_verified_upstream_session_id,v_pair_hash,p_access_expires_at);
  IF v_result IS NOT NULL THEN RETURN v_result; END IF;
  IF a.state='committed' THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF p_resolve_only THEN RETURN '{"kind":"not_committed"}'::jsonb; END IF;
  SELECT * INTO c FROM jls_auth.session_credentials WHERE session_id=a.session_id;
  PERFORM jls_auth.lock_upstream_identity((p_binding).upstream_session_id);
  SELECT upstream.not_after INTO v_upstream_expires_at FROM auth.sessions upstream
    WHERE upstream.id=(a.binding).upstream_session_id AND upstream.user_id=(a.binding).auth_subject;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  v_now:=clock_timestamp();
  IF a.state<>'sent' OR a.lease_expires_at<=v_now OR NOT jls_auth.refresh_app_current(p_binding,v_now)
    OR c.state<>'sent_or_unknown' OR c.token_version<>(p_binding).token_version OR c.token_version>=9007199254740990
    OR c.refresh_attempt_id IS DISTINCT FROM a.attempt_id OR c.refresh_lease_expires_at IS DISTINCT FROM a.lease_expires_at
    OR c.refresh_transmission_intent_at IS DISTINCT FROM a.transmission_intent_at
    OR p_access_expires_at<=v_now OR p_access_expires_at>v_now+interval '1 day'
    OR v_upstream_expires_at IS NOT NULL AND v_upstream_expires_at<=v_now
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  INSERT INTO jls_auth.refresh_receipts(operation_id,attempt_id,fingerprint,action,verified_subject,verified_upstream_session_id,
    pair_hash,access_expires_at,result) VALUES (p_finish_operation_id,a.attempt_id,p_finish_fingerprint,'finish',
    p_verified_subject,p_verified_upstream_session_id,v_pair_hash,p_access_expires_at,'committed')
    ON CONFLICT (operation_id) DO NOTHING;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  UPDATE jls_auth.session_credentials SET token_envelope=p_token_envelope,access_expires_at=p_access_expires_at,token_version=token_version+1,
    state='usable',refresh_attempt_id=NULL,refresh_lease_expires_at=NULL,refresh_transmission_intent_at=NULL WHERE session_id=a.session_id;
  UPDATE jls_auth.refresh_attempts SET state='committed' WHERE attempt_id=a.attempt_id;
  RETURN jsonb_build_object('kind','committed','attemptId',a.attempt_id,'sessionId',a.session_id,'tokenVersion',c.token_version+1);
END $$;

-- Caller holds the upstream identity lock. A replacement invalidates the old
-- claim but retains the original deadline, attempt count and claim history.
CREATE FUNCTION jls_auth.queue_session_cleanup(p_session_id uuid,p_token_envelope text,p_replace boolean,p_now timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
BEGIN
  INSERT INTO jls_auth.cleanup_work(session_id,token_envelope) VALUES (p_session_id,p_token_envelope)
    ON CONFLICT (session_id) DO NOTHING;
  IF FOUND OR NOT p_replace THEN RETURN; END IF;
  UPDATE jls_auth.cleanup_work SET token_envelope=p_token_envelope,revision=revision+1,claim_revision=NULL,lease_expires_at=NULL,
    state=CASE WHEN attempts<3 AND deadline_at>p_now THEN 'pending' ELSE 'failed' END
    WHERE session_id=p_session_id;
END $$;

CREATE FUNCTION jls_auth.refresh_close(p_session_secret_hash text,p_browser_secret_hash text,p_binding jls_auth.refresh_binding,
  p_close_operation_id uuid,p_close_fingerprint text,p_disposition text,
  p_verified_subject uuid,p_verified_upstream_session_id uuid,p_token_envelope text)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE a jls_auth.refresh_attempts; s jls_auth.app_sessions; v_now timestamptz; v_pair_hash bytea; v_result jsonb; v_kind text;
BEGIN
  IF p_close_operation_id IS NULL OR p_close_fingerprint IS NULL OR p_close_fingerprint !~ '^[0-9a-f]{64}$'
    OR p_disposition IS NULL OR p_disposition NOT IN ('pre_send','unknown','late_pair') THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF p_disposition='late_pair' THEN
    IF p_verified_subject IS DISTINCT FROM (p_binding).auth_subject
      OR p_verified_upstream_session_id IS DISTINCT FROM (p_binding).upstream_session_id
      OR NOT jls_auth.refresh_pair_valid(p_token_envelope) THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    v_pair_hash:=sha256(convert_to(p_token_envelope,'UTF8'));
  ELSIF p_verified_subject IS NOT NULL OR p_verified_upstream_session_id IS NOT NULL OR p_token_envelope IS NOT NULL
    THEN RETURN '{"kind":"denied"}'::jsonb;
  END IF;
  IF NOT jls_auth.refresh_lock(p_session_secret_hash,p_browser_secret_hash,p_binding)
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO a FROM jls_auth.refresh_attempts WHERE attempt_id=(p_binding).attempt_id AND session_id=(p_binding).session_id;
  IF NOT FOUND OR a.binding IS DISTINCT FROM p_binding THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('jls-auth-refresh-operation-v1:'||p_close_operation_id::text,0));
  v_result:=jls_auth.refresh_result(a.attempt_id,a.session_id,(p_binding).token_version,p_close_operation_id,p_close_fingerprint,
    p_disposition,p_verified_subject,p_verified_upstream_session_id,v_pair_hash,NULL);
  IF v_result IS NOT NULL THEN RETURN v_result; END IF;
  IF p_disposition='pre_send' THEN
    IF a.state NOT IN ('prepared','released') THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    v_kind:='released';
  ELSE
    IF a.state NOT IN ('sent','unknown') THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    v_kind:=CASE p_disposition WHEN 'unknown' THEN 'closed' ELSE 'late_pair_retained' END;
  END IF;
  IF p_disposition='late_pair' THEN
    PERFORM jls_auth.lock_upstream_identity((p_binding).upstream_session_id);
    SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=a.session_id;
  END IF;
  v_now:=clock_timestamp();
  INSERT INTO jls_auth.refresh_receipts(operation_id,attempt_id,fingerprint,action,verified_subject,verified_upstream_session_id,pair_hash,result)
    VALUES (p_close_operation_id,a.attempt_id,p_close_fingerprint,p_disposition,p_verified_subject,p_verified_upstream_session_id,v_pair_hash,v_kind)
    ON CONFLICT DO NOTHING;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF p_disposition='pre_send' THEN
    UPDATE jls_auth.refresh_attempts SET state='released' WHERE attempt_id=a.attempt_id AND state='prepared';
    UPDATE jls_auth.session_credentials SET state='usable',refresh_attempt_id=NULL,refresh_lease_expires_at=NULL,
      refresh_transmission_intent_at=NULL WHERE session_id=a.session_id AND refresh_attempt_id=a.attempt_id
      AND token_version=(p_binding).token_version AND state='prepared' AND refresh_transmission_intent_at IS NULL
      AND refresh_lease_expires_at=a.lease_expires_at;
  ELSE
    UPDATE jls_auth.refresh_attempts SET state='unknown' WHERE attempt_id=a.attempt_id AND state='sent';
    UPDATE jls_auth.session_credentials SET state='uncertain',refresh_attempt_id=NULL,refresh_lease_expires_at=NULL,
      refresh_transmission_intent_at=NULL WHERE session_id=a.session_id AND refresh_attempt_id=a.attempt_id
      AND token_version=(p_binding).token_version AND state='sent_or_unknown'
      AND refresh_transmission_intent_at=a.transmission_intent_at AND refresh_lease_expires_at=a.lease_expires_at;
    IF p_disposition='late_pair' THEN
      IF s.revoked_at IS NULL THEN
        UPDATE jls_auth.refresh_attempts SET late_pair_envelope=p_token_envelope WHERE attempt_id=a.attempt_id;
      ELSE
        PERFORM jls_auth.queue_session_cleanup(s.session_id,p_token_envelope,true,v_now);
      END IF;
    END IF;
  END IF;
  RETURN jsonb_build_object('kind',v_kind);
END $$;

-- Existing lifecycle operations already hold browser/owner/session locks.
-- Before either identity lock, fence the credential and refresh attempt rows.
CREATE FUNCTION jls_auth.lock_session_revocation(p_session_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
BEGIN
  PERFORM session_id FROM jls_auth.session_credentials WHERE session_id=p_session_id FOR UPDATE;
  PERFORM attempt_id FROM jls_auth.refresh_attempts WHERE session_id=p_session_id
    AND (state IN ('prepared','sent') OR late_pair_envelope IS NOT NULL)
    ORDER BY attempt_id FOR UPDATE;
END $$;

-- Caller holds the session, credential, relevant attempts and upstream identity.
-- Retire application authority and move custody in the same transaction.
CREATE FUNCTION jls_auth.revoke_locked_session(p_session_id uuid,p_now timestamptz) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE v_late_pair text; v_envelope text;
BEGIN
  UPDATE jls_auth.app_sessions SET revoked_at=p_now WHERE session_id=p_session_id AND revoked_at IS NULL;
  SELECT late_pair_envelope INTO v_late_pair FROM jls_auth.refresh_attempts
    WHERE session_id=p_session_id AND late_pair_envelope IS NOT NULL;
  SELECT token_envelope INTO v_envelope FROM jls_auth.session_credentials WHERE session_id=p_session_id;
  PERFORM jls_auth.queue_session_cleanup(p_session_id,coalesce(v_late_pair,v_envelope),v_late_pair IS NOT NULL,p_now);
  UPDATE jls_auth.session_credentials SET state='revoked',token_version=least(token_version+1,9007199254740990),
    refresh_attempt_id=NULL,refresh_lease_expires_at=NULL,refresh_transmission_intent_at=NULL
    WHERE session_id=p_session_id AND state<>'revoked';
  UPDATE jls_auth.refresh_attempts SET state=CASE state WHEN 'prepared' THEN 'released' WHEN 'sent' THEN 'unknown' ELSE state END,
    late_pair_envelope=NULL WHERE session_id=p_session_id AND (state IN ('prepared','sent') OR late_pair_envelope IS NOT NULL);
END $$;

CREATE FUNCTION jls_auth.session_cleanup_claim(p_session_id uuid,p_claim_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE s jls_auth.app_sessions; w jls_auth.cleanup_work; v_now timestamptz;
BEGIN
  IF p_claim_id IS NULL THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=p_session_id;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  -- Cleanup has no application authority and never locks an app row after this.
  PERFORM jls_auth.lock_upstream_identity(s.upstream_session_id);
  SELECT * INTO w FROM jls_auth.cleanup_work WHERE session_id=p_session_id FOR UPDATE;
  IF NOT FOUND OR EXISTS (SELECT FROM jls_auth.app_sessions WHERE upstream_session_id=s.upstream_session_id AND revoked_at IS NULL)
    OR w.state IN ('completed','failed') THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  v_now:=clock_timestamp();
  IF w.state='claimed' AND w.lease_expires_at>v_now THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF w.deadline_at<=v_now OR w.attempts>=3 THEN
    UPDATE jls_auth.cleanup_work SET state='failed',lease_expires_at=NULL WHERE session_id=p_session_id;
    RETURN '{"kind":"failed"}'::jsonb;
  END IF;
  IF w.token_envelope IS NULL THEN
    UPDATE jls_auth.cleanup_work SET state='failed',lease_expires_at=NULL,error_category='credential_unavailable' WHERE session_id=p_session_id;
    RETURN '{"kind":"credential_unavailable"}'::jsonb;
  END IF;
  IF p_claim_id=ANY(w.claim_history) THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  UPDATE jls_auth.cleanup_work SET state='claimed',attempts=attempts+1,claim_id=p_claim_id,claim_revision=revision,
    claim_history=array_append(claim_history,p_claim_id),lease_expires_at=least(deadline_at,v_now+interval '15 seconds')
    WHERE session_id=p_session_id;
  RETURN jsonb_build_object('kind','cleanup','sessionId',p_session_id,'ownerId',s.owner_id,'authSubject',s.auth_subject,
    'upstreamSessionId',s.upstream_session_id,'scope','local','tokenEnvelope',w.token_envelope,'claimId',p_claim_id,'revision',w.revision);
END $$;

CREATE FUNCTION jls_auth.session_cleanup_complete(p_session_id uuid,p_claim_id uuid,p_revision bigint,p_outcome text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE s jls_auth.app_sessions; w jls_auth.cleanup_work; v_now timestamptz; v_state text;
BEGIN
  IF p_claim_id IS NULL OR p_revision IS NULL OR p_outcome IS NULL OR p_outcome NOT IN ('completed','timeout','transport','rejected')
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=p_session_id;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  PERFORM jls_auth.lock_upstream_identity(s.upstream_session_id);
  SELECT * INTO w FROM jls_auth.cleanup_work WHERE session_id=p_session_id FOR UPDATE;
  IF NOT FOUND OR w.state<>'claimed' OR w.claim_id IS DISTINCT FROM p_claim_id
    OR w.claim_revision IS DISTINCT FROM p_revision OR w.revision<>p_revision
    OR EXISTS (SELECT FROM jls_auth.app_sessions WHERE upstream_session_id=s.upstream_session_id AND revoked_at IS NULL)
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  v_now:=clock_timestamp();
  IF w.lease_expires_at<=v_now THEN
    IF w.deadline_at<=v_now OR w.attempts>=3 THEN
      UPDATE jls_auth.cleanup_work SET state='failed',lease_expires_at=NULL WHERE session_id=p_session_id;
      RETURN '{"kind":"failed"}'::jsonb;
    END IF;
    RETURN '{"kind":"denied"}'::jsonb;
  END IF;
  v_state:=CASE WHEN p_outcome='completed' THEN 'completed'
    WHEN p_outcome='rejected' OR w.attempts>=3 THEN 'failed' ELSE 'pending' END;
  UPDATE jls_auth.cleanup_work SET state=v_state,lease_expires_at=NULL,
    token_envelope=CASE WHEN p_outcome='completed' THEN NULL ELSE w.token_envelope END,
    error_category=CASE WHEN p_outcome='completed' THEN NULL ELSE p_outcome END WHERE session_id=p_session_id;
  RETURN jsonb_build_object('kind',v_state);
END $$;

-- Preserve the existing lifecycle RPC contracts while coordinating refresh custody.
CREATE OR REPLACE FUNCTION jls_auth.delivery_retire(p_browser_secret_hash text,p_attempt_id uuid,p_session_id uuid,p_generation bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE b jls_auth.browser_bindings; s jls_auth.app_sessions; a jls_auth.oauth_attempts; v_now timestamptz;
BEGIN
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE secret_hash=p_browser_secret_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=p_session_id AND browser_id=b.browser_id;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  PERFORM owner_id FROM jls_auth.owner_control WHERE owner_id=s.owner_id FOR UPDATE;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=p_session_id FOR UPDATE;
  PERFORM jls_auth.lock_session_revocation(s.session_id);
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE attempt_id=p_attempt_id FOR UPDATE;
  PERFORM jls_auth.lock_upstream_identity(s.upstream_session_id);
  v_now:=clock_timestamp();
  IF a.state='retired' AND a.browser_id=b.browser_id AND a.resulting_session_id=s.session_id
    AND a.generation_after=p_generation AND s.browser_generation=p_generation
    AND b.generation=p_generation+1 AND b.current_session_id IS NULL AND b.expires_at>v_now
    AND s.revoked_at IS NOT NULL AND s.delivery_state='unacknowledged'
    THEN RETURN '{"kind":"already_retired"}'::jsonb; END IF;
  IF a.attempt_id IS NULL OR a.browser_id<>b.browser_id OR a.resulting_session_id IS DISTINCT FROM s.session_id
    OR a.state<>'completed' OR a.generation_after IS DISTINCT FROM p_generation
    OR b.generation IS DISTINCT FROM p_generation OR s.browser_generation IS DISTINCT FROM p_generation
    OR b.current_session_id IS DISTINCT FROM s.session_id OR s.delivery_state<>'unacknowledged'
    OR s.revoked_at IS NOT NULL OR b.expires_at<=v_now THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  PERFORM jls_auth.revoke_locked_session(s.session_id,v_now);
  UPDATE jls_auth.browser_bindings SET generation=generation+1,current_session_id=NULL WHERE browser_id=b.browser_id;
  UPDATE jls_auth.oauth_attempts SET state='retired' WHERE attempt_id=a.attempt_id;
  RETURN '{"kind":"retired"}'::jsonb;
END $$;

CREATE OR REPLACE FUNCTION jls_auth.logout(p_browser_secret_hash text,p_proof_hash text,p_operation_id uuid,p_cookie_fingerprint text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE b jls_auth.browser_bindings; s jls_auth.app_sessions; p jls_auth.csrf_proofs;
  r jls_auth.action_receipts; v_session_id uuid; v_now timestamptz; v_outcome text;
BEGIN
  IF p_cookie_fingerprint IS NULL OR (p_cookie_fingerprint<>'absent' AND p_cookie_fingerprint !~ '^present:[0-9a-f]{64}$')
    OR p_operation_id IS NULL THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE secret_hash=p_browser_secret_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  -- Discovery only; lock acquisition still follows browser -> owner -> sorted sessions -> proof/attempt/receipt.
  SELECT session_id INTO v_session_id FROM jls_auth.csrf_proofs WHERE secret_hash=p_proof_hash
    AND operation_id=p_operation_id AND browser_id=b.browser_id AND purpose='logout';
  IF v_session_id IS NOT NULL THEN
    SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=v_session_id;
    PERFORM owner_id FROM jls_auth.owner_control WHERE owner_id=s.owner_id FOR UPDATE;
    PERFORM session_id FROM jls_auth.app_sessions WHERE session_id=v_session_id ORDER BY session_id FOR UPDATE;
    PERFORM jls_auth.lock_session_revocation(v_session_id);
  END IF;
  SELECT * INTO p FROM jls_auth.csrf_proofs WHERE secret_hash=p_proof_hash AND operation_id=p_operation_id
    AND browser_id=b.browser_id AND purpose='logout' FOR UPDATE;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  PERFORM attempt_id FROM jls_auth.oauth_attempts WHERE browser_id=b.browser_id AND generation_before=p.generation
    ORDER BY attempt_id FOR UPDATE;
  PERFORM jls_auth.lock_upstream_identity(s.upstream_session_id);
  -- Receipts are immutable; the already-held browser lock serializes this operation.
  SELECT * INTO r FROM jls_auth.action_receipts WHERE operation_id=p_operation_id;
  v_now:=clock_timestamp();
  IF r.operation_id IS NOT NULL THEN
    IF r.proof_id=p.proof_id AND r.browser_id=b.browser_id AND r.expires_at>v_now
      AND r.generation_after=b.generation AND b.current_session_id IS NULL AND b.expires_at>v_now
      AND (p_cookie_fingerprint=r.cookie_fingerprint OR p_cookie_fingerprint='absent') THEN
      RETURN jsonb_build_object('kind','logged_out','outcome',r.outcome,'clearCookie',true);
    END IF;
    RETURN '{"kind":"denied"}'::jsonb;
  END IF;
  IF p.consumed_at IS NOT NULL OR p.expires_at<=v_now OR p.issued_at>v_now OR b.expires_at<=v_now
    OR b.generation<>p.generation OR p.cookie_fingerprint<>p_cookie_fingerprint
    OR b.generation>=9007199254740989 OR p.session_id IS DISTINCT FROM b.current_session_id
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF p.session_id IS NULL THEN
    IF p.cookie_fingerprint<>'absent' THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    -- No current session exists under the browser lock. Pending activation is
    -- cancelled below in this same transaction before the generation fence commits.
    v_outcome:='absent';
  ELSE
    SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=p.session_id;
    IF s.session_id IS NULL OR s.browser_id<>b.browser_id OR s.browser_generation<>b.generation
      THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    PERFORM jls_auth.revoke_locked_session(s.session_id,v_now);
    v_outcome:='revoked';
  END IF;
  UPDATE jls_auth.oauth_attempts SET state='cancelled' WHERE browser_id=b.browser_id
    AND generation_before=b.generation AND state IN ('pending','claimed','exchange_unknown');
  UPDATE jls_auth.csrf_proofs SET consumed_at=v_now WHERE proof_id=p.proof_id;
  UPDATE jls_auth.browser_bindings SET generation=generation+1,current_session_id=NULL WHERE browser_id=b.browser_id;
  INSERT INTO jls_auth.action_receipts(operation_id,proof_id,browser_id,generation_before,generation_after,cookie_fingerprint,target_session_id,outcome)
    VALUES (p_operation_id,p.proof_id,b.browser_id,b.generation,b.generation+1,p.cookie_fingerprint,p.session_id,v_outcome);
  RETURN jsonb_build_object('kind','logged_out','outcome',v_outcome,'clearCookie',true);
END $$;

CREATE OR REPLACE FUNCTION jls_auth.callback_commit(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid,
  p_commit_operation_id uuid,p_request_fingerprint text,p_candidate_id uuid,p_verified_subject uuid,p_verified_upstream_session_id uuid,
  p_new_session_id uuid,p_new_session_hash text,p_token_envelope text,p_access_expires_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE a jls_auth.oauth_attempts; b jls_auth.browser_bindings; o jls_auth.owner_control;
  v_browser uuid; v_now timestamptz; v_binding jsonb; v_prior_upstream uuid; v_identity uuid;
BEGIN
  IF p_commit_operation_id IS NULL OR p_candidate_id IS NULL OR p_verified_subject IS NULL OR p_verified_upstream_session_id IS NULL
    OR p_new_session_id IS NULL OR p_request_fingerprint IS NULL OR p_request_fingerprint !~ '^[0-9a-f]{64}$'
    OR p_new_session_hash IS NULL OR p_new_session_hash !~ '^[0-9a-f]{64}$'
    OR p_token_envelope IS NULL OR octet_length(p_token_envelope)>49152
    OR p_token_envelope !~ '^v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$'
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  v_browser:=jls_auth.lock_oauth(p_browser_hash,p_attempt_id);
  IF v_browser IS NULL OR p_claim_id IS NULL THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE attempt_id=p_attempt_id;
  IF a.prior_session_id IS NOT NULL THEN
    PERFORM jls_auth.lock_session_revocation(a.prior_session_id);
    SELECT upstream_session_id INTO v_prior_upstream FROM jls_auth.app_sessions WHERE session_id=a.prior_session_id;
  END IF;
  FOR v_identity IN SELECT DISTINCT identity FROM unnest(ARRAY[v_prior_upstream,p_verified_upstream_session_id]) AS identities(identity)
    WHERE identity IS NOT NULL ORDER BY identity
  LOOP
    PERFORM jls_auth.lock_upstream_identity(v_identity);
  END LOOP;
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE browser_id=v_browser;
  SELECT * INTO o FROM jls_auth.owner_control WHERE owner_id=a.expected_owner_id;
  v_now:=clock_timestamp();
  IF a.flow_cookie_hash IS DISTINCT FROM p_flow_hash OR a.claim_id IS DISTINCT FROM p_claim_id THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  v_binding:=jsonb_build_array(p_candidate_id,p_verified_subject,p_verified_upstream_session_id,p_new_session_id,
    p_new_session_hash,p_token_envelope,extract(epoch FROM p_access_expires_at));
  IF a.commit_operation_id IS NOT NULL THEN
    IF a.commit_operation_id=p_commit_operation_id AND a.commit_fingerprint=p_request_fingerprint AND a.commit_binding=v_binding
      THEN RETURN jsonb_build_object('kind','committed','attemptId',a.attempt_id,'sessionId',a.resulting_session_id,
        'generation',a.generation_after); END IF;
    RETURN '{"kind":"denied"}'::jsonb;
  END IF;
  IF a.state<>'exchange_unknown' OR a.exchange_transmission_intent_at IS NULL OR a.expires_at<=v_now OR a.issued_at>v_now
    OR b.expires_at<=v_now OR b.generation<>a.generation_before OR b.current_session_id IS DISTINCT FROM a.prior_session_id
    OR b.generation>=9007199254740989 OR o.active IS DISTINCT FROM true OR o.auth_subject IS DISTINCT FROM p_verified_subject
    OR o.control_version IS DISTINCT FROM a.expected_control_version OR o.current_dataset_epoch IS DISTINCT FROM a.expected_dataset_epoch
    OR o.current_dataset_epoch IS NULL OR p_access_expires_at IS NULL OR p_access_expires_at<=v_now OR p_access_expires_at>v_now+interval '1 day'
    OR EXISTS (SELECT FROM jls_auth.app_sessions WHERE session_id=p_new_session_id OR secret_hash=p_new_session_hash OR (upstream_session_id=p_verified_upstream_session_id AND revoked_at IS NULL))
    OR EXISTS (SELECT FROM jls_auth.candidate_cleanup_work WHERE upstream_session_id=p_verified_upstream_session_id)
    OR EXISTS (SELECT FROM jls_auth.cleanup_work w JOIN jls_auth.app_sessions s ON s.session_id=w.session_id WHERE s.upstream_session_id=p_verified_upstream_session_id)
    OR EXISTS (SELECT FROM jls_auth.oauth_attempts WHERE commit_operation_id=p_commit_operation_id)
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF a.prior_session_id IS NOT NULL THEN
    PERFORM jls_auth.revoke_locked_session(a.prior_session_id,v_now);
  END IF;
  INSERT INTO jls_auth.app_sessions(session_id,secret_hash,owner_id,auth_subject,upstream_session_id,browser_id,browser_generation,created_at,last_activity_at)
    VALUES (p_new_session_id,p_new_session_hash,o.owner_id,o.auth_subject,p_verified_upstream_session_id,b.browser_id,b.generation+1,v_now,v_now);
  INSERT INTO jls_auth.session_credentials(session_id,token_envelope,access_expires_at)
    VALUES (p_new_session_id,p_token_envelope,p_access_expires_at);
  UPDATE jls_auth.browser_bindings SET generation=generation+1,current_session_id=p_new_session_id WHERE browser_id=b.browser_id;
  UPDATE jls_auth.oauth_attempts SET state='completed',generation_after=b.generation+1,resulting_session_id=p_new_session_id,
    commit_operation_id=p_commit_operation_id,commit_fingerprint=p_request_fingerprint,commit_binding=v_binding,candidate_id=p_candidate_id
    WHERE attempt_id=a.attempt_id;
  RETURN jsonb_build_object('kind','committed','attemptId',a.attempt_id,'sessionId',p_new_session_id,'generation',b.generation+1);
END $$;

CREATE FUNCTION public.jls_auth_refresh_claim_v1(p_session_secret_hash text,p_browser_secret_hash text,p_attempt_id uuid,p_request_fingerprint text,
  p_session_id uuid,p_browser_id uuid,p_browser_generation bigint,p_owner_id uuid,
  p_auth_subject uuid,p_upstream_session_id uuid,p_expected_token_version bigint,p_expected_control_version bigint,
  p_expected_dataset_epoch uuid) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
  SELECT jls_auth.refresh_claim(p_session_secret_hash,p_browser_secret_hash,ROW(p_attempt_id,p_request_fingerprint,p_session_id,p_browser_id,p_browser_generation,
      p_owner_id,p_auth_subject,p_upstream_session_id,p_expected_token_version,p_expected_control_version,
      p_expected_dataset_epoch)::jls_auth.refresh_binding)
$$;

CREATE FUNCTION public.jls_auth_refresh_mark_sent_v1(p_session_secret_hash text,p_browser_secret_hash text,p_attempt_id uuid,p_request_fingerprint text,
  p_session_id uuid,p_browser_id uuid,p_browser_generation bigint,p_owner_id uuid,
  p_auth_subject uuid,p_upstream_session_id uuid,p_expected_token_version bigint,p_expected_control_version bigint,
  p_expected_dataset_epoch uuid) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
  SELECT jls_auth.refresh_mark_sent(p_session_secret_hash,p_browser_secret_hash,ROW(p_attempt_id,p_request_fingerprint,p_session_id,p_browser_id,p_browser_generation,
      p_owner_id,p_auth_subject,p_upstream_session_id,p_expected_token_version,p_expected_control_version,
      p_expected_dataset_epoch)::jls_auth.refresh_binding)
$$;

CREATE FUNCTION public.jls_auth_refresh_finish_v1(p_session_secret_hash text,p_browser_secret_hash text,p_attempt_id uuid,p_request_fingerprint text,
  p_session_id uuid,p_browser_id uuid,p_browser_generation bigint,p_owner_id uuid,
  p_auth_subject uuid,p_upstream_session_id uuid,p_expected_token_version bigint,p_expected_control_version bigint,
  p_expected_dataset_epoch uuid,p_finish_operation_id uuid,p_finish_fingerprint text,p_verified_subject uuid,
  p_verified_upstream_session_id uuid,p_token_envelope text,p_access_expires_at timestamptz) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
  SELECT jls_auth.refresh_finish(p_session_secret_hash,p_browser_secret_hash,ROW(p_attempt_id,p_request_fingerprint,p_session_id,p_browser_id,p_browser_generation,
      p_owner_id,p_auth_subject,p_upstream_session_id,p_expected_token_version,p_expected_control_version,
      p_expected_dataset_epoch)::jls_auth.refresh_binding,p_finish_operation_id,
    p_finish_fingerprint,p_verified_subject,p_verified_upstream_session_id,p_token_envelope,
    p_access_expires_at,false)
$$;

CREATE FUNCTION public.jls_auth_refresh_resolve_v1(p_session_secret_hash text,p_browser_secret_hash text,p_attempt_id uuid,p_request_fingerprint text,
  p_session_id uuid,p_browser_id uuid,p_browser_generation bigint,p_owner_id uuid,
  p_auth_subject uuid,p_upstream_session_id uuid,p_expected_token_version bigint,p_expected_control_version bigint,
  p_expected_dataset_epoch uuid,p_finish_operation_id uuid,p_finish_fingerprint text,p_verified_subject uuid,
  p_verified_upstream_session_id uuid,p_token_envelope text,p_access_expires_at timestamptz) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
  SELECT jls_auth.refresh_finish(p_session_secret_hash,p_browser_secret_hash,ROW(p_attempt_id,p_request_fingerprint,p_session_id,p_browser_id,p_browser_generation,
      p_owner_id,p_auth_subject,p_upstream_session_id,p_expected_token_version,p_expected_control_version,
      p_expected_dataset_epoch)::jls_auth.refresh_binding,p_finish_operation_id,
    p_finish_fingerprint,p_verified_subject,p_verified_upstream_session_id,p_token_envelope,
    p_access_expires_at,true)
$$;

CREATE FUNCTION public.jls_auth_refresh_close_v1(p_session_secret_hash text,p_browser_secret_hash text,p_attempt_id uuid,p_request_fingerprint text,
  p_session_id uuid,p_browser_id uuid,p_browser_generation bigint,p_owner_id uuid,
  p_auth_subject uuid,p_upstream_session_id uuid,p_expected_token_version bigint,p_expected_control_version bigint,
  p_expected_dataset_epoch uuid,p_close_operation_id uuid,p_close_fingerprint text,p_disposition text,
  p_verified_subject uuid,p_verified_upstream_session_id uuid,p_token_envelope text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
  SELECT jls_auth.refresh_close(p_session_secret_hash,p_browser_secret_hash,ROW(p_attempt_id,p_request_fingerprint,p_session_id,p_browser_id,p_browser_generation,
      p_owner_id,p_auth_subject,p_upstream_session_id,p_expected_token_version,p_expected_control_version,
      p_expected_dataset_epoch)::jls_auth.refresh_binding,p_close_operation_id,
    p_close_fingerprint,p_disposition,p_verified_subject,p_verified_upstream_session_id,
    p_token_envelope)
$$;

CREATE FUNCTION public.jls_auth_session_cleanup_claim_v1(p_session_id uuid,p_claim_id uuid) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
  SELECT jls_auth.session_cleanup_claim(p_session_id,p_claim_id)
$$;

CREATE FUNCTION public.jls_auth_session_cleanup_complete_v1(p_session_id uuid,p_claim_id uuid,p_revision bigint,p_outcome text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
  SELECT jls_auth.session_cleanup_complete(p_session_id,p_claim_id,p_revision,p_outcome)
$$;

REVOKE ALL ON FUNCTION jls_auth.refresh_lock(text,text,jls_auth.refresh_binding),
  jls_auth.refresh_app_current(jls_auth.refresh_binding,timestamptz),
  jls_auth.refresh_claim(text,text,jls_auth.refresh_binding),
  jls_auth.refresh_mark_sent(text,text,jls_auth.refresh_binding),
  jls_auth.refresh_pair_valid(text),
  jls_auth.refresh_result(uuid,uuid,bigint,uuid,text,text,uuid,uuid,bytea,timestamptz),
  jls_auth.refresh_finish(text,text,jls_auth.refresh_binding,uuid,text,uuid,uuid,text,timestamptz,boolean),
  jls_auth.refresh_close(text,text,jls_auth.refresh_binding,uuid,text,text,uuid,uuid,text),
  jls_auth.queue_session_cleanup(uuid,text,boolean,timestamptz),
  jls_auth.lock_session_revocation(uuid),
  jls_auth.revoke_locked_session(uuid,timestamptz),
  jls_auth.session_cleanup_claim(uuid,uuid),
  jls_auth.session_cleanup_complete(uuid,uuid,bigint,text),
  public.jls_auth_refresh_claim_v1(text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid),
  public.jls_auth_refresh_mark_sent_v1(text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid),
  public.jls_auth_refresh_finish_v1(text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid,uuid,text,uuid,uuid,text,timestamptz),
  public.jls_auth_refresh_resolve_v1(text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid,uuid,text,uuid,uuid,text,timestamptz),
  public.jls_auth_refresh_close_v1(text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid,uuid,text,text,uuid,uuid,text),
  public.jls_auth_session_cleanup_claim_v1(uuid,uuid),
  public.jls_auth_session_cleanup_complete_v1(uuid,uuid,bigint,text) FROM PUBLIC,anon,authenticated,service_role;

GRANT EXECUTE ON FUNCTION jls_auth.refresh_lock(text,text,jls_auth.refresh_binding),
  jls_auth.refresh_app_current(jls_auth.refresh_binding,timestamptz),
  jls_auth.refresh_claim(text,text,jls_auth.refresh_binding),
  jls_auth.refresh_mark_sent(text,text,jls_auth.refresh_binding),
  jls_auth.refresh_pair_valid(text),
  jls_auth.refresh_result(uuid,uuid,bigint,uuid,text,text,uuid,uuid,bytea,timestamptz),
  jls_auth.refresh_finish(text,text,jls_auth.refresh_binding,uuid,text,uuid,uuid,text,timestamptz,boolean),
  jls_auth.refresh_close(text,text,jls_auth.refresh_binding,uuid,text,text,uuid,uuid,text),
  jls_auth.queue_session_cleanup(uuid,text,boolean,timestamptz),
  jls_auth.lock_session_revocation(uuid),
  jls_auth.revoke_locked_session(uuid,timestamptz),
  jls_auth.session_cleanup_claim(uuid,uuid),
  jls_auth.session_cleanup_complete(uuid,uuid,bigint,text),
  public.jls_auth_refresh_claim_v1(text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid),
  public.jls_auth_refresh_mark_sent_v1(text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid),
  public.jls_auth_refresh_finish_v1(text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid,uuid,text,uuid,uuid,text,timestamptz),
  public.jls_auth_refresh_resolve_v1(text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid,uuid,text,uuid,uuid,text,timestamptz),
  public.jls_auth_refresh_close_v1(text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid,uuid,text,text,uuid,uuid,text),
  public.jls_auth_session_cleanup_claim_v1(uuid,uuid),
  public.jls_auth_session_cleanup_complete_v1(uuid,uuid,bigint,text) TO service_role;

COMMIT;
