-- LOCAL SOURCE ONLY. Extends the frozen foundation; no enrollment, network,
-- runtime wiring, refresh mutations, hosted apply or key material.
BEGIN;
CREATE TABLE jls_auth.proof_issuances (
  issuance_id uuid PRIMARY KEY,
  proof_id uuid NOT NULL UNIQUE REFERENCES jls_auth.csrf_proofs(proof_id),
  request_fingerprint text NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
  request_binding jsonb NOT NULL CHECK (jsonb_typeof(request_binding)='array')
);
ALTER TABLE jls_auth.oauth_attempts
  ADD COLUMN login_operation_id uuid UNIQUE,
  ADD COLUMN begin_fingerprint text CHECK (begin_fingerprint ~ '^[0-9a-f]{64}$'),
  ADD COLUMN begin_binding jsonb,
  ADD COLUMN expected_owner_id uuid REFERENCES jls_auth.owner_control(owner_id),
  ADD COLUMN expected_control_version bigint,
  ADD COLUMN expected_dataset_epoch uuid,
  ADD COLUMN exchange_transmission_intent_at timestamptz,
  ADD COLUMN commit_operation_id uuid UNIQUE,
  ADD COLUMN commit_fingerprint text CHECK (commit_fingerprint ~ '^[0-9a-f]{64}$'),
  ADD COLUMN commit_binding jsonb,
  ADD COLUMN candidate_id uuid,
  ADD COLUMN close_operation_id uuid UNIQUE,
  ADD COLUMN close_fingerprint text CHECK (close_fingerprint ~ '^[0-9a-f]{64}$'),
  ADD COLUMN close_binding jsonb,
  ADD CONSTRAINT oauth_transmission_claim CHECK (exchange_transmission_intent_at IS NULL OR (claim_id IS NOT NULL AND claimed_at IS NOT NULL)),
  ADD CONSTRAINT oauth_commit_binding CHECK (commit_operation_id IS NULL OR (commit_fingerprint IS NOT NULL AND commit_binding IS NOT NULL AND candidate_id IS NOT NULL));
-- An unknown exchange is still live until explicitly closed; it cannot be
-- silently replaced or made eligible for exchange by a lease timeout.
CREATE UNIQUE INDEX oauth_one_live_lifecycle ON jls_auth.oauth_attempts(browser_id)
  WHERE state IN ('pending','claimed','exchange_unknown');
CREATE TABLE jls_auth.candidate_cleanup_work (
  attempt_id uuid PRIMARY KEY REFERENCES jls_auth.oauth_attempts(attempt_id),
  candidate_id uuid,
  context_environment text CHECK (context_environment ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),
  auth_subject uuid,
  upstream_session_id uuid,
  token_envelope text CHECK (token_envelope IS NULL OR (octet_length(token_envelope) BETWEEN 1 AND 49152
    AND token_envelope ~ '^orphan-v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$')),
  scope text NOT NULL DEFAULT 'local' CHECK (scope='local'),
  state text NOT NULL CHECK (state IN ('pending','claimed','completed','failed','skipped','credential_unavailable')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
  claim_history uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(claim_history)<=3),
  claim_id uuid,
  lease_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  deadline_at timestamptz NOT NULL DEFAULT (statement_timestamp()+interval '1 hour'),
  error_category text CHECK (error_category IN ('timeout','transport','rejected','credential_unavailable','deadline_exceeded','attempts_exhausted','identity_in_use')),
  CHECK ((token_envelope IS NULL) = (state='credential_unavailable')),
  CHECK (token_envelope IS NULL OR (candidate_id IS NOT NULL AND context_environment IS NOT NULL AND auth_subject IS NOT NULL AND upstream_session_id IS NOT NULL)),
  CHECK (state<>'claimed' OR (claim_id IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK (deadline_at>created_at AND deadline_at<=created_at+interval '1 hour')
);
CREATE INDEX candidate_cleanup_identity ON jls_auth.candidate_cleanup_work(upstream_session_id);
ALTER TABLE jls_auth.proof_issuances ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.proof_issuances FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.candidate_cleanup_work ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.candidate_cleanup_work FORCE ROW LEVEL SECURITY;
CREATE POLICY service_control ON jls_auth.proof_issuances TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.candidate_cleanup_work TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON jls_auth.proof_issuances,jls_auth.candidate_cleanup_work FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT,INSERT ON jls_auth.proof_issuances,jls_auth.candidate_cleanup_work TO service_role;
GRANT UPDATE (state,attempts,claim_history,claim_id,lease_expires_at,error_category) ON jls_auth.candidate_cleanup_work TO service_role;
GRANT INSERT ON jls_auth.browser_bindings,jls_auth.csrf_proofs,jls_auth.oauth_attempts,jls_auth.app_sessions,jls_auth.session_credentials TO service_role;
GRANT UPDATE (claim_id,claimed_at,generation_after,resulting_session_id,exchange_transmission_intent_at,
  commit_operation_id,commit_fingerprint,commit_binding,candidate_id,close_operation_id,close_fingerprint,close_binding)
  ON jls_auth.oauth_attempts TO service_role;

CREATE FUNCTION jls_auth.issue_proof(p_issuance_id uuid,p_request_fingerprint text,p_browser_id uuid,p_browser_hash text,
  p_proof_id uuid,p_proof_hash text,p_purpose text,p_cookie_fingerprint text,p_presented_session_hash text,p_operation_id uuid,
  p_expected_token_version bigint,p_expected_control_version bigint,p_expected_dataset_epoch uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE b jls_auth.browser_bindings; s jls_auth.app_sessions; o jls_auth.owner_control;
  c jls_auth.session_credentials; i jls_auth.proof_issuances; p jls_auth.csrf_proofs;
  v_now timestamptz; v_binding jsonb; v_session uuid;
BEGIN
  IF p_issuance_id IS NULL OR p_browser_id IS NULL OR p_proof_id IS NULL
    OR p_request_fingerprint IS NULL OR p_request_fingerprint !~ '^[0-9a-f]{64}$'
    OR p_browser_hash IS NULL OR p_browser_hash !~ '^[0-9a-f]{64}$'
    OR p_proof_hash IS NULL OR p_proof_hash !~ '^[0-9a-f]{64}$'
    OR p_purpose IS NULL OR p_purpose NOT IN ('login','logout','mutation')
    OR p_cookie_fingerprint IS NULL OR (p_cookie_fingerprint<>'absent' AND p_cookie_fingerprint !~ '^present:[0-9a-f]{64}$')
    OR (p_cookie_fingerprint='absent' AND p_presented_session_hash IS NOT NULL)
    OR (p_presented_session_hash IS NOT NULL AND p_presented_session_hash !~ '^[0-9a-f]{64}$')
    OR (p_purpose IN ('login','logout') AND p_operation_id IS NULL)
    OR (p_purpose='mutation' AND p_operation_id IS NOT NULL)
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  -- The server hashes the exact parsed cookie separately from a syntactically
  -- valid session bearer. A fingerprint never authenticates that session.
  v_binding:=jsonb_build_array(p_browser_id,p_browser_hash,p_proof_id,p_proof_hash,p_purpose,p_cookie_fingerprint,
    p_presented_session_hash,p_operation_id,p_expected_token_version,p_expected_control_version,p_expected_dataset_epoch);
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE browser_id=p_browser_id FOR UPDATE;
  IF NOT FOUND THEN
    IF p_purpose='mutation' THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    INSERT INTO jls_auth.browser_bindings(browser_id,secret_hash,expires_at)
      VALUES (p_browser_id,p_browser_hash,clock_timestamp()+interval '8 days') ON CONFLICT DO NOTHING;
    SELECT * INTO b FROM jls_auth.browser_bindings WHERE browser_id=p_browser_id FOR UPDATE;
  END IF;
  IF b.browser_id IS NULL OR b.secret_hash IS DISTINCT FROM p_browser_hash THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=b.current_session_id;
  IF s.session_id IS NOT NULL THEN
    SELECT * INTO o FROM jls_auth.owner_control WHERE owner_id=s.owner_id FOR UPDATE;
    SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=b.current_session_id FOR UPDATE;
    IF s.secret_hash=p_presented_session_hash AND s.browser_generation=b.generation THEN v_session:=s.session_id; END IF;
  END IF;
  v_now:=clock_timestamp();
  IF b.expires_at<=v_now OR b.generation>=9007199254740989 THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF p_purpose='mutation' THEN
    SELECT * INTO c FROM jls_auth.session_credentials WHERE session_id=v_session FOR UPDATE;
    v_now:=clock_timestamp();
    IF v_session IS NULL OR b.expires_at<=v_now OR o.active IS DISTINCT FROM true OR o.auth_subject IS DISTINCT FROM s.auth_subject
      OR o.control_version IS DISTINCT FROM p_expected_control_version OR o.current_dataset_epoch IS DISTINCT FROM p_expected_dataset_epoch
      OR p_expected_dataset_epoch IS NULL OR s.revoked_at IS NOT NULL OR s.created_at>v_now OR s.last_activity_at>v_now
      OR s.created_at<=v_now-interval '7 days' OR s.last_activity_at<=v_now-interval '24 hours'
      OR c.session_id IS NULL OR c.state<>'usable' OR c.token_version IS DISTINCT FROM p_expected_token_version OR c.access_expires_at<=v_now
      THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  END IF;
  SELECT * INTO i FROM jls_auth.proof_issuances WHERE issuance_id=p_issuance_id;
  IF i.issuance_id IS NOT NULL THEN
    SELECT * INTO p FROM jls_auth.csrf_proofs WHERE proof_id=i.proof_id FOR UPDATE;
    IF i.request_fingerprint IS DISTINCT FROM p_request_fingerprint OR i.request_binding IS DISTINCT FROM v_binding
      OR p.browser_id<>b.browser_id OR p.generation<>b.generation OR p.expires_at<=v_now OR p.consumed_at IS NOT NULL
      THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  ELSE
    IF EXISTS (SELECT FROM jls_auth.csrf_proofs WHERE proof_id=p_proof_id OR secret_hash=p_proof_hash OR operation_id=p_operation_id)
      THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    INSERT INTO jls_auth.csrf_proofs(proof_id,secret_hash,browser_id,generation,purpose,cookie_fingerprint,session_id,operation_id)
      VALUES (p_proof_id,p_proof_hash,b.browser_id,b.generation,p_purpose,p_cookie_fingerprint,v_session,p_operation_id) RETURNING * INTO p;
    INSERT INTO jls_auth.proof_issuances(issuance_id,proof_id,request_fingerprint,request_binding)
      VALUES (p_issuance_id,p.proof_id,p_request_fingerprint,v_binding);
  END IF;
  RETURN jsonb_build_object('kind','issued','proofId',p.proof_id,'browserId',b.browser_id,'generation',p.generation,
    'expiresAt',floor(extract(epoch FROM p.expires_at)*1000)::bigint);
END $$;

CREATE FUNCTION jls_auth.begin_login(p_browser_hash text,p_proof_hash text,p_operation_id uuid,p_cookie_fingerprint text,
  p_attempt_id uuid,p_flow_hash text,p_pkce_envelope text,p_request_fingerprint text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE b jls_auth.browser_bindings; o jls_auth.owner_control; p jls_auth.csrf_proofs; a jls_auth.oauth_attempts;
  v_now timestamptz; v_binding jsonb;
BEGIN
  IF p_attempt_id IS NULL OR p_operation_id IS NULL OR p_request_fingerprint IS NULL OR p_request_fingerprint !~ '^[0-9a-f]{64}$'
    OR p_flow_hash IS NULL OR p_flow_hash !~ '^[0-9a-f]{64}$' OR p_pkce_envelope IS NULL OR octet_length(p_pkce_envelope)>2048
    OR p_pkce_envelope !~ '^pkce-v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{58}\.[A-Za-z0-9_-]{22}$'
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE secret_hash=p_browser_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO o FROM jls_auth.owner_control WHERE active FOR UPDATE;
  -- Current and prior session belong to this controlled owner; sorted sessions
  -- precede proof and attempt locks, matching logout and delivery retirement.
  PERFORM session_id FROM jls_auth.app_sessions WHERE browser_id=b.browser_id AND session_id=b.current_session_id ORDER BY session_id FOR UPDATE;
  SELECT * INTO p FROM jls_auth.csrf_proofs WHERE secret_hash=p_proof_hash AND operation_id=p_operation_id
    AND browser_id=b.browser_id AND purpose='login' FOR UPDATE;
  PERFORM attempt_id FROM jls_auth.oauth_attempts WHERE browser_id=b.browser_id ORDER BY attempt_id FOR UPDATE;
  v_now:=clock_timestamp();
  v_binding:=jsonb_build_array(p_proof_hash,p_operation_id,p_cookie_fingerprint,p_attempt_id,p_flow_hash,p_pkce_envelope);
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE login_operation_id=p_operation_id;
  IF a.attempt_id IS NOT NULL THEN
    IF a.browser_id=b.browser_id AND a.begin_fingerprint=p_request_fingerprint AND a.begin_binding=v_binding
      AND a.state='pending' AND a.expires_at>v_now AND b.generation=a.generation_before AND b.expires_at>v_now
      AND o.active IS TRUE AND o.owner_id=a.expected_owner_id AND o.control_version=a.expected_control_version
      AND o.current_dataset_epoch=a.expected_dataset_epoch THEN
      RETURN jsonb_build_object('kind','begun','attemptId',a.attempt_id,'generation',a.generation_before,
        'expiresAt',floor(extract(epoch FROM a.expires_at)*1000)::bigint);
    END IF;
    RETURN '{"kind":"denied"}'::jsonb;
  END IF;
  IF p.proof_id IS NULL OR p.consumed_at IS NOT NULL OR p.expires_at<=v_now OR p.issued_at>v_now
    OR p.generation<>b.generation OR p.cookie_fingerprint IS DISTINCT FROM p_cookie_fingerprint
    OR b.expires_at<=v_now OR b.generation>=9007199254740989 OR o.active IS DISTINCT FROM true OR o.current_dataset_epoch IS NULL
    OR EXISTS (SELECT FROM jls_auth.app_sessions WHERE session_id=b.current_session_id AND owner_id<>o.owner_id)
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF EXISTS (SELECT FROM jls_auth.oauth_attempts WHERE browser_id=b.browser_id AND state='exchange_unknown')
    THEN RETURN '{"kind":"restart_required"}'::jsonb; END IF;
  UPDATE jls_auth.oauth_attempts SET state='cancelled' WHERE browser_id=b.browser_id AND state IN ('pending','claimed')
    AND expires_at<=v_now AND exchange_transmission_intent_at IS NULL;
  IF EXISTS (SELECT FROM jls_auth.oauth_attempts WHERE browser_id=b.browser_id AND state IN ('pending','claimed'))
    THEN RETURN '{"kind":"restart_required"}'::jsonb; END IF;
  IF EXISTS (SELECT FROM jls_auth.oauth_attempts WHERE attempt_id=p_attempt_id OR flow_cookie_hash=p_flow_hash)
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  INSERT INTO jls_auth.oauth_attempts(attempt_id,browser_id,generation_before,purpose,prior_session_id,flow_cookie_hash,pkce_envelope,
    login_operation_id,begin_fingerprint,begin_binding,expected_owner_id,expected_control_version,expected_dataset_epoch)
    VALUES (p_attempt_id,b.browser_id,b.generation,'login',b.current_session_id,p_flow_hash,p_pkce_envelope,
      p_operation_id,p_request_fingerprint,v_binding,o.owner_id,o.control_version,o.current_dataset_epoch) RETURNING * INTO a;
  UPDATE jls_auth.csrf_proofs SET consumed_at=v_now WHERE proof_id=p.proof_id;
  RETURN jsonb_build_object('kind','begun','attemptId',a.attempt_id,'generation',a.generation_before,
    'expiresAt',floor(extract(epoch FROM a.expires_at)*1000)::bigint);
END $$;

-- This helper takes locks only. It is private, typed, has no dynamic SQL and
-- never interprets a JSON request or returns credentials. All mutation routines
-- re-read the locked rows and apply their own operation-specific predicates.
CREATE FUNCTION jls_auth.lock_oauth(p_browser_hash text,p_attempt_id uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE b jls_auth.browser_bindings; a jls_auth.oauth_attempts;
BEGIN
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE secret_hash=p_browser_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE attempt_id=p_attempt_id AND browser_id=b.browser_id;
  IF NOT FOUND OR a.expected_owner_id IS NULL THEN RETURN NULL; END IF;
  PERFORM owner_id FROM jls_auth.owner_control WHERE owner_id=a.expected_owner_id FOR UPDATE;
  PERFORM session_id FROM jls_auth.app_sessions WHERE browser_id=b.browser_id
    AND session_id IN (b.current_session_id,a.prior_session_id,a.resulting_session_id) ORDER BY session_id FOR UPDATE;
  PERFORM attempt_id FROM jls_auth.oauth_attempts WHERE attempt_id=a.attempt_id FOR UPDATE;
  RETURN b.browser_id;
END $$;

-- A shared upstream identity must never be adopted while cleanup could revoke
-- it. The fixed namespace separates these locks from all domain advisory locks;
-- a hash collision merely adds serialization. Never retain this lock over HTTP.
CREATE FUNCTION jls_auth.lock_upstream_identity(p_upstream_session_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
BEGIN
  IF p_upstream_session_id IS NOT NULL THEN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('jls-auth-upstream-cleanup-v1:'||p_upstream_session_id::text,0));
  END IF;
END $$;

CREATE FUNCTION jls_auth.callback_claim(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE a jls_auth.oauth_attempts; b jls_auth.browser_bindings; o jls_auth.owner_control; v_browser uuid; v_now timestamptz;
BEGIN
  v_browser:=jls_auth.lock_oauth(p_browser_hash,p_attempt_id);
  IF v_browser IS NULL OR p_claim_id IS NULL THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE attempt_id=p_attempt_id;
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE browser_id=v_browser;
  SELECT * INTO o FROM jls_auth.owner_control WHERE owner_id=a.expected_owner_id;
  v_now:=clock_timestamp();
  IF a.flow_cookie_hash IS DISTINCT FROM p_flow_hash THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF a.state NOT IN ('pending','claimed') OR a.exchange_transmission_intent_at IS NOT NULL OR a.expires_at<=v_now
    OR b.expires_at<=v_now OR a.generation_before<>b.generation OR b.current_session_id IS DISTINCT FROM a.prior_session_id
    OR o.active IS DISTINCT FROM true OR o.control_version IS DISTINCT FROM a.expected_control_version
    OR o.current_dataset_epoch IS DISTINCT FROM a.expected_dataset_epoch
    OR (a.state='claimed' AND a.claim_id IS DISTINCT FROM p_claim_id)
    THEN RETURN '{"kind":"restart_required"}'::jsonb; END IF;
  IF a.state='pending' THEN
    UPDATE jls_auth.oauth_attempts SET state='claimed',claim_id=p_claim_id,claimed_at=v_now WHERE attempt_id=a.attempt_id;
  END IF;
  RETURN jsonb_build_object('kind','claimed','now',floor(extract(epoch FROM v_now)*1000)::bigint,'attemptId',a.attempt_id,'claimId',p_claim_id,
    'browserId',b.browser_id,'pkceEnvelope',a.pkce_envelope,'ownerId',o.owner_id,'authSubject',o.auth_subject,
    'controlVersion',o.control_version,'datasetEpoch',o.current_dataset_epoch,'generation',a.generation_before);
END $$;

CREATE FUNCTION jls_auth.callback_mark_sent(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE a jls_auth.oauth_attempts; b jls_auth.browser_bindings; o jls_auth.owner_control; v_browser uuid; v_now timestamptz;
BEGIN
  v_browser:=jls_auth.lock_oauth(p_browser_hash,p_attempt_id);
  IF v_browser IS NULL OR p_claim_id IS NULL THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE attempt_id=p_attempt_id;
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE browser_id=v_browser;
  SELECT * INTO o FROM jls_auth.owner_control WHERE owner_id=a.expected_owner_id;
  v_now:=clock_timestamp();
  IF a.flow_cookie_hash IS DISTINCT FROM p_flow_hash OR a.claim_id IS DISTINCT FROM p_claim_id
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF a.exchange_transmission_intent_at IS NOT NULL OR a.state<>'claimed' OR a.expires_at<=v_now OR b.expires_at<=v_now
    OR a.generation_before<>b.generation OR b.current_session_id IS DISTINCT FROM a.prior_session_id
    OR o.active IS DISTINCT FROM true OR o.control_version IS DISTINCT FROM a.expected_control_version
    OR o.current_dataset_epoch IS DISTINCT FROM a.expected_dataset_epoch
    THEN RETURN '{"kind":"restart_required"}'::jsonb; END IF;
  UPDATE jls_auth.oauth_attempts SET state='exchange_unknown',exchange_transmission_intent_at=v_now WHERE attempt_id=a.attempt_id;
  -- Only this first, successfully committed response permits one transmission.
  -- An unknown COMMIT ACK must be resolved conservatively without sending.
  RETURN '{"kind":"send_intent"}'::jsonb;
END $$;

CREATE FUNCTION jls_auth.callback_commit(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid,
  p_commit_operation_id uuid,p_request_fingerprint text,p_candidate_id uuid,p_verified_subject uuid,p_verified_upstream_session_id uuid,
  p_new_session_id uuid,p_new_session_hash text,p_token_envelope text,p_access_expires_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE a jls_auth.oauth_attempts; b jls_auth.browser_bindings; o jls_auth.owner_control;
  v_browser uuid; v_now timestamptz; v_binding jsonb;
BEGIN
  IF p_commit_operation_id IS NULL OR p_candidate_id IS NULL OR p_verified_subject IS NULL OR p_verified_upstream_session_id IS NULL
    OR p_new_session_id IS NULL OR p_request_fingerprint IS NULL OR p_request_fingerprint !~ '^[0-9a-f]{64}$'
    OR p_new_session_hash IS NULL OR p_new_session_hash !~ '^[0-9a-f]{64}$'
    OR p_token_envelope IS NULL OR octet_length(p_token_envelope)>49152
    OR p_token_envelope !~ '^v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$'
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  v_browser:=jls_auth.lock_oauth(p_browser_hash,p_attempt_id);
  IF v_browser IS NULL OR p_claim_id IS NULL THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  PERFORM jls_auth.lock_upstream_identity(p_verified_upstream_session_id);
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE attempt_id=p_attempt_id;
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
    UPDATE jls_auth.app_sessions SET revoked_at=coalesce(revoked_at,v_now) WHERE session_id=a.prior_session_id;
    INSERT INTO jls_auth.cleanup_work(session_id,token_envelope)
      VALUES (a.prior_session_id,(SELECT c.token_envelope FROM jls_auth.session_credentials c WHERE c.session_id=a.prior_session_id))
      ON CONFLICT (session_id) DO NOTHING;
    UPDATE jls_auth.session_credentials SET state='revoked',token_version=token_version+1,
      refresh_attempt_id=NULL,refresh_lease_expires_at=NULL,refresh_transmission_intent_at=NULL WHERE session_id=a.prior_session_id;
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

CREATE FUNCTION jls_auth.callback_resolve(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid,
  p_commit_operation_id uuid,p_request_fingerprint text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE a jls_auth.oauth_attempts; v_browser uuid;
BEGIN
  v_browser:=jls_auth.lock_oauth(p_browser_hash,p_attempt_id);
  IF v_browser IS NULL OR p_claim_id IS NULL OR p_commit_operation_id IS NULL OR p_request_fingerprint IS NULL
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE attempt_id=p_attempt_id;
  IF a.flow_cookie_hash IS DISTINCT FROM p_flow_hash OR a.claim_id IS DISTINCT FROM p_claim_id THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF a.commit_operation_id IS NULL THEN RETURN '{"kind":"unresolved"}'::jsonb; END IF;
  IF a.commit_operation_id IS DISTINCT FROM p_commit_operation_id OR a.commit_fingerprint IS DISTINCT FROM p_request_fingerprint
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  -- Historical receipt only: current-cookie verification or delivery-retire CAS
  -- decides recovery. No raw bearer or credential is reconstructed here.
  RETURN jsonb_build_object('kind','committed','attemptId',a.attempt_id,'sessionId',a.resulting_session_id,'generation',a.generation_after);
END $$;

CREATE FUNCTION jls_auth.callback_close(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid,
  p_close_operation_id uuid,p_request_fingerprint text,p_candidate_id uuid,p_verified_subject uuid,
  p_verified_upstream_session_id uuid,p_token_envelope text,p_cleanup_environment text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE a jls_auth.oauth_attempts; v_browser uuid; v_binding jsonb; v_identity_live boolean;
BEGIN
  IF p_close_operation_id IS NULL OR p_request_fingerprint IS NULL OR p_request_fingerprint !~ '^[0-9a-f]{64}$'
    OR (p_token_envelope IS NOT NULL AND (p_candidate_id IS NULL OR p_cleanup_environment IS NULL OR p_cleanup_environment !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$' OR p_verified_subject IS NULL OR p_verified_upstream_session_id IS NULL
      OR octet_length(p_token_envelope)>49152 OR p_token_envelope !~ '^orphan-v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$'))
    OR (p_token_envelope IS NULL AND (p_candidate_id IS NOT NULL OR p_cleanup_environment IS NOT NULL OR p_verified_subject IS NOT NULL OR p_verified_upstream_session_id IS NOT NULL))
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  v_browser:=jls_auth.lock_oauth(p_browser_hash,p_attempt_id);
  IF v_browser IS NULL THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  PERFORM jls_auth.lock_upstream_identity(p_verified_upstream_session_id);
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE attempt_id=p_attempt_id;
  IF a.flow_cookie_hash IS DISTINCT FROM p_flow_hash OR a.claim_id IS DISTINCT FROM p_claim_id
    OR a.state IN ('completed','retired') OR a.commit_operation_id IS NOT NULL THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  v_binding:=jsonb_build_array(p_claim_id,p_candidate_id,p_verified_subject,p_verified_upstream_session_id,p_token_envelope,p_cleanup_environment);
  IF a.close_operation_id IS NOT NULL THEN
    IF a.close_operation_id=p_close_operation_id AND a.close_fingerprint=p_request_fingerprint AND a.close_binding=v_binding
      THEN RETURN '{"kind":"closed"}'::jsonb; END IF;
    RETURN '{"kind":"denied"}'::jsonb;
  END IF;
  IF EXISTS (SELECT FROM jls_auth.oauth_attempts WHERE close_operation_id=p_close_operation_id)
    OR (a.exchange_transmission_intent_at IS NULL AND p_token_envelope IS NOT NULL)
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF a.exchange_transmission_intent_at IS NOT NULL THEN
    SELECT EXISTS (SELECT FROM jls_auth.app_sessions WHERE upstream_session_id=p_verified_upstream_session_id AND revoked_at IS NULL) INTO v_identity_live;
    INSERT INTO jls_auth.candidate_cleanup_work(attempt_id,candidate_id,context_environment,auth_subject,upstream_session_id,token_envelope,state,error_category)
      VALUES (a.attempt_id,p_candidate_id,p_cleanup_environment,p_verified_subject,p_verified_upstream_session_id,p_token_envelope,
        CASE WHEN p_token_envelope IS NULL THEN 'credential_unavailable' WHEN v_identity_live THEN 'skipped' ELSE 'pending' END,
        CASE WHEN p_token_envelope IS NULL THEN 'credential_unavailable' WHEN v_identity_live THEN 'identity_in_use' ELSE NULL END);
  END IF;
  UPDATE jls_auth.oauth_attempts SET state='cancelled',close_operation_id=p_close_operation_id,
    close_fingerprint=p_request_fingerprint,close_binding=v_binding WHERE attempt_id=a.attempt_id;
  RETURN '{"kind":"closed"}'::jsonb;
END $$;

CREATE FUNCTION jls_auth.candidate_cleanup_claim(p_attempt_id uuid,p_claim_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE w jls_auth.candidate_cleanup_work; v_now timestamptz;
BEGIN
  IF p_claim_id IS NULL THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  -- Independent work: no owner authority or fabricated app-session is required.
  -- Cleanup workers never take browser/session locks after taking this row lock.
  SELECT * INTO w FROM jls_auth.candidate_cleanup_work WHERE attempt_id=p_attempt_id;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  -- Discovery takes no row lock. Identity precedes work-row locking, while
  -- commit/close acquire identity after their browser/owner/session/attempt locks.
  PERFORM jls_auth.lock_upstream_identity(w.upstream_session_id);
  SELECT * INTO w FROM jls_auth.candidate_cleanup_work WHERE attempt_id=p_attempt_id FOR UPDATE;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  v_now:=clock_timestamp();
  IF w.state='credential_unavailable' THEN RETURN '{"kind":"credential_unavailable"}'::jsonb; END IF;
  IF w.state='skipped' THEN RETURN '{"kind":"skipped"}'::jsonb; END IF;
  IF w.state IN ('completed','failed') THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF EXISTS (SELECT FROM jls_auth.app_sessions WHERE upstream_session_id=w.upstream_session_id AND revoked_at IS NULL) THEN
    UPDATE jls_auth.candidate_cleanup_work SET state='skipped',lease_expires_at=NULL,error_category='identity_in_use' WHERE attempt_id=w.attempt_id;
    RETURN '{"kind":"skipped"}'::jsonb;
  END IF;
  IF w.deadline_at<=v_now THEN
    UPDATE jls_auth.candidate_cleanup_work SET state='failed',lease_expires_at=NULL,error_category='deadline_exceeded' WHERE attempt_id=w.attempt_id;
    RETURN '{"kind":"failed"}'::jsonb;
  END IF;
  IF w.state='claimed' AND w.lease_expires_at>v_now THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF w.attempts>=3 THEN
    UPDATE jls_auth.candidate_cleanup_work SET state='failed',lease_expires_at=NULL,error_category='attempts_exhausted' WHERE attempt_id=w.attempt_id;
    RETURN '{"kind":"failed"}'::jsonb;
  END IF;
  IF p_claim_id=ANY(w.claim_history) THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  UPDATE jls_auth.candidate_cleanup_work SET state='claimed',attempts=attempts+1,claim_id=p_claim_id,claim_history=array_append(claim_history,p_claim_id),
    lease_expires_at=least(deadline_at,v_now+interval '15 seconds') WHERE attempt_id=w.attempt_id;
  RETURN jsonb_build_object('kind','cleanup','attemptId',w.attempt_id,'candidateId',w.candidate_id,'environment',w.context_environment,'authSubject',w.auth_subject,
    'upstreamSessionId',w.upstream_session_id,'scope','local','tokenEnvelope',w.token_envelope,'claimId',p_claim_id);
END $$;

CREATE FUNCTION jls_auth.candidate_cleanup_complete(p_attempt_id uuid,p_claim_id uuid,p_outcome text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE w jls_auth.candidate_cleanup_work; v_now timestamptz; v_state text;
BEGIN
  IF p_claim_id IS NULL OR p_outcome IS NULL OR p_outcome NOT IN ('completed','timeout','transport','rejected')
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO w FROM jls_auth.candidate_cleanup_work WHERE attempt_id=p_attempt_id FOR UPDATE;
  v_now:=clock_timestamp();
  IF w.attempt_id IS NULL OR w.claim_id IS DISTINCT FROM p_claim_id OR w.state<>'claimed'
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF w.deadline_at<=v_now OR (w.lease_expires_at<=v_now AND w.attempts>=3) THEN
    UPDATE jls_auth.candidate_cleanup_work SET state='failed',lease_expires_at=NULL,
      error_category=CASE WHEN w.deadline_at<=v_now THEN 'deadline_exceeded' ELSE 'attempts_exhausted' END WHERE attempt_id=w.attempt_id;
    RETURN '{"kind":"failed"}'::jsonb;
  END IF;
  IF w.lease_expires_at<=v_now THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  v_state:=CASE WHEN p_outcome='completed' THEN 'completed' WHEN p_outcome='rejected' OR w.attempts>=3 OR w.deadline_at<=v_now THEN 'failed' ELSE 'pending' END;
  UPDATE jls_auth.candidate_cleanup_work SET state=v_state,lease_expires_at=NULL,
    error_category=CASE WHEN p_outcome='completed' THEN NULL ELSE p_outcome END WHERE attempt_id=w.attempt_id;
  RETURN jsonb_build_object('kind',v_state);
END $$;

CREATE FUNCTION public.jls_auth_issue_proof_v1(p_issuance_id uuid,p_request_fingerprint text,p_browser_id uuid,p_browser_hash text,
  p_proof_id uuid,p_proof_hash text,p_purpose text,p_cookie_fingerprint text,p_presented_session_hash text,p_operation_id uuid,
  p_expected_token_version bigint,p_expected_control_version bigint,p_expected_dataset_epoch uuid) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.issue_proof(p_issuance_id,p_request_fingerprint,p_browser_id,p_browser_hash,
  p_proof_id,p_proof_hash,p_purpose,p_cookie_fingerprint,p_presented_session_hash,p_operation_id,p_expected_token_version,p_expected_control_version,p_expected_dataset_epoch) $$;
CREATE FUNCTION public.jls_auth_begin_login_v1(p_browser_hash text,p_proof_hash text,p_operation_id uuid,p_cookie_fingerprint text,
  p_attempt_id uuid,p_flow_hash text,p_pkce_envelope text,p_request_fingerprint text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.begin_login(p_browser_hash,p_proof_hash,p_operation_id,p_cookie_fingerprint,p_attempt_id,p_flow_hash,p_pkce_envelope,p_request_fingerprint) $$;
CREATE FUNCTION public.jls_auth_callback_claim_v1(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.callback_claim(p_browser_hash,p_flow_hash,p_attempt_id,p_claim_id) $$;
CREATE FUNCTION public.jls_auth_callback_mark_sent_v1(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.callback_mark_sent(p_browser_hash,p_flow_hash,p_attempt_id,p_claim_id) $$;
CREATE FUNCTION public.jls_auth_callback_commit_v1(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid,
  p_commit_operation_id uuid,p_request_fingerprint text,p_candidate_id uuid,p_verified_subject uuid,p_verified_upstream_session_id uuid,
  p_new_session_id uuid,p_new_session_hash text,p_token_envelope text,p_access_expires_at timestamptz) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.callback_commit(p_browser_hash,p_flow_hash,p_attempt_id,p_claim_id,
  p_commit_operation_id,p_request_fingerprint,p_candidate_id,p_verified_subject,p_verified_upstream_session_id,p_new_session_id,p_new_session_hash,p_token_envelope,p_access_expires_at) $$;
CREATE FUNCTION public.jls_auth_callback_resolve_v1(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid,
  p_commit_operation_id uuid,p_request_fingerprint text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.callback_resolve(p_browser_hash,p_flow_hash,p_attempt_id,p_claim_id,p_commit_operation_id,p_request_fingerprint) $$;
CREATE FUNCTION public.jls_auth_callback_close_v1(p_browser_hash text,p_flow_hash text,p_attempt_id uuid,p_claim_id uuid,
  p_close_operation_id uuid,p_request_fingerprint text,p_candidate_id uuid,p_verified_subject uuid,p_verified_upstream_session_id uuid,p_token_envelope text,p_cleanup_environment text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.callback_close(p_browser_hash,p_flow_hash,p_attempt_id,p_claim_id,p_close_operation_id,p_request_fingerprint,p_candidate_id,p_verified_subject,p_verified_upstream_session_id,p_token_envelope,p_cleanup_environment) $$;
CREATE FUNCTION public.jls_auth_candidate_cleanup_claim_v1(p_attempt_id uuid,p_claim_id uuid) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.candidate_cleanup_claim(p_attempt_id,p_claim_id) $$;
CREATE FUNCTION public.jls_auth_candidate_cleanup_complete_v1(p_attempt_id uuid,p_claim_id uuid,p_outcome text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.candidate_cleanup_complete(p_attempt_id,p_claim_id,p_outcome) $$;

REVOKE ALL ON FUNCTION jls_auth.issue_proof(uuid,text,uuid,text,uuid,text,text,text,text,uuid,bigint,bigint,uuid),
  jls_auth.begin_login(text,text,uuid,text,uuid,text,text,text),jls_auth.lock_oauth(text,uuid),jls_auth.lock_upstream_identity(uuid),
  jls_auth.callback_claim(text,text,uuid,uuid),jls_auth.callback_mark_sent(text,text,uuid,uuid),
  jls_auth.callback_commit(text,text,uuid,uuid,uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz),
  jls_auth.callback_resolve(text,text,uuid,uuid,uuid,text),jls_auth.callback_close(text,text,uuid,uuid,uuid,text,uuid,uuid,uuid,text,text),
  jls_auth.candidate_cleanup_claim(uuid,uuid),jls_auth.candidate_cleanup_complete(uuid,uuid,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION jls_auth.issue_proof(uuid,text,uuid,text,uuid,text,text,text,text,uuid,bigint,bigint,uuid),
  jls_auth.begin_login(text,text,uuid,text,uuid,text,text,text),jls_auth.lock_oauth(text,uuid),jls_auth.lock_upstream_identity(uuid),
  jls_auth.callback_claim(text,text,uuid,uuid),jls_auth.callback_mark_sent(text,text,uuid,uuid),
  jls_auth.callback_commit(text,text,uuid,uuid,uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz),
  jls_auth.callback_resolve(text,text,uuid,uuid,uuid,text),jls_auth.callback_close(text,text,uuid,uuid,uuid,text,uuid,uuid,uuid,text,text),
  jls_auth.candidate_cleanup_claim(uuid,uuid),jls_auth.candidate_cleanup_complete(uuid,uuid,text) TO service_role;
REVOKE ALL ON FUNCTION public.jls_auth_issue_proof_v1(uuid,text,uuid,text,uuid,text,text,text,text,uuid,bigint,bigint,uuid),
  public.jls_auth_begin_login_v1(text,text,uuid,text,uuid,text,text,text),
  public.jls_auth_callback_claim_v1(text,text,uuid,uuid),public.jls_auth_callback_mark_sent_v1(text,text,uuid,uuid),
  public.jls_auth_callback_commit_v1(text,text,uuid,uuid,uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz),
  public.jls_auth_callback_resolve_v1(text,text,uuid,uuid,uuid,text),public.jls_auth_callback_close_v1(text,text,uuid,uuid,uuid,text,uuid,uuid,uuid,text,text),
  public.jls_auth_candidate_cleanup_claim_v1(uuid,uuid),public.jls_auth_candidate_cleanup_complete_v1(uuid,uuid,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.jls_auth_issue_proof_v1(uuid,text,uuid,text,uuid,text,text,text,text,uuid,bigint,bigint,uuid),
  public.jls_auth_begin_login_v1(text,text,uuid,text,uuid,text,text,text),
  public.jls_auth_callback_claim_v1(text,text,uuid,uuid),public.jls_auth_callback_mark_sent_v1(text,text,uuid,uuid),
  public.jls_auth_callback_commit_v1(text,text,uuid,uuid,uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz),
  public.jls_auth_callback_resolve_v1(text,text,uuid,uuid,uuid,text),public.jls_auth_callback_close_v1(text,text,uuid,uuid,uuid,text,uuid,uuid,uuid,text,text),
  public.jls_auth_candidate_cleanup_claim_v1(uuid,uuid),public.jls_auth_candidate_cleanup_complete_v1(uuid,uuid,text) TO service_role;
COMMIT;
