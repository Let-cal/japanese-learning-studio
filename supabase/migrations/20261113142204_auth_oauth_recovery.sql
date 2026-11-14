BEGIN;

CREATE TABLE jls_auth.oauth_recovery_receipts (
  operation_id uuid PRIMARY KEY,
  proof_id uuid NOT NULL UNIQUE,
  browser_id uuid NOT NULL REFERENCES jls_auth.browser_bindings(browser_id),
  attempt_id uuid NOT NULL REFERENCES jls_auth.oauth_attempts(attempt_id),
  generation_before bigint NOT NULL,
  generation_after bigint NOT NULL,
  current_session_id uuid,
  cookie_fingerprint text NOT NULL,
  presented_session_hash text CHECK (presented_session_hash ~ '^[0-9a-f]{64}$'),
  superseded boolean NOT NULL DEFAULT false,
  committed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  FOREIGN KEY (proof_id,browser_id,generation_before,operation_id,cookie_fingerprint)
    REFERENCES jls_auth.csrf_proofs(proof_id,browser_id,generation,operation_id,cookie_fingerprint),
  FOREIGN KEY (current_session_id,browser_id,generation_after)
    REFERENCES jls_auth.app_sessions(session_id,browser_id,browser_generation),
  CHECK (generation_after IN (generation_before,generation_before+1)),
  CHECK (expires_at>committed_at AND expires_at<=committed_at+interval '15 minutes')
);
CREATE INDEX oauth_recovery_receipts_current ON jls_auth.oauth_recovery_receipts(browser_id,generation_after)
  WHERE NOT superseded;

-- An expired exchange keeps its possible-send marker. This historical record
-- preserves the uncertainty without claiming custody of an upstream pair.
-- The original claimant can still record a verified candidate via callback_close.
CREATE TABLE jls_auth.oauth_exchange_expirations (
  attempt_id uuid PRIMARY KEY REFERENCES jls_auth.oauth_attempts(attempt_id),
  settled_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'credential_unavailable' CHECK (state='credential_unavailable')
);
ALTER TABLE jls_auth.oauth_recovery_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.oauth_recovery_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.oauth_exchange_expirations ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.oauth_exchange_expirations FORCE ROW LEVEL SECURITY;
CREATE POLICY service_control ON jls_auth.oauth_recovery_receipts TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.oauth_exchange_expirations TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON jls_auth.oauth_recovery_receipts,jls_auth.oauth_exchange_expirations FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT,INSERT ON jls_auth.oauth_recovery_receipts,jls_auth.oauth_exchange_expirations TO service_role;
GRANT UPDATE (superseded) ON jls_auth.oauth_recovery_receipts TO service_role;

CREATE FUNCTION public.jls_auth_recover_login_v1(p_browser_hash text,p_flow_hash text,p_proof_hash text,
  p_cookie_fingerprint text,p_presented_session_hash text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE b jls_auth.browser_bindings; a jls_auth.oauth_attempts; o jls_auth.owner_control;
  s jls_auth.app_sessions; p jls_auth.csrf_proofs; r jls_auth.oauth_recovery_receipts;
  v_now timestamptz; v_open boolean; v_generation bigint; v_current_session_id uuid;
BEGIN
  IF p_browser_hash IS NULL OR p_browser_hash !~ '^[0-9a-f]{64}$'
    OR p_flow_hash IS NULL OR p_flow_hash !~ '^[0-9a-f]{64}$'
    OR p_proof_hash IS NULL OR p_proof_hash !~ '^[0-9a-f]{64}$'
    OR p_cookie_fingerprint IS NULL OR (p_cookie_fingerprint<>'absent' AND p_cookie_fingerprint !~ '^present:[0-9a-f]{64}$')
    OR (p_cookie_fingerprint='absent' AND p_presented_session_hash IS NOT NULL)
    OR (p_presented_session_hash IS NOT NULL AND p_presented_session_hash !~ '^[0-9a-f]{64}$')
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;

  SELECT * INTO b FROM jls_auth.browser_bindings WHERE secret_hash=p_browser_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  -- Discover the target under the browser lock, then follow the established
  -- owner, session, credential, proof, attempt and upstream identity ordering.
  SELECT * INTO a FROM jls_auth.oauth_attempts
    WHERE browser_id=b.browser_id AND flow_cookie_hash=p_flow_hash AND purpose='login';
  IF NOT FOUND OR a.expected_owner_id IS NULL THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO o FROM jls_auth.owner_control WHERE owner_id=a.expected_owner_id FOR UPDATE;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=b.current_session_id FOR UPDATE;
  IF a.state='completed' AND a.resulting_session_id=s.session_id THEN
    PERFORM jls_auth.lock_session_revocation(s.session_id);
  END IF;
  SELECT * INTO p FROM jls_auth.csrf_proofs WHERE secret_hash=p_proof_hash AND browser_id=b.browser_id
    AND purpose='login' AND cookie_fingerprint=p_cookie_fingerprint AND operation_id IS NOT NULL FOR UPDATE;
  IF NOT FOUND OR NOT EXISTS (
    SELECT FROM jls_auth.proof_issuances i WHERE i.proof_id=p.proof_id
      AND i.request_fingerprint=encode(sha256(convert_to('jls-oauth-recovery-proof-v1:'||p_proof_hash||':'||p_flow_hash,'UTF8')),'hex')
      AND i.request_binding->6=(jsonb_build_array(p_presented_session_hash)->0)
  ) THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE attempt_id=a.attempt_id FOR UPDATE;
  SELECT EXISTS (SELECT FROM jls_auth.oauth_attempts WHERE browser_id=b.browser_id AND attempt_id<>a.attempt_id
    AND state IN ('pending','claimed','exchange_unknown')) INTO v_open;
  SELECT * INTO r FROM jls_auth.oauth_recovery_receipts WHERE operation_id=p.operation_id;
  v_now:=clock_timestamp();
  IF b.expires_at<=v_now OR v_open OR o.active IS DISTINCT FROM true
    OR o.control_version IS DISTINCT FROM a.expected_control_version
    OR o.current_dataset_epoch IS NULL OR o.current_dataset_epoch IS DISTINCT FROM a.expected_dataset_epoch
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  IF r.operation_id IS NOT NULL THEN
    IF NOT r.superseded AND r.proof_id=p.proof_id AND r.browser_id=b.browser_id AND r.attempt_id=a.attempt_id
      AND r.expires_at>v_now AND r.generation_after=b.generation
      AND r.current_session_id IS NOT DISTINCT FROM b.current_session_id
      AND r.cookie_fingerprint=p_cookie_fingerprint AND r.presented_session_hash IS NOT DISTINCT FROM p_presented_session_hash
      AND a.state IN ('cancelled','retired') THEN RETURN '{"kind":"recovered"}'::jsonb; END IF;
    RETURN '{"kind":"denied"}'::jsonb;
  END IF;
  IF p.consumed_at IS NOT NULL OR p.expires_at<=v_now OR p.issued_at>v_now OR p.issued_at<=a.issued_at
    OR p.generation<>b.generation THEN RETURN '{"kind":"denied"}'::jsonb; END IF;

  v_generation:=b.generation;
  v_current_session_id:=b.current_session_id;
  IF a.state='completed' THEN
    IF s.session_id IS NULL OR a.resulting_session_id IS DISTINCT FROM s.session_id
      OR a.generation_after IS DISTINCT FROM b.generation OR s.browser_generation<>b.generation
      OR s.owner_id<>o.owner_id OR s.auth_subject<>o.auth_subject OR s.revoked_at IS NOT NULL
      OR s.delivery_state<>'unacknowledged' OR s.secret_hash IS NOT DISTINCT FROM p_presented_session_hash
      OR b.generation>=9007199254740990
      OR EXISTS (SELECT FROM jls_auth.oauth_attempts WHERE browser_id=b.browser_id AND generation_before=a.generation_after
        AND attempt_id<>a.attempt_id) THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    IF s.created_at>v_now-interval '30 seconds' THEN RETURN '{"kind":"in_progress"}'::jsonb; END IF;
    PERFORM jls_auth.lock_upstream_identity(s.upstream_session_id);
    v_now:=clock_timestamp();
    IF b.expires_at<=v_now OR p.expires_at<=v_now THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    PERFORM jls_auth.revoke_locked_session(s.session_id,v_now);
    v_generation:=b.generation+1;
    v_current_session_id:=NULL;
    UPDATE jls_auth.browser_bindings SET generation=v_generation,current_session_id=NULL WHERE browser_id=b.browser_id;
    UPDATE jls_auth.oauth_attempts SET state='retired' WHERE attempt_id=a.attempt_id;
  ELSIF a.state IN ('pending','claimed','exchange_unknown') THEN
    IF a.generation_before<>b.generation OR a.prior_session_id IS DISTINCT FROM b.current_session_id
      OR (a.state IN ('pending','claimed') AND a.exchange_transmission_intent_at IS NOT NULL)
      OR (a.state='exchange_unknown' AND a.exchange_transmission_intent_at IS NULL)
      THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
    IF a.state IN ('claimed','exchange_unknown') AND a.expires_at>v_now THEN RETURN '{"kind":"in_progress"}'::jsonb; END IF;
    IF a.state='exchange_unknown' THEN
      INSERT INTO jls_auth.oauth_exchange_expirations(attempt_id,settled_at) VALUES (a.attempt_id,v_now);
    END IF;
    UPDATE jls_auth.oauth_attempts SET state='cancelled' WHERE attempt_id=a.attempt_id;
  ELSE
    RETURN '{"kind":"denied"}'::jsonb;
  END IF;

  UPDATE jls_auth.csrf_proofs SET consumed_at=v_now WHERE proof_id=p.proof_id;
  INSERT INTO jls_auth.oauth_recovery_receipts(operation_id,proof_id,browser_id,attempt_id,generation_before,
    generation_after,current_session_id,cookie_fingerprint,presented_session_hash,committed_at,expires_at)
    VALUES (p.operation_id,p.proof_id,b.browser_id,a.attempt_id,b.generation,v_generation,v_current_session_id,
      p.cookie_fingerprint,p_presented_session_hash,v_now,v_now+interval '15 minutes');
  RETURN '{"kind":"recovered"}'::jsonb;
END $$;

REVOKE ALL ON FUNCTION public.jls_auth_recover_login_v1(text,text,text,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.jls_auth_recover_login_v1(text,text,text,text,text) TO service_role;

-- A new login proof can settle an expired send even after the old flow cookie
-- has expired. The original attempt remains fenced from exchange and commit.
CREATE OR REPLACE FUNCTION jls_auth.begin_login(p_browser_hash text,p_proof_hash text,p_operation_id uuid,p_cookie_fingerprint text,
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

  WITH expired AS (
    UPDATE jls_auth.oauth_attempts SET state='cancelled' WHERE browser_id=b.browser_id AND purpose='login'
      AND state='exchange_unknown' AND generation_before=b.generation
      AND prior_session_id IS NOT DISTINCT FROM b.current_session_id AND expires_at<=v_now
      AND exchange_transmission_intent_at IS NOT NULL
      RETURNING attempt_id
  )
  INSERT INTO jls_auth.oauth_exchange_expirations(attempt_id,settled_at) SELECT attempt_id,v_now FROM expired;
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
  -- The browser lock serializes this irreversible replay fence with recovery.
  UPDATE jls_auth.oauth_recovery_receipts SET superseded=true
    WHERE browser_id=b.browser_id AND generation_after=b.generation AND NOT superseded;
  UPDATE jls_auth.csrf_proofs SET consumed_at=v_now WHERE proof_id=p.proof_id;
  RETURN jsonb_build_object('kind','begun','attemptId',a.attempt_id,'generation',a.generation_before,
    'expiresAt',floor(extract(epoch FROM a.expires_at)*1000)::bigint);
END $$;

COMMIT;
