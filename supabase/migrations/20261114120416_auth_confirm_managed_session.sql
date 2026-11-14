BEGIN;

-- Confirm against the managed session visible after the app and upstream identity locks.
-- Supabase Auth can revoke the row independently after this check.
CREATE OR REPLACE FUNCTION jls_auth.confirm_session(p_session_secret_hash text,p_browser_secret_hash text,
  p_expected_token_version bigint,p_expected_control_version bigint,p_expected_dataset_epoch uuid,
  p_verified_subject uuid,p_verified_upstream_session_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE v jsonb; v_session_id uuid; v_upstream_expires_at timestamptz; v_now timestamptz;
BEGIN
  v:=jls_auth.current_credentials(p_session_secret_hash,p_browser_secret_hash,p_expected_token_version,
    p_expected_control_version,p_expected_dataset_epoch);
  IF v->>'kind' IS DISTINCT FROM 'credentials' OR (v->>'authSubject')::uuid IS DISTINCT FROM p_verified_subject
    OR (v->>'upstreamSessionId')::uuid IS DISTINCT FROM p_verified_upstream_session_id
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;

  PERFORM jls_auth.lock_upstream_identity(p_verified_upstream_session_id);
  SELECT upstream.not_after INTO v_upstream_expires_at FROM auth.sessions upstream
    WHERE upstream.id=p_verified_upstream_session_id AND upstream.user_id=p_verified_subject;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;

  -- The app rows are still locked. Recheck only the time-dependent bounds after waiting.
  v_now:=clock_timestamp();
  v_session_id:=(v->>'sessionId')::uuid;
  IF (v_upstream_expires_at IS NOT NULL AND v_upstream_expires_at<=v_now) OR NOT EXISTS (
    SELECT FROM jls_auth.app_sessions s
      JOIN jls_auth.browser_bindings b ON b.browser_id=s.browser_id
      JOIN jls_auth.session_credentials c ON c.session_id=s.session_id
    WHERE s.session_id=v_session_id AND b.expires_at>v_now AND c.access_expires_at>v_now
      AND s.created_at<=v_now AND s.created_at>v_now-interval '7 days'
      AND s.last_activity_at<=v_now AND s.last_activity_at>v_now-interval '24 hours'
  ) THEN RETURN '{"kind":"denied"}'::jsonb; END IF;

  UPDATE jls_auth.app_sessions SET delivery_state='acknowledged',delivery_acknowledged_at=coalesce(delivery_acknowledged_at,v_now)
    WHERE session_id=v_session_id;
  RETURN jsonb_build_object('kind','confirmed','context',jsonb_build_object('ownerId',v->'ownerId','authSubject',v->'authSubject',
    'sessionId',v->'sessionId','datasetEpoch',v->'datasetEpoch'),'tokenVersion',v->'tokenVersion',
    'controlVersion',v->'controlVersion','browserGeneration',v->'browserGeneration');
END $$;

COMMIT;
