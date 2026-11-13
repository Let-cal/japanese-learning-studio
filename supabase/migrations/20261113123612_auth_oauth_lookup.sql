BEGIN;

-- These RPCs discover server-owned identities from cookie and proof hashes.
-- Each result is a snapshot. The existing locked mutations recheck authority.
CREATE FUNCTION public.jls_auth_browser_resolve_v1(p_browser_hash text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$
  WITH lookup_time AS MATERIALIZED (SELECT clock_timestamp() AS now)
  SELECT coalesce((
    SELECT jsonb_build_object('kind','active','browserId',b.browser_id,'generation',b.generation)
    FROM jls_auth.browser_bindings b CROSS JOIN lookup_time t
    WHERE b.secret_hash=p_browser_hash AND b.expires_at>t.now
  ), '{"kind":"absent_or_expired"}'::jsonb)
$$;

CREATE FUNCTION public.jls_auth_action_resolve_v1(p_browser_hash text,p_proof_hash text,p_purpose text,
  p_cookie_fingerprint text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$
  WITH lookup_time AS MATERIALIZED (SELECT clock_timestamp() AS now)
  SELECT coalesce((
    SELECT jsonb_build_object('kind','resolved','browserId',b.browser_id,
      'operationId',p.operation_id,'generation',b.generation)
    FROM jls_auth.browser_bindings b
    JOIN jls_auth.csrf_proofs p ON p.browser_id=b.browser_id
    LEFT JOIN jls_auth.action_receipts r ON p_purpose='logout' AND r.operation_id=p.operation_id
    CROSS JOIN lookup_time t
    WHERE b.secret_hash=p_browser_hash AND p.secret_hash=p_proof_hash AND p.purpose=p_purpose
      AND p_purpose IN ('login','logout') AND p.operation_id IS NOT NULL
      AND b.expires_at>t.now
      AND CASE WHEN r.operation_id IS NOT NULL THEN
        r.proof_id=p.proof_id AND r.browser_id=b.browser_id AND r.generation_before=p.generation
        AND r.expires_at>t.now AND r.generation_after=b.generation AND b.current_session_id IS NULL
        AND (p_cookie_fingerprint=r.cookie_fingerprint OR p_cookie_fingerprint='absent')
      ELSE
        p.consumed_at IS NULL AND p.issued_at<=t.now AND p.expires_at>t.now
        AND p.generation=b.generation AND b.generation<9007199254740989
        AND p.cookie_fingerprint=p_cookie_fingerprint
        AND (p_purpose='login' OR (
          p.session_id IS NOT DISTINCT FROM b.current_session_id
          AND (p.session_id IS NOT NULL OR p.cookie_fingerprint='absent')
        ))
      END
  ), '{"kind":"denied"}'::jsonb)
$$;

CREATE FUNCTION public.jls_auth_callback_inspect_v1(p_browser_hash text,p_flow_hash text,
  p_presented_session_hash text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$
  WITH lookup_time AS MATERIALIZED (SELECT clock_timestamp() AS now)
  SELECT coalesce((
    SELECT CASE
      WHEN b.expires_at<=t.now OR a.issued_at>t.now OR a.expires_at<=t.now
        OR o.active IS DISTINCT FROM true OR o.control_version IS DISTINCT FROM a.expected_control_version
        OR o.current_dataset_epoch IS NULL OR o.current_dataset_epoch IS DISTINCT FROM a.expected_dataset_epoch
        THEN '{"kind":"restart_required"}'::jsonb
      WHEN a.state='completed' THEN
        CASE WHEN s.secret_hash=p_presented_session_hash AND b.current_session_id=s.session_id
          AND b.generation=a.generation_after AND s.browser_generation=b.generation
          AND s.owner_id=o.owner_id AND s.auth_subject=o.auth_subject AND s.revoked_at IS NULL
          AND s.created_at<=t.now AND s.last_activity_at<=t.now
          AND s.created_at>t.now-interval '7 days' AND s.last_activity_at>t.now-interval '24 hours'
        THEN jsonb_build_object('kind','completed_with_cookie','attemptId',a.attempt_id,
          'sessionId',s.session_id,'generation',b.generation)
        ELSE '{"kind":"restart_required"}'::jsonb END
      WHEN a.generation_before<>b.generation OR b.current_session_id IS DISTINCT FROM a.prior_session_id
        THEN '{"kind":"restart_required"}'::jsonb
      WHEN a.state='pending' AND a.exchange_transmission_intent_at IS NULL
        THEN jsonb_build_object('kind','pending','attemptId',a.attempt_id,'browserId',b.browser_id)
      WHEN a.state IN ('claimed','exchange_unknown') THEN '{"kind":"in_progress"}'::jsonb
      ELSE '{"kind":"restart_required"}'::jsonb
    END
    FROM jls_auth.browser_bindings b
    JOIN jls_auth.oauth_attempts a ON a.browser_id=b.browser_id
    JOIN jls_auth.owner_control o ON o.owner_id=a.expected_owner_id
    LEFT JOIN jls_auth.app_sessions s ON s.session_id=a.resulting_session_id AND s.browser_id=b.browser_id
    CROSS JOIN lookup_time t
    WHERE b.secret_hash=p_browser_hash AND a.flow_cookie_hash=p_flow_hash AND a.purpose='login'
      AND (p_presented_session_hash IS NULL OR p_presented_session_hash ~ '^[0-9a-f]{64}$')
  ), '{"kind":"denied"}'::jsonb)
$$;

REVOKE ALL ON FUNCTION public.jls_auth_browser_resolve_v1(text),
  public.jls_auth_action_resolve_v1(text,text,text,text),
  public.jls_auth_callback_inspect_v1(text,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.jls_auth_browser_resolve_v1(text),
  public.jls_auth_action_resolve_v1(text,text,text,text),
  public.jls_auth_callback_inspect_v1(text,text,text) TO service_role;

COMMIT;
