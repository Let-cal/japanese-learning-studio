-- Source-only durable Auth foundation. No owner enrollment, key, hosted configuration,
-- managed auth.sessions access, OAuth commit or refresh mutation is installed here.
-- Keep jls_auth OUT of PostgREST exposed_schemas. Public wrappers are the fixed API.
BEGIN;
CREATE SCHEMA jls_auth;
REVOKE ALL ON SCHEMA jls_auth FROM PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA jls_auth TO service_role;

CREATE TABLE jls_auth.owner_control (
  owner_id uuid PRIMARY KEY,
  auth_subject uuid NOT NULL,
  active boolean NOT NULL DEFAULT false,
  current_dataset_epoch uuid,
  control_version bigint NOT NULL DEFAULT 0 CHECK (control_version BETWEEN 0 AND 9007199254740991),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (owner_id, auth_subject),
  CHECK (NOT active OR current_dataset_epoch IS NOT NULL)
);
CREATE UNIQUE INDEX owner_control_one_active ON jls_auth.owner_control ((true)) WHERE active;
CREATE TABLE jls_auth.datasets (
  owner_id uuid NOT NULL REFERENCES jls_auth.owner_control(owner_id),
  dataset_epoch uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (owner_id, dataset_epoch)
);
ALTER TABLE jls_auth.owner_control ADD CONSTRAINT owner_current_dataset_fk
  FOREIGN KEY (owner_id,current_dataset_epoch) REFERENCES jls_auth.datasets(owner_id,dataset_epoch);

CREATE TABLE jls_auth.browser_bindings (
  browser_id uuid PRIMARY KEY,
  secret_hash text NOT NULL UNIQUE CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
  generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9007199254740990),
  current_session_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > created_at)
);
CREATE TABLE jls_auth.app_sessions (
  session_id uuid PRIMARY KEY,
  secret_hash text NOT NULL UNIQUE CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
  owner_id uuid NOT NULL,
  auth_subject uuid NOT NULL,
  upstream_session_id uuid NOT NULL,
  browser_id uuid NOT NULL REFERENCES jls_auth.browser_bindings(browser_id),
  browser_generation bigint NOT NULL CHECK (browser_generation BETWEEN 0 AND 9007199254740990),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_activity_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  reauthenticated_at timestamptz,
  revoked_at timestamptz,
  delivery_state text NOT NULL DEFAULT 'unacknowledged' CHECK (delivery_state IN ('unacknowledged','acknowledged')),
  delivery_acknowledged_at timestamptz,
  FOREIGN KEY (owner_id,auth_subject) REFERENCES jls_auth.owner_control(owner_id,auth_subject),
  UNIQUE (session_id,browser_id),
  UNIQUE (session_id,browser_id,browser_generation),
  CHECK (last_activity_at >= created_at),
  CHECK (reauthenticated_at IS NULL OR reauthenticated_at >= created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  CHECK ((delivery_state='acknowledged') = (delivery_acknowledged_at IS NOT NULL)),
  CHECK (delivery_acknowledged_at IS NULL OR delivery_acknowledged_at >= created_at)
);
CREATE UNIQUE INDEX app_sessions_live_upstream ON jls_auth.app_sessions(upstream_session_id) WHERE revoked_at IS NULL;
CREATE INDEX app_sessions_owner ON jls_auth.app_sessions(owner_id,auth_subject);
CREATE INDEX app_sessions_browser ON jls_auth.app_sessions(browser_id,browser_generation,session_id);
ALTER TABLE jls_auth.browser_bindings ADD CONSTRAINT browser_current_session_fk
  FOREIGN KEY (current_session_id,browser_id) REFERENCES jls_auth.app_sessions(session_id,browser_id);

CREATE TABLE jls_auth.session_credentials (
  session_id uuid PRIMARY KEY REFERENCES jls_auth.app_sessions(session_id),
  token_envelope text NOT NULL CHECK (octet_length(token_envelope) BETWEEN 1 AND 49152
    AND token_envelope ~ '^v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$'),
  token_version bigint NOT NULL DEFAULT 0 CHECK (token_version BETWEEN 0 AND 9007199254740990),
  access_expires_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'usable' CHECK (state IN ('usable','prepared','sent_or_unknown','uncertain','reauthentication_required','revoked')),
  refresh_attempt_id uuid,
  refresh_lease_expires_at timestamptz,
  refresh_transmission_intent_at timestamptz,
  CHECK ((state NOT IN ('prepared','sent_or_unknown')) OR (refresh_attempt_id IS NOT NULL AND refresh_lease_expires_at IS NOT NULL)),
  CHECK (state <> 'prepared' OR refresh_transmission_intent_at IS NULL),
  CHECK (state <> 'sent_or_unknown' OR refresh_transmission_intent_at IS NOT NULL),
  CHECK (state <> 'usable' OR (refresh_attempt_id IS NULL AND refresh_lease_expires_at IS NULL AND refresh_transmission_intent_at IS NULL))
);
CREATE TABLE jls_auth.csrf_proofs (
  proof_id uuid PRIMARY KEY,
  secret_hash text NOT NULL UNIQUE CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
  browser_id uuid NOT NULL REFERENCES jls_auth.browser_bindings(browser_id),
  generation bigint NOT NULL CHECK (generation BETWEEN 0 AND 9007199254740990),
  purpose text NOT NULL CHECK (purpose IN ('login','logout','mutation')),
  cookie_fingerprint text NOT NULL CHECK (cookie_fingerprint='absent' OR cookie_fingerprint ~ '^present:[0-9a-f]{64}$'),
  session_id uuid,
  operation_id uuid,
  issued_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT (statement_timestamp()+interval '15 minutes'),
  consumed_at timestamptz,
  FOREIGN KEY (session_id,browser_id,generation) REFERENCES jls_auth.app_sessions(session_id,browser_id,browser_generation),
  UNIQUE (proof_id,browser_id,generation,operation_id,cookie_fingerprint),
  CHECK (purpose='mutation' OR operation_id IS NOT NULL),
  CHECK (purpose<>'mutation' OR session_id IS NOT NULL),
  CHECK (cookie_fingerprint<>'absent' OR session_id IS NULL),
  CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '15 minutes'),
  CHECK (consumed_at IS NULL OR consumed_at >= issued_at)
);
CREATE UNIQUE INDEX csrf_auth_operation ON jls_auth.csrf_proofs(operation_id) WHERE operation_id IS NOT NULL;
CREATE INDEX csrf_browser_generation ON jls_auth.csrf_proofs(browser_id,generation);

CREATE TABLE jls_auth.oauth_attempts (
  attempt_id uuid PRIMARY KEY,
  browser_id uuid NOT NULL REFERENCES jls_auth.browser_bindings(browser_id),
  generation_before bigint NOT NULL CHECK (generation_before BETWEEN 0 AND 9007199254740989),
  generation_after bigint,
  purpose text NOT NULL CHECK (purpose IN ('login','reauthentication')),
  prior_session_id uuid,
  flow_cookie_hash text NOT NULL UNIQUE CHECK (flow_cookie_hash ~ '^[0-9a-f]{64}$'),
  pkce_envelope text NOT NULL CHECK (octet_length(pkce_envelope) BETWEEN 1 AND 2048
    AND pkce_envelope ~ '^pkce-v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{58}\.[A-Za-z0-9_-]{22}$'),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','claimed','exchange_unknown','completed','cancelled','retired')),
  claim_id uuid,
  claimed_at timestamptz,
  resulting_session_id uuid,
  issued_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT (statement_timestamp()+interval '10 minutes'),
  FOREIGN KEY (prior_session_id,browser_id,generation_before) REFERENCES jls_auth.app_sessions(session_id,browser_id,browser_generation),
  FOREIGN KEY (resulting_session_id,browser_id,generation_after) REFERENCES jls_auth.app_sessions(session_id,browser_id,browser_generation),
  CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '10 minutes'),
  CHECK (generation_after IS NULL OR generation_after=generation_before+1),
  CHECK ((state IN ('completed','retired')) = (resulting_session_id IS NOT NULL AND generation_after IS NOT NULL)),
  CHECK (state<>'claimed' OR (claim_id IS NOT NULL AND claimed_at IS NOT NULL))
);
CREATE UNIQUE INDEX oauth_one_outstanding ON jls_auth.oauth_attempts(browser_id) WHERE state IN ('pending','claimed');
CREATE INDEX oauth_result ON jls_auth.oauth_attempts(resulting_session_id);
CREATE INDEX oauth_prior ON jls_auth.oauth_attempts(prior_session_id);

CREATE TABLE jls_auth.action_receipts (
  operation_id uuid PRIMARY KEY,
  proof_id uuid NOT NULL UNIQUE,
  browser_id uuid NOT NULL REFERENCES jls_auth.browser_bindings(browser_id),
  generation_before bigint NOT NULL,
  generation_after bigint NOT NULL,
  cookie_fingerprint text NOT NULL,
  target_session_id uuid,
  outcome text NOT NULL CHECK (outcome IN ('revoked','absent')),
  committed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT (statement_timestamp()+interval '15 minutes'),
  FOREIGN KEY (proof_id,browser_id,generation_before,operation_id,cookie_fingerprint)
    REFERENCES jls_auth.csrf_proofs(proof_id,browser_id,generation,operation_id,cookie_fingerprint),
  FOREIGN KEY (target_session_id,browser_id,generation_before) REFERENCES jls_auth.app_sessions(session_id,browser_id,browser_generation),
  CHECK (generation_before BETWEEN 0 AND 9007199254740989 AND generation_after=generation_before+1),
  CHECK ((outcome='absent') = (target_session_id IS NULL)),
  CHECK (expires_at > committed_at AND expires_at <= committed_at + interval '15 minutes')
);
CREATE INDEX receipt_browser ON jls_auth.action_receipts(browser_id,generation_after);
CREATE TABLE jls_auth.cleanup_work (
  session_id uuid PRIMARY KEY REFERENCES jls_auth.app_sessions(session_id),
  token_envelope text CHECK (token_envelope IS NULL OR (octet_length(token_envelope) BETWEEN 1 AND 49152
    AND token_envelope ~ '^v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$')),
  scope text NOT NULL DEFAULT 'local' CHECK (scope='local'),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','claimed','completed','failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
  claim_id uuid,
  lease_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  deadline_at timestamptz NOT NULL DEFAULT (statement_timestamp()+interval '1 hour'),
  error_category text CHECK (error_category IN ('timeout','transport','rejected','credential_unavailable')),
  CHECK (deadline_at > created_at AND deadline_at <= created_at + interval '1 hour'),
  CHECK (state<>'claimed' OR (claim_id IS NOT NULL AND lease_expires_at IS NOT NULL))
);

-- No authenticated/anon policies. The service credential is intentionally broad;
-- invoker functions need real underlying privileges, not a definer escape hatch.
ALTER TABLE jls_auth.owner_control ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.owner_control FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.datasets FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.browser_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.browser_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.app_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.app_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.session_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.session_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.csrf_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.csrf_proofs FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.oauth_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.oauth_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.action_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.action_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.cleanup_work ENABLE ROW LEVEL SECURITY;
ALTER TABLE jls_auth.cleanup_work FORCE ROW LEVEL SECURITY;
CREATE POLICY service_control ON jls_auth.owner_control TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.datasets TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.browser_bindings TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.app_sessions TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.session_credentials TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.csrf_proofs TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.oauth_attempts TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.action_receipts TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_control ON jls_auth.cleanup_work TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON ALL TABLES IN SCHEMA jls_auth FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT ON jls_auth.owner_control,jls_auth.datasets,jls_auth.browser_bindings,
  jls_auth.app_sessions,jls_auth.session_credentials,jls_auth.csrf_proofs,
  jls_auth.oauth_attempts,jls_auth.action_receipts,jls_auth.cleanup_work TO service_role;
-- SELECT FOR UPDATE needs some UPDATE privilege even where the routine only locks.
-- The columns below are precisely the current routines' locking/mutation capabilities.
GRANT UPDATE (control_version) ON jls_auth.owner_control TO service_role;
GRANT UPDATE (generation,current_session_id) ON jls_auth.browser_bindings TO service_role;
GRANT UPDATE (revoked_at,delivery_state,delivery_acknowledged_at) ON jls_auth.app_sessions TO service_role;
GRANT UPDATE (state,token_version,refresh_attempt_id,refresh_lease_expires_at,refresh_transmission_intent_at) ON jls_auth.session_credentials TO service_role;
GRANT UPDATE (consumed_at) ON jls_auth.csrf_proofs TO service_role;
GRANT UPDATE (state) ON jls_auth.oauth_attempts TO service_role;
GRANT INSERT ON jls_auth.action_receipts,jls_auth.cleanup_work TO service_role;

CREATE FUNCTION jls_auth.session_lookup(p_session_secret_hash text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE v_now timestamptz := clock_timestamp(); v_result jsonb;
BEGIN
  IF p_session_secret_hash IS NULL OR p_session_secret_hash !~ '^[0-9a-f]{64}$' THEN
    RETURN jsonb_build_object('kind','absent','now',floor(extract(epoch FROM v_now)*1000)::bigint);
  END IF;
  SELECT jsonb_build_object('kind','found','now',floor(extract(epoch FROM v_now)*1000)::bigint,
    'session',jsonb_build_object('sessionId',s.session_id,'ownerId',s.owner_id,'authSubject',s.auth_subject,
      'upstreamSessionId',s.upstream_session_id,'createdAt',floor(extract(epoch FROM s.created_at)*1000)::bigint,
      'lastActivityAt',floor(extract(epoch FROM s.last_activity_at)*1000)::bigint,
      'reauthenticatedAt',floor(extract(epoch FROM s.reauthenticated_at)*1000)::bigint,
      'revokedAt',floor(extract(epoch FROM s.revoked_at)*1000)::bigint),
    'currentOwner',CASE WHEN o.owner_id IS NULL THEN NULL ELSE jsonb_build_object('ownerId',o.owner_id,'authorizedAuthSubject',o.auth_subject,'active',o.active) END,
    'currentDataset',CASE WHEN d.dataset_epoch IS NULL THEN NULL ELSE jsonb_build_object('ownerId',d.owner_id,'activeDatasetEpoch',d.dataset_epoch) END,
    'credential',jsonb_build_object('state',CASE WHEN c.state='usable' AND c.access_expires_at>v_now THEN 'usable'
      WHEN c.state='usable' THEN 'refreshRequired' ELSE 'reauthenticationRequired' END,
      'accessExpiresAt',floor(extract(epoch FROM c.access_expires_at)*1000)::bigint)) INTO v_result
  FROM jls_auth.app_sessions s LEFT JOIN jls_auth.owner_control o ON o.owner_id=s.owner_id
  LEFT JOIN jls_auth.datasets d ON d.owner_id=o.owner_id AND d.dataset_epoch=o.current_dataset_epoch
  LEFT JOIN jls_auth.session_credentials c ON c.session_id=s.session_id WHERE s.secret_hash=p_session_secret_hash;
  RETURN coalesce(v_result,jsonb_build_object('kind','absent','now',floor(extract(epoch FROM v_now)*1000)::bigint));
END $$;

-- A distinct, safe metadata capability supplies CAS inputs. It never authorizes,
-- returns an envelope/hash, or defaults missing versions to zero.
CREATE FUNCTION jls_auth.session_snapshot(p_session_secret_hash text,p_browser_secret_hash text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE v_result jsonb; v_now timestamptz:=clock_timestamp();
BEGIN
  SELECT jsonb_build_object('kind','snapshot','now',floor(extract(epoch FROM v_now)*1000)::bigint,
    'session',jsonb_build_object('sessionId',s.session_id,'ownerId',s.owner_id,'authSubject',s.auth_subject,
      'upstreamSessionId',s.upstream_session_id,'createdAt',floor(extract(epoch FROM s.created_at)*1000)::bigint,
      'lastActivityAt',floor(extract(epoch FROM s.last_activity_at)*1000)::bigint,
      'reauthenticatedAt',floor(extract(epoch FROM s.reauthenticated_at)*1000)::bigint,
      'revokedAt',floor(extract(epoch FROM s.revoked_at)*1000)::bigint,
      'deliveryState',s.delivery_state,'deliveryAcknowledgedAt',floor(extract(epoch FROM s.delivery_acknowledged_at)*1000)::bigint),
    'owner',jsonb_build_object('ownerId',o.owner_id,'authSubject',o.auth_subject,'active',o.active,
      'controlVersion',o.control_version,'datasetEpoch',o.current_dataset_epoch),
    'browser',jsonb_build_object('browserId',b.browser_id,'generation',b.generation,'sessionGeneration',s.browser_generation,
      'currentSessionId',b.current_session_id,'expiresAt',floor(extract(epoch FROM b.expires_at)*1000)::bigint),
    'credential',jsonb_build_object('tokenVersion',c.token_version,'state',c.state,
      'accessExpiresAt',floor(extract(epoch FROM c.access_expires_at)*1000)::bigint,
      'refreshAttemptId',c.refresh_attempt_id,'refreshLeaseExpiresAt',floor(extract(epoch FROM c.refresh_lease_expires_at)*1000)::bigint,
      'refreshTransmissionIntentAt',floor(extract(epoch FROM c.refresh_transmission_intent_at)*1000)::bigint)) INTO v_result
  FROM jls_auth.app_sessions s JOIN jls_auth.browser_bindings b ON b.browser_id=s.browser_id
  JOIN jls_auth.owner_control o ON o.owner_id=s.owner_id
  JOIN jls_auth.session_credentials c ON c.session_id=s.session_id
  WHERE s.secret_hash=p_session_secret_hash AND b.secret_hash=p_browser_secret_hash;
  RETURN coalesce(v_result,jsonb_build_object('kind','absent','now',floor(extract(epoch FROM v_now)*1000)::bigint));
END $$;

-- Locks browser -> owner -> session -> credential. No caller clock and no decrypt.
CREATE FUNCTION jls_auth.current_credentials(p_session_secret_hash text,p_browser_secret_hash text,
  p_expected_token_version bigint,p_expected_control_version bigint,p_expected_dataset_epoch uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE b jls_auth.browser_bindings; s jls_auth.app_sessions; o jls_auth.owner_control;
  c jls_auth.session_credentials; v_now timestamptz;
BEGIN
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE secret_hash=p_browser_secret_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE secret_hash=p_session_secret_hash AND browser_id=b.browser_id;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO o FROM jls_auth.owner_control WHERE owner_id=s.owner_id FOR UPDATE;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=s.session_id FOR UPDATE;
  v_now:=clock_timestamp();
  IF o.active IS DISTINCT FROM true OR o.auth_subject<>s.auth_subject OR o.control_version IS DISTINCT FROM p_expected_control_version
    OR o.current_dataset_epoch IS DISTINCT FROM p_expected_dataset_epoch OR p_expected_dataset_epoch IS NULL
    OR b.current_session_id IS DISTINCT FROM s.session_id OR b.generation<>s.browser_generation OR b.expires_at<=v_now
    OR s.revoked_at IS NOT NULL OR s.created_at>v_now OR s.last_activity_at>v_now
    OR s.created_at<=v_now-interval '7 days' OR s.last_activity_at<=v_now-interval '24 hours'
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO c FROM jls_auth.session_credentials WHERE session_id=s.session_id FOR UPDATE;
  v_now:=clock_timestamp();
  IF NOT FOUND OR c.state<>'usable' OR c.access_expires_at<=v_now
    OR b.expires_at<=v_now
    OR s.created_at<=v_now-interval '7 days' OR s.last_activity_at<=v_now-interval '24 hours'
    OR c.token_version IS DISTINCT FROM p_expected_token_version THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  RETURN jsonb_build_object('kind','credentials','now',floor(extract(epoch FROM v_now)*1000)::bigint,'sessionId',s.session_id,'ownerId',s.owner_id,'authSubject',s.auth_subject,
    'upstreamSessionId',s.upstream_session_id,'datasetEpoch',o.current_dataset_epoch,'controlVersion',o.control_version,
    'browserGeneration',b.generation,'tokenVersion',c.token_version,'tokenEnvelope',c.token_envelope,
    'accessExpiresAt',floor(extract(epoch FROM c.access_expires_at)*1000)::bigint);
END $$;

-- Acknowledgement alone is delivery bookkeeping, not verified-user authorization.
CREATE FUNCTION jls_auth.delivery_ack(p_session_secret_hash text,p_browser_secret_hash text,p_expected_token_version bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE b jls_auth.browser_bindings; s jls_auth.app_sessions; o jls_auth.owner_control;
  c jls_auth.session_credentials; v_now timestamptz;
BEGIN
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE secret_hash=p_browser_secret_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE secret_hash=p_session_secret_hash AND browser_id=b.browser_id;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO o FROM jls_auth.owner_control WHERE owner_id=s.owner_id FOR UPDATE;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=s.session_id FOR UPDATE;
  SELECT * INTO c FROM jls_auth.session_credentials WHERE session_id=s.session_id FOR UPDATE;
  v_now:=clock_timestamp();
  IF o.active IS DISTINCT FROM true OR o.auth_subject<>s.auth_subject OR o.current_dataset_epoch IS NULL
    OR b.current_session_id IS DISTINCT FROM s.session_id OR b.generation<>s.browser_generation OR b.expires_at<=v_now
    OR s.revoked_at IS NOT NULL OR s.created_at>v_now OR s.last_activity_at>v_now
    OR s.created_at<=v_now-interval '7 days' OR s.last_activity_at<=v_now-interval '24 hours'
    OR c.session_id IS NULL OR c.state<>'usable' OR c.access_expires_at<=v_now OR c.token_version IS DISTINCT FROM p_expected_token_version
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  UPDATE jls_auth.app_sessions SET delivery_state='acknowledged',delivery_acknowledged_at=coalesce(delivery_acknowledged_at,v_now)
    WHERE session_id=s.session_id;
  RETURN '{"kind":"acknowledged"}'::jsonb;
END $$;

-- Post-network fence: the caller supplies independently verified upstream identity,
-- plus the exact pre-network CAS snapshot. Never return the credential capability.
CREATE FUNCTION jls_auth.confirm_session(p_session_secret_hash text,p_browser_secret_hash text,
  p_expected_token_version bigint,p_expected_control_version bigint,p_expected_dataset_epoch uuid,
  p_verified_subject uuid,p_verified_upstream_session_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE v jsonb;
BEGIN
  v:=jls_auth.current_credentials(p_session_secret_hash,p_browser_secret_hash,p_expected_token_version,
    p_expected_control_version,p_expected_dataset_epoch);
  IF v->>'kind'<>'credentials' OR (v->>'authSubject')::uuid IS DISTINCT FROM p_verified_subject
    OR (v->>'upstreamSessionId')::uuid IS DISTINCT FROM p_verified_upstream_session_id
    THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  UPDATE jls_auth.app_sessions SET delivery_state='acknowledged',delivery_acknowledged_at=coalesce(delivery_acknowledged_at,clock_timestamp())
    WHERE session_id=(v->>'sessionId')::uuid;
  RETURN jsonb_build_object('kind','confirmed','context',jsonb_build_object('ownerId',v->'ownerId','authSubject',v->'authSubject',
    'sessionId',v->'sessionId','datasetEpoch',v->'datasetEpoch'),'tokenVersion',v->'tokenVersion',
    'controlVersion',v->'controlVersion','browserGeneration',v->'browserGeneration');
END $$;

CREATE FUNCTION jls_auth.delivery_retire(p_browser_secret_hash text,p_attempt_id uuid,p_session_id uuid,p_generation bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' SET lock_timeout='250ms' AS $$
DECLARE b jls_auth.browser_bindings; s jls_auth.app_sessions; a jls_auth.oauth_attempts; v_now timestamptz;
BEGIN
  SELECT * INTO b FROM jls_auth.browser_bindings WHERE secret_hash=p_browser_secret_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=p_session_id AND browser_id=b.browser_id;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  PERFORM owner_id FROM jls_auth.owner_control WHERE owner_id=s.owner_id FOR UPDATE;
  SELECT * INTO s FROM jls_auth.app_sessions WHERE session_id=p_session_id FOR UPDATE;
  SELECT * INTO a FROM jls_auth.oauth_attempts WHERE attempt_id=p_attempt_id FOR UPDATE;
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
  UPDATE jls_auth.app_sessions SET revoked_at=v_now WHERE session_id=s.session_id;
  INSERT INTO jls_auth.cleanup_work(session_id,token_envelope)
    VALUES (s.session_id,(SELECT c.token_envelope FROM jls_auth.session_credentials c WHERE c.session_id=s.session_id))
    ON CONFLICT (session_id) DO NOTHING;
  UPDATE jls_auth.session_credentials SET state='revoked',token_version=token_version+1,
    refresh_attempt_id=NULL,refresh_lease_expires_at=NULL,refresh_transmission_intent_at=NULL WHERE session_id=s.session_id;
  UPDATE jls_auth.browser_bindings SET generation=generation+1,current_session_id=NULL WHERE browser_id=b.browser_id;
  UPDATE jls_auth.oauth_attempts SET state='retired' WHERE attempt_id=a.attempt_id;
  RETURN '{"kind":"retired"}'::jsonb;
END $$;

CREATE FUNCTION jls_auth.logout(p_browser_secret_hash text,p_proof_hash text,p_operation_id uuid,p_cookie_fingerprint text) RETURNS jsonb
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
  END IF;
  SELECT * INTO p FROM jls_auth.csrf_proofs WHERE secret_hash=p_proof_hash AND operation_id=p_operation_id
    AND browser_id=b.browser_id AND purpose='logout' FOR UPDATE;
  IF NOT FOUND THEN RETURN '{"kind":"denied"}'::jsonb; END IF;
  PERFORM attempt_id FROM jls_auth.oauth_attempts WHERE browser_id=b.browser_id AND generation_before=p.generation
    ORDER BY attempt_id FOR UPDATE;
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
    UPDATE jls_auth.app_sessions SET revoked_at=coalesce(revoked_at,v_now) WHERE session_id=s.session_id;
    INSERT INTO jls_auth.cleanup_work(session_id,token_envelope)
      VALUES (s.session_id,(SELECT c.token_envelope FROM jls_auth.session_credentials c WHERE c.session_id=s.session_id))
      ON CONFLICT (session_id) DO NOTHING;
    UPDATE jls_auth.session_credentials SET state='revoked',token_version=token_version+1,
      refresh_attempt_id=NULL,refresh_lease_expires_at=NULL,refresh_transmission_intent_at=NULL WHERE session_id=s.session_id;
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

CREATE FUNCTION public.jls_auth_session_lookup_v1(p_session_secret_hash text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.session_lookup(p_session_secret_hash) $$;
CREATE FUNCTION public.jls_auth_session_snapshot_v1(p_session_secret_hash text,p_browser_secret_hash text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.session_snapshot(p_session_secret_hash,p_browser_secret_hash) $$;
CREATE FUNCTION public.jls_auth_current_credentials_v1(p_session_secret_hash text,p_browser_secret_hash text,
  p_expected_token_version bigint,p_expected_control_version bigint,p_expected_dataset_epoch uuid) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$
  SELECT jls_auth.current_credentials(p_session_secret_hash,p_browser_secret_hash,p_expected_token_version,p_expected_control_version,p_expected_dataset_epoch) $$;
CREATE FUNCTION public.jls_auth_confirm_session_v1(p_session_secret_hash text,p_browser_secret_hash text,
  p_expected_token_version bigint,p_expected_control_version bigint,p_expected_dataset_epoch uuid,
  p_verified_subject uuid,p_verified_upstream_session_id uuid) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.confirm_session(p_session_secret_hash,p_browser_secret_hash,
  p_expected_token_version,p_expected_control_version,p_expected_dataset_epoch,p_verified_subject,p_verified_upstream_session_id) $$;
CREATE FUNCTION public.jls_auth_delivery_ack_v1(p_session_secret_hash text,p_browser_secret_hash text,p_expected_token_version bigint) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.delivery_ack(p_session_secret_hash,p_browser_secret_hash,p_expected_token_version) $$;
CREATE FUNCTION public.jls_auth_delivery_retire_v1(p_browser_secret_hash text,p_attempt_id uuid,p_session_id uuid,p_generation bigint) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.delivery_retire(p_browser_secret_hash,p_attempt_id,p_session_id,p_generation) $$;
CREATE FUNCTION public.jls_auth_logout_v1(p_browser_secret_hash text,p_proof_hash text,p_operation_id uuid,p_cookie_fingerprint text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER SET search_path='' AS $$ SELECT jls_auth.logout(p_browser_secret_hash,p_proof_hash,p_operation_id,p_cookie_fingerprint) $$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA jls_auth FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION jls_auth.session_lookup(text),jls_auth.session_snapshot(text,text),jls_auth.current_credentials(text,text,bigint,bigint,uuid),
  jls_auth.confirm_session(text,text,bigint,bigint,uuid,uuid,uuid),
  jls_auth.delivery_ack(text,text,bigint),jls_auth.delivery_retire(text,uuid,uuid,bigint),jls_auth.logout(text,text,uuid,text) TO service_role;
REVOKE ALL ON FUNCTION public.jls_auth_session_lookup_v1(text),public.jls_auth_session_snapshot_v1(text,text),public.jls_auth_current_credentials_v1(text,text,bigint,bigint,uuid),
  public.jls_auth_confirm_session_v1(text,text,bigint,bigint,uuid,uuid,uuid),
  public.jls_auth_delivery_ack_v1(text,text,bigint),public.jls_auth_delivery_retire_v1(text,uuid,uuid,bigint),
  public.jls_auth_logout_v1(text,text,uuid,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.jls_auth_session_lookup_v1(text),public.jls_auth_session_snapshot_v1(text,text),public.jls_auth_current_credentials_v1(text,text,bigint,bigint,uuid),
  public.jls_auth_confirm_session_v1(text,text,bigint,bigint,uuid,uuid,uuid),
  public.jls_auth_delivery_ack_v1(text,text,bigint),public.jls_auth_delivery_retire_v1(text,uuid,uuid,bigint),
  public.jls_auth_logout_v1(text,text,uuid,text) TO service_role;
COMMIT;
