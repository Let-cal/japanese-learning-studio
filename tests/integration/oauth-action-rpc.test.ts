import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOAuthActionRepository, type OAuthActionRepository } from '../../src/infrastructure/auth/oauthActionRepository';

const config = { supabaseOrigin: 'https://abcdefghijklmnopqrst.supabase.co', secretKey: 'sb_secret_oauth_fixture_1234567890' };
const uuid = (hex: string) => `${hex.repeat(8)}-${hex.repeat(4)}-${hex.repeat(4)}-${hex.repeat(4)}-${hex.repeat(12)}`;
const pkceEnvelope = `pkce-v1.fixture.${'A'.repeat(16)}.${'A'.repeat(58)}.${'A'.repeat(22)}`;
const tokenEnvelope = `v1.fixture.${'A'.repeat(16)}.ciphertext.${'A'.repeat(22)}`;
const orphanEnvelope = `orphan-${tokenEnvelope}`;
const requestFingerprint = 'a'.repeat(64);
const proofHash = 'b'.repeat(64);
const operationId = uuid('a');
const browserId = uuid('b');
const browserHash = 'c'.repeat(64);
const base = { browserHash, flowHash: 'd'.repeat(64), attemptId: uuid('c'), claimId: uuid('d') };
const begin = { browserHash, proofHash, operationId, cookieFingerprint: 'absent',
  attemptId: base.attemptId, flowHash: base.flowHash, pkceEnvelope, requestFingerprint };
const issue = { issuanceId: uuid('1'), requestFingerprint, browserId, browserHash, proofId: uuid('e'), proofHash,
  purpose: 'login' as const, cookieFingerprint: 'absent', presentedSessionHash: null, operationId,
  expectedTokenVersion: null, expectedControlVersion: null, expectedDatasetEpoch: null };
const claim = { ...base, browserId };
const resolve = { ...base, commitOperationId: uuid('2'), requestFingerprint, newSessionId: uuid('3'), generation: 7 };
const commit = { ...resolve, candidateId: uuid('4'), verifiedSubject: uuid('5'), verifiedUpstreamSessionId: uuid('6'),
  newSessionHash: 'e'.repeat(64), tokenEnvelope, accessExpiresAt: 1_800_000_010_000 };
const close = { ...base, closeOperationId: uuid('7'), requestFingerprint, candidateId: null, verifiedSubject: null,
  verifiedUpstreamSessionId: null, tokenEnvelope: null, cleanupEnvironment: null };
const closeWithCandidate = { ...close, candidateId: commit.candidateId, verifiedSubject: commit.verifiedSubject,
  verifiedUpstreamSessionId: commit.verifiedUpstreamSessionId, tokenEnvelope: orphanEnvelope, cleanupEnvironment: 'local' };
const claimed = { kind: 'claimed', now: 1_800_000_000_000, attemptId: base.attemptId, claimId: base.claimId,
  browserId, pkceEnvelope, ownerId: uuid('8'), authSubject: commit.verifiedSubject, controlVersion: 3, datasetEpoch: uuid('9'), generation: 7 };
const committed = { kind: 'committed', attemptId: base.attemptId, sessionId: commit.newSessionId, generation: 8 };
const issued = { kind: 'issued', proofId: issue.proofId, browserId, generation: 7, expiresAt: 1_800_000_900_000 };
const begun = { kind: 'begun', attemptId: base.attemptId, generation: 7, expiresAt: 1_800_000_600_000 };
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const callbackArgs = { p_browser_hash: browserHash, p_flow_hash: base.flowHash, p_attempt_id: base.attemptId, p_claim_id: base.claimId };
const commitArgs = { ...callbackArgs, p_commit_operation_id: resolve.commitOperationId, p_request_fingerprint: requestFingerprint };

type Action = keyof OAuthActionRepository;
type ValidCase = { [Method in Action]: readonly [
  Method, string, Parameters<OAuthActionRepository[Method]>[0], object, unknown,
] }[Action];

function invoke(repository: OAuthActionRepository, method: Action, input: unknown): Promise<unknown> {
  return Reflect.apply(repository[method], repository, [input]);
}

afterEach(() => vi.useRealTimers());

describe('fixed OAuth action RPCs', () => {
  const cases = [
    ['issueProof', 'issue_proof', issue, {
      p_issuance_id: issue.issuanceId, p_request_fingerprint: requestFingerprint, p_browser_id: browserId,
      p_browser_hash: browserHash, p_proof_id: issue.proofId, p_proof_hash: proofHash, p_purpose: 'login',
      p_cookie_fingerprint: 'absent', p_presented_session_hash: null, p_operation_id: operationId,
      p_expected_token_version: null, p_expected_control_version: null, p_expected_dataset_epoch: null,
    }, issued],
    ['beginLogin', 'begin_login', begin, {
      p_browser_hash: browserHash, p_proof_hash: proofHash, p_operation_id: operationId, p_cookie_fingerprint: 'absent',
      p_attempt_id: base.attemptId, p_flow_hash: base.flowHash, p_pkce_envelope: pkceEnvelope, p_request_fingerprint: requestFingerprint,
    }, begun],
    ['callbackClaim', 'callback_claim', claim, callbackArgs, claimed],
    ['callbackMarkSent', 'callback_mark_sent', base, callbackArgs, { kind: 'send_intent' }],
    ['callbackCommit', 'callback_commit', commit, {
      ...commitArgs, p_candidate_id: commit.candidateId, p_verified_subject: commit.verifiedSubject,
      p_verified_upstream_session_id: commit.verifiedUpstreamSessionId, p_new_session_id: commit.newSessionId,
      p_new_session_hash: commit.newSessionHash, p_token_envelope: tokenEnvelope, p_access_expires_at: '2027-01-15T08:00:10.000Z',
    }, committed],
    ['callbackResolve', 'callback_resolve', resolve, commitArgs, committed],
    ['callbackClose', 'callback_close', { ...close, claimId: null }, {
      ...callbackArgs, p_claim_id: null, p_close_operation_id: close.closeOperationId, p_request_fingerprint: requestFingerprint,
      p_candidate_id: null, p_verified_subject: null, p_verified_upstream_session_id: null, p_token_envelope: null, p_cleanup_environment: null,
    }, { kind: 'closed' }],
    ['callbackClose', 'callback_close', closeWithCandidate, {
      ...callbackArgs, p_close_operation_id: close.closeOperationId, p_request_fingerprint: requestFingerprint,
      p_candidate_id: commit.candidateId, p_verified_subject: commit.verifiedSubject,
      p_verified_upstream_session_id: commit.verifiedUpstreamSessionId, p_token_envelope: orphanEnvelope, p_cleanup_environment: 'local',
    }, { kind: 'closed' }],
    ['deliveryAck', 'delivery_ack', { browserHash, sessionHash: commit.newSessionHash, tokenVersion: 0 },
      { p_browser_secret_hash: browserHash, p_session_secret_hash: commit.newSessionHash, p_expected_token_version: 0 },
      { kind: 'acknowledged' }],
    ['deliveryRetire', 'delivery_retire', { browserHash, attemptId: base.attemptId, sessionId: commit.newSessionId, generation: 8 },
      { p_browser_secret_hash: browserHash, p_attempt_id: base.attemptId, p_session_id: commit.newSessionId, p_generation: 8 },
      { kind: 'already_retired' }],
    ['logout', 'logout', { browserHash, proofHash, operationId, cookieFingerprint: 'absent' },
      { p_browser_secret_hash: browserHash, p_proof_hash: proofHash, p_operation_id: operationId, p_cookie_fingerprint: 'absent' },
      { kind: 'logged_out', outcome: 'revoked', clearCookie: true }],
  ] as const satisfies readonly ValidCase[];

  it.each(cases)('%s posts only the versioned SQL signature and returns its validated result', async (method, rpc, input, args, result) => {
    const fetcher = vi.fn<typeof fetch>(async () => json(result));
    const repository = createOAuthActionRepository({ ...config }, fetcher);

    const actual = await invoke(repository, method, input);
    expect(actual).toEqual(result);
    expect(Object.isFrozen(actual)).toBe(true);
    expect(fetcher).toHaveBeenCalledOnce();
    const [url, options] = fetcher.mock.calls[0];
    expect(url).toBe(`${config.supabaseOrigin}/rest/v1/rpc/jls_auth_${rpc}_v1`);
    expect(options).toMatchObject({ method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store' });
    expect(Object.fromEntries(new Headers(options?.headers))).toEqual({
      accept: 'application/json', apikey: config.secretKey, 'content-type': 'application/json',
    });
    expect(JSON.parse(String(options?.body))).toEqual(args);
  });

  it.each([
    ['issueProof', { ...issue, operationId: null }],
    ['issueProof', { ...issue, presentedSessionHash: proofHash }],
    ['issueProof', { ...issue, purpose: 'mutation', operationId: null, cookieFingerprint: `present:${proofHash}` }],
    ['beginLogin', { ...begin, pkceEnvelope: tokenEnvelope }],
    ['callbackClaim', { ...claim, browserId: uuid('b').toUpperCase() }],
    ['callbackMarkSent', { ...base, rpc: 'any_endpoint' }],
    ['callbackCommit', { ...commit, accessExpiresAt: Number.MAX_SAFE_INTEGER }],
    ['callbackResolve', { ...resolve, generation: Number.MAX_SAFE_INTEGER }],
    ['callbackClose', { ...close, candidateId: commit.candidateId }],
    ['callbackClose', { ...closeWithCandidate, tokenEnvelope }],
    ['deliveryAck', { browserHash, sessionHash: commit.newSessionHash, tokenVersion: -1 }],
    ['deliveryRetire', { browserHash, attemptId: base.attemptId, sessionId: commit.newSessionId, generation: 0 }],
    ['logout', { browserHash, proofHash, operationId, cookieFingerprint: '' }],
  ] as const)('%s rejects malformed bindings before sending %#', async (method, input) => {
    const fetcher = vi.fn<typeof fetch>(async () => json({ kind: 'denied' }));
    expect(await invoke(createOAuthActionRepository(config, fetcher), method, input)).toEqual({ kind: 'invalid_input' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    ['issueProof', issue, { ...issued, proofId: uuid('f') }],
    ['issueProof', issue, { ...issued, browserId: uuid('f') }],
    ['beginLogin', begin, { ...begun, attemptId: uuid('f') }],
    ['callbackClaim', claim, { ...claimed, attemptId: uuid('f') }],
    ['callbackClaim', claim, { ...claimed, claimId: uuid('f') }],
    ['callbackClaim', claim, { ...claimed, browserId: uuid('f') }],
    ['callbackClaim', claim, { ...claimed, pkceEnvelope: tokenEnvelope }],
    ['callbackMarkSent', base, { kind: 'transmit' }],
    ['callbackMarkSent', base, { kind: 'send_intent', pkceEnvelope }],
    ['callbackCommit', commit, { ...committed, sessionId: uuid('f') }],
    ['callbackCommit', commit, { ...committed, generation: 7 }],
    ['logout', { browserHash, proofHash, operationId, cookieFingerprint: 'absent' },
      { kind: 'logged_out', outcome: 'absent', clearCookie: false }],
  ] as const)('%s rejects unexpected fields or misbound SQL results %#', async (method, input, result) => {
    expect(await invoke(createOAuthActionRepository(config, async () => json(result)), method, input))
      .toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
  });

  it('never interprets a misbound historical receipt as the selected session', async () => {
    const repository = createOAuthActionRepository(config, async () => json({ ...committed, sessionId: uuid('f') }));
    expect(await repository.callbackResolve(resolve)).toEqual({ kind: 'unavailable', reason: 'invalid_response' });
  });

  it('keeps SQL send fences, replay denials, and unresolved receipts distinct', async () => {
    const fetcher = vi.fn<typeof fetch>()
      .mockImplementationOnce(async () => json({ kind: 'restart_required' }))
      .mockImplementationOnce(async () => json({ kind: 'denied' }))
      .mockImplementationOnce(async () => json({ kind: 'unresolved' }));
    const repository = createOAuthActionRepository(config, fetcher);
    expect(await repository.callbackMarkSent(base)).toEqual({ kind: 'restart_required' });
    expect(await repository.callbackCommit(commit)).toEqual({ kind: 'denied' });
    expect(await repository.callbackResolve(resolve)).toEqual({ kind: 'unresolved' });
  });

  it('closes the capability on invalid configuration and never evaluates accessor inputs', async () => {
    const fetcher = vi.fn<typeof fetch>();
    const getHash = vi.fn(() => browserHash);
    const bad = { ...base, get browserHash() { return getHash(); } };
    expect(await createOAuthActionRepository(config, fetcher).callbackMarkSent(bad)).toEqual({ kind: 'invalid_input' });
    expect(await createOAuthActionRepository({ ...config, supabaseOrigin: config.supabaseOrigin + '/extra' }, fetcher).callbackMarkSent(base))
      .toEqual({ kind: 'unavailable', reason: 'configuration' });
    expect(getHash).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('classifies caller cancellation before and after fetch separately without retries', async () => {
    const controller = new AbortController();
    const fetcher = vi.fn<typeof fetch>(async (_url, init) => {
      controller.abort();
      expect(init?.signal?.aborted).toBe(true);
      return json({ kind: 'send_intent' });
    });
    const repository = createOAuthActionRepository(config, fetcher);
    const before = AbortSignal.abort();
    expect(await repository.callbackMarkSent(base, before)).toEqual({ kind: 'unavailable', reason: 'cancelled' });
    expect(fetcher).not.toHaveBeenCalled();
    expect(await repository.callbackMarkSent(base, controller.signal)).toEqual({ kind: 'outcome_unknown', reason: 'cancelled' });
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it('uses one two-second deadline for headers and body and cancels the stuck read', async () => {
    vi.useFakeTimers();
    const cancel = vi.fn();
    let releaseHeaders!: (response: Response) => void;
    const fetcher = vi.fn<typeof fetch>(async () => new Promise(resolveResponse => { releaseHeaders = resolveResponse; }));
    const repository = createOAuthActionRepository(config, fetcher);
    const result = repository.callbackMarkSent(base);

    await vi.advanceTimersByTimeAsync(1500);
    releaseHeaders(new Response(new ReadableStream({ cancel }), { headers: { 'Content-Type': 'application/json' } }));
    await vi.advanceTimersByTimeAsync(500);
    expect(await result).toEqual({ kind: 'outcome_unknown', reason: 'timeout' });
    expect(fetcher.mock.calls[0][1]?.signal?.aborted).toBe(true);
    expect(cancel).toHaveBeenCalledOnce();
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it('does not send a mutation when its monotonic budget is exhausted before fetch', async () => {
    const fetcher = vi.fn<typeof fetch>(async () => json({ kind: 'send_intent' }));
    const clock = vi.fn().mockReturnValue(2000).mockReturnValueOnce(0);
    const repository = createOAuthActionRepository(config, fetcher, clock);
    expect(await repository.callbackMarkSent(base)).toEqual({ kind: 'unavailable', reason: 'timeout' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('stops reading as soon as the response exceeds the byte bound', async () => {
    const cancel = vi.fn();
    const body = new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(8193)); },
      cancel,
    });
    const repository = createOAuthActionRepository(config, async () =>
      new Response(body, { headers: { 'Content-Type': 'application/json' } }));
    expect(await repository.callbackClaim(claim)).toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('rejects unreadable UTF-8 in a success response', async () => {
    const repository = createOAuthActionRepository(config, async () =>
      new Response(new Uint8Array([0xc0, 0x80]), { headers: { 'Content-Type': 'application/json' } }));
    expect(await repository.callbackMarkSent(base)).toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
  });

  it('sanitizes failures and treats a lost write response as uncertain', async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValueOnce(new Error(config.secretKey))
      .mockImplementationOnce(async () => new Response(config.secretKey, { status: 503 }));
    const repository = createOAuthActionRepository(config, fetcher);
    expect(await repository.callbackCommit(commit)).toEqual({ kind: 'outcome_unknown', reason: 'transport' });
    expect(await repository.callbackResolve(resolve)).toEqual({ kind: 'unavailable', reason: 'upstream_rejected' });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});


describe('fixed OAuth lookup RPCs', () => {
  it('resolves a browser without sending the raw secret', async () => {
    const reply = { kind: 'active', browserId, generation: 7 };
    const fetcher = vi.fn<typeof fetch>(async () => json(reply));
    const repository = createOAuthActionRepository(config, fetcher);

    expect(await repository.resolveBrowser({ browserHash })).toEqual(reply);
    expect(fetcher.mock.calls[0][0]).toBe(config.supabaseOrigin + '/rest/v1/rpc/jls_auth_browser_resolve_v1');
    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toEqual({ p_browser_hash: browserHash });
  });

  it('resolves an action with the exact purpose and cookie presentation', async () => {
    const reply = { kind: 'resolved', browserId, operationId, generation: 7 };
    const fetcher = vi.fn<typeof fetch>(async () => json(reply));
    const repository = createOAuthActionRepository(config, fetcher);

    expect(await repository.resolveAction({ browserHash, proofHash, purpose: 'login', cookieFingerprint: 'absent' })).toEqual(reply);
    expect(fetcher.mock.calls[0][0]).toBe(config.supabaseOrigin + '/rest/v1/rpc/jls_auth_action_resolve_v1');
    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toEqual({
      p_browser_hash: browserHash, p_proof_hash: proofHash, p_purpose: 'login', p_cookie_fingerprint: 'absent',
    });
  });

  it('distinguishes explicit absence from malformed and unspecified presentation', async () => {
    const reply = { kind: 'pending', attemptId: base.attemptId, browserId };
    const fetcher = vi.fn<typeof fetch>(async () => json(reply));
    const repository = createOAuthActionRepository(config, fetcher);
    const input = { browserHash, flowHash: base.flowHash };

    expect(await invoke(repository, 'inspectCallback', input)).toEqual({ kind: 'invalid_input' });
    expect(await repository.inspectCallback({ ...input, presentedSessionHash: 'invalid' })).toEqual({ kind: 'invalid_input' });
    expect(await repository.inspectCallback({ ...input, presentedSessionHash: null })).toEqual(reply);
    expect(fetcher).toHaveBeenCalledOnce();
    expect(fetcher.mock.calls[0][0]).toBe(config.supabaseOrigin + '/rest/v1/rpc/jls_auth_callback_inspect_v1');
    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toEqual({
      p_browser_hash: browserHash, p_flow_hash: base.flowHash, p_presented_session_hash: null,
    });
  });

  it('never accepts a completed match without a presented bearer', async () => {
    const completed = { kind: 'completed_with_cookie', attemptId: base.attemptId, sessionId: commit.newSessionId, generation: 8 };
    const repository = createOAuthActionRepository(config, async () => json(completed));
    const input = { browserHash, flowHash: base.flowHash };

    expect(await repository.inspectCallback({ ...input, presentedSessionHash: null }))
      .toEqual({ kind: 'unavailable', reason: 'invalid_response' });
    expect(await repository.inspectCallback({ ...input, presentedSessionHash: commit.newSessionHash })).toEqual(completed);
  });

  it('rejects extra response fields and reports lookup transport failure as unavailable', async () => {
    const invalid = createOAuthActionRepository(config, async () => json({
      kind: 'pending', attemptId: base.attemptId, browserId, pkceEnvelope,
    }));
    expect(await invalid.inspectCallback({ browserHash, flowHash: base.flowHash, presentedSessionHash: null }))
      .toEqual({ kind: 'unavailable', reason: 'invalid_response' });

    const offline = createOAuthActionRepository(config, async () => { throw Error('private error'); });
    expect(await offline.resolveBrowser({ browserHash })).toEqual({ kind: 'unavailable', reason: 'transport' });
  });
});
