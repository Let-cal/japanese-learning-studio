import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSessionRuntimeRepository } from '../../src/infrastructure/auth/sessionRuntimeRepository';
import { hashSessionSecret } from '../../src/infrastructure/auth/sessionSecrets';
import { hashAuthActionSecret } from '../../src/infrastructure/auth/authActionSecrets';

const config = { supabaseOrigin: 'https://abcdefghijklmnopqrst.supabase.co', secretKey: 'sb_secret_fixture_only_1234567890123456' };
const secret = 'A'.repeat(43); const browser = `jls-browser-v1.${secret}`;
const ownerId = '11111111-1111-4111-8111-111111111111';
const authSubject = '22222222-2222-4222-8222-222222222222';
const sessionId = '33333333-3333-4333-8333-333333333333';
const upstreamSessionId = '44444444-4444-4444-8444-444444444444';
const epoch = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const browserId = '55555555-5555-4555-8555-555555555555';
const now = 1_800_000_000_000;
const snapshot = () => ({ kind: 'snapshot', now,
  session: { sessionId, ownerId, authSubject, upstreamSessionId, createdAt: now-1000, lastActivityAt: now-500,
    reauthenticatedAt: null, revokedAt: null, deliveryState: 'unacknowledged', deliveryAcknowledgedAt: null },
  owner: { ownerId, authSubject, active: true, controlVersion: 9, datasetEpoch: epoch },
  browser: { browserId, generation: 4, sessionGeneration: 4, currentSessionId: sessionId, expiresAt: now+10000 },
  credential: { tokenVersion: 7, state: 'usable', accessExpiresAt: now+10000,
    refreshAttemptId: null, refreshLeaseExpiresAt: null, refreshTransmissionIntentAt: null },
});
const facts = () => ({ sessionSecret: secret, browserSecret: browser, tokenVersion: 7, controlVersion: 9, datasetEpoch: epoch,
  sessionId, ownerId, authSubject, upstreamSessionId, browserGeneration: 4 });
const credential = () => ({ kind: 'credentials', now, sessionId, ownerId, authSubject, upstreamSessionId,
  datasetEpoch: epoch, controlVersion: 9, browserGeneration: 4, tokenVersion: 7,
  tokenEnvelope: `v1.fixture.${'A'.repeat(16)}.${'A'.repeat(64)}.${'A'.repeat(22)}`, accessExpiresAt: now+10000 });
const confirmed = () => ({ kind: 'confirmed', context: { sessionId, ownerId, authSubject, datasetEpoch: epoch },
  tokenVersion: 7, controlVersion: 9, browserGeneration: 4 });
const json = (data: unknown) => new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
afterEach(() => vi.useRealTimers());

describe('fixed runtime control RPCs and closed responses', () => {
  it('hashes both cookie secrets and sends only fixed snapshot arguments with the server key', async () => {
    let url = ''; let init: RequestInit | undefined;
    const repository = createSessionRuntimeRepository(config, (async (destination, options) => { url = String(destination); init = options; return json(snapshot()); }) as typeof fetch);
    const result = await repository.snapshot({ sessionSecret: secret, browserSecret: browser });
    expect(result.kind).toBe('snapshot');
    expect(url).toBe(`${config.supabaseOrigin}/rest/v1/rpc/jls_auth_session_snapshot_v1`);
    expect(JSON.parse(String(init?.body))).toEqual({ p_session_secret_hash: hashSessionSecret(secret), p_browser_secret_hash: hashAuthActionSecret('browser', browser) });
    expect(String(init?.body)).not.toContain(browser);
    expect(new Headers(init?.headers).get('apikey')).toBe(config.secretKey);
    expect(new Headers(init?.headers).has('Authorization')).toBe(false);
    expect(init).toMatchObject({ method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store' });
    if (result.kind === 'snapshot') { expect(Object.isFrozen(result)).toBe(true); expect(Object.isFrozen(result.credential)).toBe(true); }
  });
  it('keeps confirmed absence distinct from an upstream failure', async () => {
    const absent = createSessionRuntimeRepository(config, (async () => json({ kind: 'absent', now })) as typeof fetch);
    expect(await absent.snapshot({ sessionSecret: secret, browserSecret: browser })).toEqual({ kind: 'absent', now });
    const failed = createSessionRuntimeRepository(config, (async () => new Response('private error', { status: 503 })) as typeof fetch);
    expect(await failed.snapshot({ sessionSecret: secret, browserSecret: browser })).toEqual({ kind: 'unavailable', reason: 'upstream_rejected' });
  });
  it('sends actual credential CAS inputs and returns only the closed envelope response', async () => {
    let sent: Record<string, unknown> | undefined;
    const repository = createSessionRuntimeRepository(config, (async (_url, init) => { sent = JSON.parse(String(init?.body)); return json(credential()); }) as typeof fetch);
    expect(await repository.credentials(facts())).toEqual(credential());
    expect(sent).toEqual({ p_session_secret_hash: hashSessionSecret(secret), p_browser_secret_hash: hashAuthActionSecret('browser', browser),
      p_expected_token_version: 7, p_expected_control_version: 9, p_expected_dataset_epoch: epoch });
  });
  it('confirms independently verified identity against fixed CAS arguments without returning a token envelope', async () => {
    let destination = ''; let sent: Record<string, unknown> | undefined;
    const repository = createSessionRuntimeRepository(config, (async (url, init) => { destination = String(url); sent = JSON.parse(String(init?.body)); return json(confirmed()); }) as typeof fetch);
    const result = await repository.confirm({ ...facts(), verifiedAuthSubject: authSubject, verifiedUpstreamSessionId: upstreamSessionId });
    expect(result).toEqual(confirmed());
    expect(destination).toBe(`${config.supabaseOrigin}/rest/v1/rpc/jls_auth_confirm_session_v1`);
    expect(sent).toMatchObject({ p_verified_subject: authSubject, p_verified_upstream_session_id: upstreamSessionId, p_expected_control_version: 9 });
    expect(JSON.stringify(result)).not.toContain('tokenEnvelope');
  });
  it('never defaults missing CAS versions or accepts extra caller-selected functions', async () => {
    let calls = 0;
    const repository = createSessionRuntimeRepository(config, (async () => { calls++; return json(credential()); }) as typeof fetch);
    expect(await repository.credentials({ ...facts(), tokenVersion: undefined })).toEqual({ kind: 'invalid_input' });
    expect(await repository.credentials({ ...facts(), function: 'other' })).toEqual({ kind: 'invalid_input' });
    expect(await repository.confirm({ ...facts(), verifiedAuthSubject: authSubject })).toEqual({ kind: 'invalid_input' });
    expect(calls).toBe(0);
  });
  it.each([
    { ...config, supabaseOrigin: 'https://attacker.example' },
    { ...config, secretKey: 'sb_publishable_wrong_boundary' },
  ])('rejects invalid fixed configuration without network', async supplied => {
    let calls = 0;
    const repository = createSessionRuntimeRepository(supplied, (async () => { calls++; return json(snapshot()); }) as typeof fetch);
    expect(await repository.snapshot({ sessionSecret: secret, browserSecret: browser })).toEqual({ kind: 'unavailable', reason: 'configuration' });
    expect(calls).toBe(0);
  });
  it.each([
    () => ({ ...snapshot(), tokenEnvelope: 'must never be here' }),
    () => ({ ...snapshot(), now: -1 }),
    () => ({ ...snapshot(), credential: { ...snapshot().credential, tokenVersion: 0.5 } }),
    () => ({ ...snapshot(), session: { ...snapshot().session, createdAt: now+1 } }),
    () => ({ ...snapshot(), session: { ...snapshot().session, deliveryState: 'acknowledged' } }),
  ])('rejects expanded or impossible metadata without exposing raw data', async invalid => {
    expect(await createSessionRuntimeRepository(config, (async () => json(invalid())) as typeof fetch)
      .snapshot({ sessionSecret: secret, browserSecret: browser })).toEqual({ kind: 'unavailable', reason: 'invalid_response' });
  });
  it('rejects credential and confirmation responses with mismatched CAS facts', async () => {
    const repository = createSessionRuntimeRepository(config, (async url => json(String(url).includes('confirm')
      ? { ...confirmed(), controlVersion: 10 } : { ...credential(), tokenVersion: 8 })) as typeof fetch);
    expect(await repository.credentials(facts())).toEqual({ kind: 'unavailable', reason: 'invalid_response' });
    expect(await repository.confirm({ ...facts(), verifiedAuthSubject: authSubject, verifiedUpstreamSessionId: upstreamSessionId }))
      .toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
  });
  it('retains denial but treats uncertain confirmation transport as possibly committed', async () => {
    const denied = createSessionRuntimeRepository(config, (async () => json({ kind: 'denied' })) as typeof fetch);
    expect(await denied.confirm({ ...facts(), verifiedAuthSubject: authSubject, verifiedUpstreamSessionId: upstreamSessionId })).toEqual({ kind: 'denied' });
    const failed = createSessionRuntimeRepository(config, (async () => { throw new Error('private diagnostic'); }) as typeof fetch);
    expect(await failed.confirm({ ...facts(), verifiedAuthSubject: authSubject, verifiedUpstreamSessionId: upstreamSessionId })).toEqual({ kind: 'outcome_unknown', reason: 'transport' });
  });
  it('bounds slow body reads and rejects late headers even before its timer fires', async () => {
    vi.useFakeTimers(); let calls = 0;
    const slow = createSessionRuntimeRepository(config, (async () => { calls++; return new Response(new ReadableStream({ start() {} }), { headers: { 'Content-Type': 'application/json' } }); }) as typeof fetch);
    const pending = slow.snapshot({ sessionSecret: secret, browserSecret: browser });
    await vi.advanceTimersByTimeAsync(2000);
    expect(await pending).toEqual({ kind: 'unavailable', reason: 'timeout' }); expect(calls).toBe(1);
    let elapsed = 0;
    const late = createSessionRuntimeRepository(config, (async () => { elapsed = 2001; return json(snapshot()); }) as typeof fetch, () => elapsed);
    expect(await late.snapshot({ sessionSecret: secret, browserSecret: browser })).toEqual({ kind: 'unavailable', reason: 'timeout' });
  });
  it('respects parent cancellation and never sends an already-cancelled confirmation', async () => {
    let calls = 0; const controller = new AbortController(); controller.abort();
    const repository = createSessionRuntimeRepository(config, (async () => { calls++; return json(confirmed()); }) as typeof fetch);
    expect(await repository.confirm({ ...facts(), verifiedAuthSubject: authSubject, verifiedUpstreamSessionId: upstreamSessionId }, controller.signal))
      .toEqual({ kind: 'unavailable', reason: 'cancelled' });
    expect(calls).toBe(0);
  });
});
