import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSessionControlRepository } from '../../src/infrastructure/auth/sessionControlRepository';

const secret = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const configuration = {
  supabaseOrigin: 'https://abcdefghijklmnopqrst.supabase.co',
  secretKey: 'sb_secret_TestOnlyCredential0123456789',
};
const id = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE';
const canonicalId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const found = () => ({
  kind: 'found', now: 1000,
  session: { sessionId: id, ownerId: id, authSubject: id, upstreamSessionId: id,
    createdAt: 100, lastActivityAt: 900, reauthenticatedAt: null as number | null, revokedAt: null as number | null },
  currentOwner: { ownerId: id, authorizedAuthSubject: id, active: true },
  currentDataset: { ownerId: id, activeDatasetEpoch: id },
  credential: { state: 'usable', accessExpiresAt: 1001 as number | null },
});
const json = (value: unknown) => new Response(JSON.stringify(value), {
  status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8' },
});
const unavailable = (reason: string) => ({ kind: 'unavailable', reason });

afterEach(() => vi.useRealTimers());

describe('fixed server session-control lookup transport (no live requests)', () => {
  it('sends only the purpose-separated digest through the fixed secret-key POST', async () => {
    let request: { url: unknown; init: RequestInit | undefined } | undefined;
    const repository = createSessionControlRepository(configuration, async (url: unknown, init?: RequestInit) => {
      request = { url, init };
      return json({ kind: 'absent', now: 1000 });
    });
    expect(await repository.lookup(secret)).toEqual({ kind: 'absent', now: 1000 });
    expect(request?.url).toBe('https://abcdefghijklmnopqrst.supabase.co/rest/v1/rpc/jls_auth_session_lookup_v1');
    expect(request?.init).toMatchObject({ method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store' });
    expect(request?.init?.headers).toEqual({ apikey: configuration.secretKey,
      'Content-Type': 'application/json', Accept: 'application/json' });
    expect(request?.init?.signal).toBeInstanceOf(AbortSignal);
    expect(request?.init?.body).toBe('{"p_session_secret_hash":"ccdc3b124c1b268674bd7d9cd8d14a8512e99ac85a9a5b7e6482b455cba47cf0"}');
    expect(Object.keys(repository)).toEqual(['lookup']);
  });

  it('distinguishes absent and invalid local inputs without network', async () => {
    const fetcher = vi.fn(() => Promise.reject(new Error('network must not run')));
    const repository = createSessionControlRepository(configuration, fetcher);
    for (const value of [undefined, null]) expect(await repository.lookup(value)).toEqual({ kind: 'input_absent' });
    for (const value of ['', {}, 42, `${secret.slice(0, -1)}B`, '0'.repeat(64), `${secret}=`]) {
      expect(await repository.lookup(value)).toEqual({ kind: 'input_invalid' });
    }
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('copies canonical immutable metadata without treating stored usability as authorization', async () => {
    const repository = createSessionControlRepository(configuration, async () => json(found()));
    const result = await repository.lookup(secret) as ReturnType<typeof found>;
    expect(result.kind).toBe('found');
    expect(result.session).toEqual({ sessionId: canonicalId, ownerId: canonicalId, authSubject: canonicalId,
      upstreamSessionId: canonicalId, createdAt: 100, lastActivityAt: 900, reauthenticatedAt: null, revokedAt: null });
    expect(result.currentDataset.activeDatasetEpoch).toBe(canonicalId);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.session)).toBe(true);
    expect(Object.isFrozen(result.currentOwner)).toBe(true);
    expect(Object.isFrozen(result.currentDataset)).toBe(true);
    expect(Object.isFrozen(result.credential)).toBe(true);
    expect(result).not.toHaveProperty('authorized');
  });

  it('preserves valid denial facts and confirmed missing controls', async () => {
    const value = found();
    value.currentOwner.active = false;
    value.currentOwner.ownerId = '11111111-1111-1111-1111-111111111111';
    value.session.revokedAt = 500;
    value.credential.state = 'reauthenticationRequired';
    value.credential.accessExpiresAt = null;
    const result = await createSessionControlRepository(configuration, async () => json(value)).lookup(secret);
    expect(result).toMatchObject({ kind: 'found', currentOwner: { active: false }, session: { revokedAt: 500 } });
    expect(await createSessionControlRepository(configuration, async () => json({ ...found(), currentOwner: null,
      currentDataset: null })).lookup(secret)).toMatchObject({ kind: 'found', currentOwner: null, currentDataset: null });
  });

  it('fails closed on untrusted configuration without sending any request', async () => {
    const fetcher = vi.fn(() => Promise.resolve(json({ kind: 'absent', now: 0 })));
    const invalid = [
      { ...configuration, supabaseOrigin: 'https://abcdefghijklmnopqrst.supabase.co.evil.test' },
      { ...configuration, supabaseOrigin: 'https://abcdefghijklmnopqrst.supabase.co:443' },
      { ...configuration, supabaseOrigin: 'https://abcdefghijklmnopqrst.supabase.co/' },
      { ...configuration, supabaseOrigin: 'https://user@abcdefghijklmnopqrst.supabase.co' },
      { ...configuration, supabaseOrigin: 'http://abcdefghijklmnopqrst.supabase.co' },
      { ...configuration, supabaseOrigin: 'https://abcdefghijklmnopqrst.supabase.co?x=1' },
      { ...configuration, supabaseOrigin: 'https://abcdefghijklmnopqrst.supabase.co#x' },
      { ...configuration, secretKey: 'eyJlegacy' },
      { ...configuration, secretKey: 'sb_secret_bad\r\nAuthorization: leak' },
      { ...configuration, secretKey: `${configuration.secretKey}\n` },
      { ...configuration, supabaseOrigin: `${configuration.supabaseOrigin}\n` },
    ];
    for (const config of invalid) expect(await createSessionControlRepository(config, fetcher).lookup(secret))
      .toEqual(unavailable('configuration'));
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('rejects malformed contracts, secret-bearing extensions and unsafe time relationships', async () => {
    const malformed = [null, [], [found()], {}, { kind: 'absent' }, { kind: 'absent', now: -1 },
      { kind: 'absent', now: 0, accessToken: 'sensitive' }, { ...found(), session: undefined },
      { ...found(), session: { ...found().session, upstreamSessionId: 'bad' } },
      { ...found(), session: { ...found().session, upstreamSessionId: `${id}\n` } },
      { ...found(), session: { ...found().session, tokenEnvelope: 'sensitive' } },
      { ...found(), session: { ...found().session, createdAt: 901 } },
      { ...found(), session: { ...found().session, lastActivityAt: 1001 } },
      { ...found(), session: { ...found().session, reauthenticatedAt: 99 } },
      { ...found(), session: { ...found().session, revokedAt: 1001 } },
      { ...found(), currentOwner: { ...found().currentOwner, active: 'true' } },
      { ...found(), currentDataset: { ...found().currentDataset, activeDatasetEpoch: 123 } },
      { ...found(), credential: { state: 'usable', accessExpiresAt: null } },
      { ...found(), credential: { state: 'usable', accessExpiresAt: 1000 } },
      { ...found(), credential: { state: 'refreshRequired', accessExpiresAt: Number.MAX_SAFE_INTEGER + 1 } },
      { ...found(), credential: { state: 'refreshRequired', accessExpiresAt: null, refreshToken: 'sensitive' } },
    ];
    for (const value of malformed) expect(await createSessionControlRepository(configuration, async () => json(value))
      .lookup(secret)).toEqual(unavailable('invalid_response'));
  });

  it('rejects non-200 without reading the body and cancels without awaiting a stuck cancel', async () => {
    let cancelled = false;
    const reader = { read: vi.fn(), cancel: () => { cancelled = true; return new Promise<void>(() => {}); } };
    const response = { status: 503, body: { getReader: () => reader } } as unknown as Response;
    expect(await createSessionControlRepository(configuration, async () => response).lookup(secret))
      .toEqual(unavailable('upstream_rejected'));
    expect(reader.read).not.toHaveBeenCalled();
    expect(cancelled).toBe(true);
  });

  it('rejects wrong media types, malformed JSON, invalid UTF-8 and empty successes', async () => {
    const responses = [new Response('{}', { headers: { 'Content-Type': 'text/plain' } }),
      new Response('{', { headers: { 'Content-Type': 'application/json' } }),
      new Response(new Uint8Array([0xc3, 0x28]), { headers: { 'Content-Type': 'application/json' } }),
      new Response('', { headers: { 'Content-Type': 'application/json' } }), new Response(null, { status: 204 })];
    for (const response of responses) expect(await createSessionControlRepository(configuration, async () => response)
      .lookup(secret)).toEqual(unavailable(response.status === 204 ? 'upstream_rejected' : 'invalid_response'));
  });

  it('caps streamed response bytes before parsing, aborting and cancelling immediately', async () => {
    let cancelled = false;
    let signal: AbortSignal | null | undefined;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new TextEncoder().encode(' '.repeat(8193))); },
      cancel() { cancelled = true; return new Promise<void>(() => {}); },
    });
    const result = await createSessionControlRepository(configuration, async (_url: unknown, init?: RequestInit) => {
      signal = init?.signal;
      return new Response(stream, { headers: { 'Content-Type': 'application/json' } });
    }).lookup(secret);
    expect(result).toEqual(unavailable('invalid_response'));
    expect(cancelled).toBe(true);
    expect(signal?.aborted).toBe(true);
  });

  it('uses one total two-second deadline even when fetch ignores AbortSignal', async () => {
    vi.useFakeTimers();
    let signal: AbortSignal | null | undefined;
    const fetcher = vi.fn((_url: unknown, init?: RequestInit): Promise<Response> => {
      signal = init?.signal;
      return new Promise(() => {});
    });
    const pending = createSessionControlRepository(configuration, fetcher).lookup(secret);
    await vi.advanceTimersByTimeAsync(2000);
    expect(await pending).toEqual(unavailable('timeout'));
    expect(signal?.aborted).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('includes stalled body reads in the same deadline and cancels without waiting', async () => {
    vi.useFakeTimers();
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new TextEncoder().encode('{')); },
      cancel() { cancelled = true; return new Promise<void>(() => {}); },
    });
    const pending = createSessionControlRepository(configuration, async () => {
      await new Promise(resolve => setTimeout(resolve, 1500));
      return new Response(stream, { headers: { 'Content-Type': 'application/json' } });
    }).lookup(secret);
    await vi.advanceTimersByTimeAsync(2000);
    expect(await pending).toEqual(unavailable('timeout'));
    expect(cancelled).toBe(true);
  });

  it('sanitizes transport failures and never retries', async () => {
    const fetcher = vi.fn(() => Promise.reject(new Error(`sensitive ${secret} ${configuration.secretKey}`)));
    expect(await createSessionControlRepository(configuration, fetcher).lookup(secret)).toEqual(unavailable('transport'));
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
