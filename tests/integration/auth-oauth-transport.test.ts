import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOAuthTransport, createPkceVerifier, derivePkceChallenge } from '../../src/infrastructure/auth/oauthTransport';

const configuration = {
  supabaseOrigin: 'https://abcdefghijklmnopqrst.supabase.co',
  publishableKey: 'sb_publishable_sample_only_1234567890',
  appOrigin: 'https://studio.example.test',
};
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const tokens = { access_token: 'header.payload.signature', refresh_token: 'sample_refresh', token_type: 'bearer' };
const response = (body: unknown = tokens) => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
afterEach(() => { vi.useRealTimers(); });

describe('fixed Google PKCE transport (tokens remain unverified)', () => {
  // Changing the challenge derivation to hash decoded bytes breaks this RFC7636 vector.
  it('derives the S256 challenge from verifier text and generates canonical random verifiers', () => {
    expect(derivePkceChallenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    const first = createPkceVerifier(); const second = createPkceVerifier();
    expect(first).toMatch(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
    expect(first).not.toBe(second);
    expect(() => derivePkceChallenge(`${verifier}=`)).toThrow('Invalid PKCE verifier');
  });
  it('builds only the configured Google redirect and never supplies provider state or a secret key', () => {
    const transport = createOAuthTransport(configuration);
    const result = transport.authorizationUrl(verifier);
    expect(result.kind).toBe('ready');
    if (result.kind !== 'ready') throw new Error('Expected URL');
    const url = new URL(result.url);
    expect(url.origin + url.pathname).toBe('https://abcdefghijklmnopqrst.supabase.co/auth/v1/authorize');
    expect(Object.fromEntries(url.searchParams)).toEqual({ provider: 'google',
      redirect_to: 'https://studio.example.test/api/v1/auth/callback',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 's256' });
    expect(result.url).not.toContain(verifier);
    expect(result.url).not.toContain(configuration.publishableKey);
  });
  it('snapshots fixed configuration and exchanges once with a publishable key, never a bearer or cookie', async () => {
    const mutable = { ...configuration };
    const requests: { url: string; init: RequestInit | undefined }[] = [];
    const transport = createOAuthTransport(mutable, (async (url, init) => { requests.push({ url: String(url), init }); return response(); }) as typeof fetch);
    mutable.supabaseOrigin = 'https://attacker.example';
    expect(await transport.exchange({ authorizationCode: 'sample_code', codeVerifier: verifier })).toEqual({ kind: 'tokens',
      accessToken: tokens.access_token, refreshToken: tokens.refresh_token });
    expect(requests).toHaveLength(1);
    const { url, init } = requests[0];
    expect(url).toBe('https://abcdefghijklmnopqrst.supabase.co/auth/v1/token?grant_type=pkce');
    expect(JSON.parse(String(init?.body))).toEqual({ auth_code: 'sample_code', code_verifier: verifier });
    expect(new Headers(init?.headers).get('apikey')).toBe(configuration.publishableKey);
    expect(new Headers(init?.headers).has('Authorization')).toBe(false);
    expect(init).toMatchObject({ method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store' });
  });
  it('copies only the unverified token pair, dropping user, provider tokens and expiry claims', async () => {
    const transport = createOAuthTransport(configuration, (async () => response({ ...tokens, user: { id: 'untrusted' },
      provider_token: 'discard_me', provider_refresh_token: 'discard_me', expires_in: 99999999 })) as typeof fetch);
    const result = await transport.refresh({ refreshToken: 'old_refresh' });
    expect(result).toEqual({ kind: 'tokens', accessToken: tokens.access_token, refreshToken: tokens.refresh_token });
    expect(Object.isFrozen(result)).toBe(true);
  });
  it('uses the distinct refresh grant once without resending an access token', async () => {
    let sent: RequestInit | undefined; let destination = '';
    const transport = createOAuthTransport(configuration, (async (url, init) => { destination = String(url); sent = init; return response(); }) as typeof fetch);
    await transport.refresh({ refreshToken: 'old_refresh' });
    expect(destination).toBe('https://abcdefghijklmnopqrst.supabase.co/auth/v1/token?grant_type=refresh_token');
    expect(JSON.parse(String(sent?.body))).toEqual({ refresh_token: 'old_refresh' });
  });
  it.each(['http://studio.example.test', 'https://studio.example.test/', 'https://studio.example.test/path', 'https://*.example.test'])
    ('fails closed before sending with invalid app origin %s', async appOrigin => {
      let calls = 0;
      const transport = createOAuthTransport({ ...configuration, appOrigin }, (async () => { calls++; return response(); }) as typeof fetch);
      expect(transport.authorizationUrl(verifier)).toEqual({ kind: 'not_sent', reason: 'configuration' });
      expect(await transport.exchange({ authorizationCode: 'code', codeVerifier: verifier })).toEqual({ kind: 'not_sent', reason: 'configuration' });
      expect(calls).toBe(0);
    });
  it.each([
    { authorizationCode: '', codeVerifier: verifier }, { authorizationCode: 'a\ncode', codeVerifier: verifier },
    { authorizationCode: 'x'.repeat(2049), codeVerifier: verifier }, { authorizationCode: 'code', codeVerifier: `${verifier}=` },
    { authorizationCode: 'code', codeVerifier: verifier, url: 'https://attacker.example' },
  ])('rejects malformed or expanded exchange input before any request', async input => {
    let calls = 0;
    const transport = createOAuthTransport(configuration, (async () => { calls++; return response(); }) as typeof fetch);
    expect(await transport.exchange(input)).toEqual({ kind: 'not_sent', reason: 'invalid_input' });
    expect(calls).toBe(0);
  });
  it('does not invoke input accessors', async () => {
    let reads = 0;
    const input = { get authorizationCode() { reads++; return 'code'; }, codeVerifier: verifier };
    expect(await createOAuthTransport(configuration).exchange(input)).toEqual({ kind: 'not_sent', reason: 'invalid_input' });
    expect(reads).toBe(0);
  });
  it('does not send if the enclosing request has already been cancelled', async () => {
    const controller = new AbortController(); controller.abort(); let calls = 0;
    const transport = createOAuthTransport(configuration, (async () => { calls++; return response(); }) as typeof fetch);
    expect(await transport.refresh({ refreshToken: 'old_refresh' }, controller.signal)).toEqual({ kind: 'not_sent', reason: 'cancelled' });
    expect(calls).toBe(0);
  });
  it.each([400, 401, 403, 429, 500, 503])('never retries or exposes upstream body for status %i', async status => {
    let calls = 0;
    const transport = createOAuthTransport(configuration, (async () => { calls++; return new Response('private upstream details', { status }); }) as typeof fetch);
    expect(await transport.refresh({ refreshToken: 'old_refresh' })).toEqual({ kind: 'outcome_unknown', reason: 'upstream_rejected' });
    expect(calls).toBe(1);
  });
  it.each([
    new Response('not json', { headers: { 'Content-Type': 'application/json' } }),
    new Response(JSON.stringify(tokens), { headers: { 'Content-Type': 'text/plain' } }),
    response({ ...tokens, token_type: 'mac' }), response({ ...tokens, refresh_token: '' }),
    response({ ...tokens, access_token: 'a'.repeat(8193) }), response({ ...tokens, access_token: 'a\nb' }),
  ])('treats malformed success as unknown, never as a session or a safe retry', async upstream => {
    expect(await createOAuthTransport(configuration, (async () => upstream) as typeof fetch)
      .exchange({ authorizationCode: 'sample_code', codeVerifier: verifier })).toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
  });
  it('bounds the response stream before allocating a token result', async () => {
    let cancelled = false;
    const upstream = new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(65_537)); }, cancel() { cancelled = true; } }),
      { headers: { 'Content-Type': 'application/json' } });
    expect(await createOAuthTransport(configuration, (async () => upstream) as typeof fetch)
      .refresh({ refreshToken: 'old_refresh' })).toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
    expect(cancelled).toBe(true);
  });
  it('bounds a stalled body with the same deadline as headers, without a second exchange', async () => {
    vi.useFakeTimers(); let calls = 0; let aborted = false;
    const transport = createOAuthTransport(configuration, (async (_url, init) => { calls++;
      init?.signal?.addEventListener('abort', () => { aborted = true; });
      return new Response(new ReadableStream({ start() {} }), { headers: { 'Content-Type': 'application/json' } });
    }) as typeof fetch);
    const pending = transport.exchange({ authorizationCode: 'sample_code', codeVerifier: verifier });
    await vi.advanceTimersByTimeAsync(5000);
    expect(await pending).toEqual({ kind: 'outcome_unknown', reason: 'timeout' });
    expect(calls).toBe(1); expect(aborted).toBe(true);
  });
  it('cancels a sent operation when its parent deadline fires, keeping the outcome unknown', async () => {
    const controller = new AbortController();
    const transport = createOAuthTransport(configuration, (() => new Promise(() => {})) as typeof fetch);
    const pending = transport.refresh({ refreshToken: 'old_refresh' }, controller.signal);
    controller.abort();
    expect(await pending).toEqual({ kind: 'outcome_unknown', reason: 'cancelled' });
  });
  it('sanitizes a transport exception and does not retry a potentially consumed code', async () => {
    let calls = 0;
    const transport = createOAuthTransport(configuration, (async () => { calls++; throw new Error('secret provider diagnostics'); }) as typeof fetch);
    expect(await transport.exchange({ authorizationCode: 'sample_code', codeVerifier: verifier }))
      .toEqual({ kind: 'outcome_unknown', reason: 'transport' });
    expect(calls).toBe(1);
  });
  it('rejects late headers even before an overdue timer callback can run', async () => {
    vi.useFakeTimers(); let elapsed = 0;
    const transport = createOAuthTransport(configuration, (async () => { elapsed = 5001; return response(); }) as typeof fetch, () => elapsed);
    expect(await transport.refresh({ refreshToken: 'old_refresh' })).toEqual({ kind: 'outcome_unknown', reason: 'timeout' });
  });
  it('rejects a body that crosses the total deadline before the timer is scheduled', async () => {
    vi.useFakeTimers(); let elapsed = 0; let chunks = 0;
    const upstream = new Response(new ReadableStream({ pull(c) {
      if (chunks++ === 0) { elapsed = 4999; c.enqueue(new TextEncoder().encode(JSON.stringify(tokens))); }
      else { elapsed = 5001; c.close(); }
    } }, { highWaterMark: 0 }), { headers: { 'Content-Type': 'application/json' } });
    const transport = createOAuthTransport(configuration, (async () => upstream) as typeof fetch, () => elapsed);
    expect(await transport.refresh({ refreshToken: 'old_refresh' })).toEqual({ kind: 'outcome_unknown', reason: 'timeout' });
  });
});

describe('OAuth cancellation at the transport boundary', () => {
  it('does not send when cancellation occurs during preflight', async () => {
    const controller = new AbortController();
    const fetcher = vi.fn<typeof fetch>(async () => response());
    const transport = createOAuthTransport(configuration, fetcher, () => {
      controller.abort();
      return 1;
    });

    expect(await transport.refresh({ refreshToken: 'old_refresh' }, controller.signal))
      .toEqual({ kind: 'not_sent', reason: 'cancelled' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('reports an unknown outcome if cancellation wins before the token result returns', async () => {
    const controller = new AbortController();
    const clock = vi.fn().mockReturnValue(0);
    for (let check = 0; check < 4; check++) clock.mockReturnValueOnce(0);
    clock.mockImplementationOnce(() => { queueMicrotask(() => controller.abort()); return 0; });
    const fetcher = vi.fn<typeof fetch>(async () => response());
    const transport = createOAuthTransport(configuration, fetcher, clock);

    expect(await transport.refresh({ refreshToken: 'old_refresh' }, controller.signal))
      .toEqual({ kind: 'outcome_unknown', reason: 'cancelled' });
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it('cancels and releases a late response body after the request returns', async () => {
    const controller = new AbortController();
    const headers = Promise.withResolvers<Response>();
    const cancelBody = vi.fn();
    const body = new ReadableStream<Uint8Array>({ cancel: cancelBody });
    const transport = createOAuthTransport(configuration, async () => headers.promise);
    const pending = transport.refresh({ refreshToken: 'old_refresh' }, controller.signal);
    controller.abort();
    expect(await pending).toEqual({ kind: 'outcome_unknown', reason: 'cancelled' });

    headers.resolve(new Response(body, { headers: { 'Content-Type': 'application/json' } }));
    await vi.waitFor(() => expect(cancelBody).toHaveBeenCalledOnce());
    expect(body.locked).toBe(false);
  });

  it('sanitizes unreadable input before any request', async () => {
    const fetcher = vi.fn<typeof fetch>(async () => response());
    const value = new Proxy({}, { ownKeys() { throw new Error('private diagnostic'); } });
    const transport = createOAuthTransport(configuration, fetcher);

    expect(await transport.refresh(value)).toEqual({ kind: 'not_sent', reason: 'invalid_input' });
    expect(await transport.exchange(value)).toEqual({ kind: 'not_sent', reason: 'invalid_input' });
    expect(fetcher).not.toHaveBeenCalled();
  });
});
