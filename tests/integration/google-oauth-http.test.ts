import { describe, expect, it, vi } from 'vitest';
import { createGoogleOAuthHttp } from '../../src/application/auth/googleOAuthHttp';

const origin = 'https://studio.example.test';
const browser = `jls-browser-v1.${'A'.repeat(43)}`;
const flow = `jls-oauth-v1.${'E'.repeat(43)}`;
const proof = `jls-csrf-v1.${'I'.repeat(43)}`;
const session = 'M'.repeat(43);
const browserId = '22222222-2222-4222-8222-222222222222';
const attemptId = '33333333-3333-4333-8333-333333333333';
const operationId = '44444444-4444-4444-8444-444444444444';
const loginCookie = `__Host-jls-browser=${browser}`;
const callbackCookie = `${loginCookie}; __Host-jls-oauth=${flow}`;
const location = 'https://abcdefghijklmnopqrst.supabase.co/auth/v1/authorize?provider=google';

function setup() {
  const resolveAction = vi.fn().mockResolvedValue({ kind: 'resolved', browserId, operationId, generation: 4 });
  const inspectCallback = vi.fn().mockResolvedValue({ kind: 'pending', browserId, attemptId });
  const begin = vi.fn().mockResolvedValue({ kind: 'redirect', location, flowSecret: flow });
  const finish = vi.fn().mockResolvedValue({ kind: 'signed_in', sessionSecret: session });
  const verifyCurrent = vi.fn().mockResolvedValue({ kind: 'authorized' });
  const handlers = createGoogleOAuthHttp(origin, { resolveAction, inspectCallback, begin, finish, verifyCurrent });
  return { handlers, resolveAction, inspectCallback, begin, finish, verifyCurrent };
}

function login(body = `csrfToken=${proof}`, cookie = loginCookie, requestOrigin = origin) {
  return new Request(origin + '/api/v1/auth/login', {
    method: 'POST', headers: { Origin: requestOrigin, Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded' }, body,
  });
}
function callback(query = 'code=fixture', cookie = callbackCookie) {
  return new Request(origin + '/api/v1/auth/callback?' + query, { headers: { Cookie: cookie } });
}

describe('Google OAuth HTTP handlers', () => {
  it('issues only the flow cookie and external top-level redirect after begin', async () => {
    const { handlers, begin } = setup();
    const response = await handlers.login(login());
    expect(response.status).toBe(303);
    expect(response.headers.get('Location')).toBe(location);
    expect(response.headers.get('Cache-Control')).toBe('private, no-store');
    expect(response.headers.get('X-Request-Id')).toMatch(/^[0-9a-f-]{36}$/);
    expect(response.headers.getSetCookie()).toEqual([
      `__Host-jls-oauth=${flow}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
    ]);
    expect(await response.text()).toBe('');
    expect(begin.mock.calls[0][0]).toMatchObject({ browserId, operationId, generation: 4, browserSecret: browser, csrfToken: proof });
  });

  it('rejects cross-origin, oversized, duplicate-field and duplicate-cookie requests before lookup', async () => {
    const { handlers, resolveAction } = setup();
    expect((await handlers.login(login(undefined, undefined, 'https://other.example.test'))).status).toBe(403);
    expect((await handlers.login(login('x'.repeat(257)))).status).toBe(400);
    expect((await handlers.login(login(`csrfToken=${proof}&csrf%54oken=${proof}`))).status).toBe(400);
    expect((await handlers.login(login(undefined, `${loginCookie}; ${loginCookie}`))).status).toBe(400);
    expect(resolveAction).not.toHaveBeenCalled();
  });

  it('uses the contract temporary outcome when an earlier attempt blocks login', async () => {
    const { handlers, begin } = setup();
    begin.mockResolvedValueOnce({ kind: 'restart_required' });
    const response = await handlers.login(login());
    expect(response.status).toBe(503);
    expect((await response.json()).code).toBe('temporarily_unavailable');
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it('routes a pending callback to fresh verification and emits only the confirmed session cookie', async () => {
    const { handlers, finish } = setup();
    const response = await handlers.callback(callback());
    expect(response.status).toBe(303);
    expect(response.headers.get('Location')).toBe('/today');
    expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
    expect(response.headers.getSetCookie()).toEqual([
      `__Host-jls-session=${session}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`,
    ]);
    expect(await response.text()).toBe('');
    expect(finish.mock.calls[0][0]).toEqual({
      browserId, attemptId, browserSecret: browser, flowSecret: flow, authorizationCode: 'fixture',
    });
  });

  it('sanitizes provider denial and malformed queries without inspecting or modifying attempts', async () => {
    const { handlers, inspectCallback } = setup();
    const denied = await handlers.callback(callback('error=denied&error_description=private-data'));
    expect(denied.status).toBe(403);
    expect(await denied.text()).not.toContain('private-data');
    expect((await handlers.callback(callback('code=one&%63ode=two'))).status).toBe(400);
    expect((await handlers.callback(callback('code=a%20b'))).status).toBe(400);
    expect((await handlers.callback(callback('code=%ZZ'))).status).toBe(400);
    expect((await handlers.callback(callback('code=one%0Atwo'))).status).toBe(400);
    expect((await handlers.callback(callback('code=one', callbackCookie + '; __Host-jls-session'))).status).toBe(400);
    expect(inspectCallback).not.toHaveBeenCalled();
  });

  it('lets a fresh callback replace a bounded invalid old session cookie without treating it as absent or current', async () => {
    const { handlers, inspectCallback, finish, verifyCurrent } = setup();
    const response = await handlers.callback(callback(undefined, callbackCookie + '; __Host-jls-session=bad'));
    expect(response.status).toBe(303);
    expect(inspectCallback.mock.calls[0][0].presentedSessionHash).toMatch(/^[0-9a-f]{64}$/);
    expect(finish).toHaveBeenCalledOnce();
    expect(verifyCurrent).not.toHaveBeenCalled();

    inspectCallback.mockResolvedValueOnce({ kind: 'completed_with_cookie', attemptId, sessionId: operationId, generation: 5 });
    const wrongMatch = await handlers.callback(callback(undefined, callbackCookie + '; __Host-jls-session=bad'));
    expect(wrongMatch.status).toBe(503);
    expect(verifyCurrent).not.toHaveBeenCalled();
  });

  it('requires current authorization for a matching replay and issues no cookies', async () => {
    const { handlers, inspectCallback, verifyCurrent, finish } = setup();
    inspectCallback.mockResolvedValue({ kind: 'completed_with_cookie', attemptId, sessionId: operationId, generation: 5 });
    const request = () => callback(undefined, callbackCookie + `; __Host-jls-session=${session}`);
    expect((await handlers.callback(request())).headers.getSetCookie()).toEqual([]);
    verifyCurrent.mockResolvedValueOnce({ kind: 'denied' });
    const denied = await handlers.callback(request());
    expect(denied.status).toBe(409);
    expect(denied.headers.getSetCookie()).toEqual([]);
    expect(finish).not.toHaveBeenCalled();
  });

  it('does no work when Next delegates HEAD to the callback handler', async () => {
    const { handlers, inspectCallback, finish } = setup();
    const request = new Request(origin + '/api/v1/auth/callback?code=fixture', {
      method: 'HEAD', headers: { Cookie: callbackCookie },
    });
    const response = await handlers.callback(request);
    expect(response.status).toBe(405);
    expect(response.headers.get('Allow')).toBe('GET');
    expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
    expect(inspectCallback).not.toHaveBeenCalled();
    expect(finish).not.toHaveBeenCalled();
  });

  it('reinspects a claim race without starting another exchange', async () => {
    const { handlers, finish, inspectCallback } = setup();
    finish.mockResolvedValueOnce({ kind: 'restart_required' });
    inspectCallback.mockResolvedValueOnce({ kind: 'pending', browserId, attemptId }).mockResolvedValueOnce({ kind: 'in_progress' });
    expect((await handlers.callback(callback())).status).toBe(503);
    expect(inspectCallback).toHaveBeenCalledTimes(2);
    expect(finish).toHaveBeenCalledOnce();
  });

  it('stops reading a stalled form when the request is cancelled', async () => {
    const { handlers, resolveAction } = setup();
    const controller = new AbortController();
    const waiting = Promise.withResolvers<void>();
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ pull() { waiting.resolve(); }, cancel }, { highWaterMark: 0 });
    const request = new Request(origin + '/api/v1/auth/login', {
      method: 'POST', headers: { Origin: origin, Cookie: loginCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body, duplex: 'half', signal: controller.signal,
    } as RequestInit & { duplex: 'half' });

    const result = handlers.login(request);
    await waiting.promise;
    controller.abort();
    expect((await result).status).toBe(503);
    expect(cancel).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
    expect(resolveAction).not.toHaveBeenCalled();
  });
});
