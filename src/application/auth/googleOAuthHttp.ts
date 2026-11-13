import { randomUUID } from 'node:crypto';
import { BrowserBindingSecretSchema, OAuthAttemptSecretSchema, parseAuthCallbackQuery, parseAuthLoginForm } from '../../contracts/auth';
import { createProblem, type ProblemCode } from '../../contracts/problems';
import { fingerprintSessionCookie, hashAuthActionSecret } from '../../infrastructure/auth/authActionSecrets';
import type { OAuthActionRepository } from '../../infrastructure/auth/oauthActionRepository';
import { hashSessionSecret } from '../../infrastructure/auth/sessionSecrets';
import type { createGoogleOAuthBegin } from './googleOAuthBegin';
import type { createGoogleOAuthCallback } from './googleOAuthCallback';
import { createOAuthRequestBudget } from './oauthRequestBudget';

interface Dependencies extends Pick<OAuthActionRepository, 'resolveAction' | 'inspectCallback'> {
  readonly begin: ReturnType<typeof createGoogleOAuthBegin>;
  readonly finish: ReturnType<typeof createGoogleOAuthCallback>;
  readonly verifyCurrent: (input: { sessionId: string; sessionSecret: string; browserSecret: string },
    signal: AbortSignal) => Promise<{ kind: 'authorized' | 'denied' | 'unavailable' }>;
}

const cookieNames = ['__Host-jls-browser', '__Host-jls-oauth', '__Host-jls-session'] as const;
type CookieName = typeof cookieNames[number];

function readCookies(header: string | null): Map<CookieName, string> | null {
  const result = new Map<CookieName, string>();
  if (header === null) return result;
  if (header.length > 16_384) return null;
  for (const pair of header.split(';')) {
    const entry = pair.trim();
    const delimiter = entry.indexOf('=');
    const name = (delimiter < 0 ? entry : entry.slice(0, delimiter)).trimEnd() as CookieName;
    if (!cookieNames.includes(name)) continue;
    if (delimiter < 0 || result.has(name)) return null;
    const value = entry.slice(delimiter + 1);
    if (value.length > 8192 || !/^[\x21-\x7e]*$/.test(value) || /[",\\]/.test(value)) return null;
    result.set(name, value);
  }
  return result;
}

async function loginForm(request: Request, signal: AbortSignal): Promise<URLSearchParams | null> {
  const contentType = request.headers.get('Content-Type')?.trim().toLowerCase();
  if (!contentType || !/^application\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?$/.test(contentType)) return null;
  const reader = request.body?.getReader();
  if (!reader) return null;
  const { promise: stopped, resolve } = Promise.withResolvers<null>();
  let cancellationStarted = false;
  const cancel = () => {
    resolve(null);
    if (cancellationStarted) return;
    cancellationStarted = true;
    try { void reader.cancel().catch(() => {}); } catch { /* Do not let a broken body hold the request. */ }
  };
  signal.addEventListener('abort', cancel, { once: true });
  if (signal.aborted) cancel();
  const bytes = new Uint8Array(256);
  let length = 0;
  try {
    while (true) {
      if (signal.aborted) return null;
      const item = await Promise.race([reader.read(), stopped]);
      if (item === null || signal.aborted) return null;
      if (item.done) break;
      if (item.value.length > bytes.length - length) return null;
      bytes.set(item.value, length);
      length += item.value.length;
    }
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length));
    return new URLSearchParams(text);
  } catch { return null; }
  finally {
    signal.removeEventListener('abort', cancel);
    cancel();
    try { reader.releaseLock(); } catch { /* A stalled stream must not prevent returning. */ }
  }
}

function cookie(name: CookieName, value: string, maxAge: number): string {
  return `${name}=${value}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function responseContext(callback: boolean) {
  const requestId = randomUUID();
  const headers = new Headers({ 'Cache-Control': 'private, no-store', 'X-Request-Id': requestId });
  if (callback) headers.set('Referrer-Policy', 'no-referrer');
  return {
    problem(code: ProblemCode) {
      const body = createProblem(code, requestId);
      headers.set('Content-Type', 'application/problem+json');
      return new Response(JSON.stringify(body), { status: body.status, headers });
    },
    methodNotAllowed(allow: 'GET' | 'POST') {
      headers.set('Allow', allow);
      return new Response(null, { status: 405, headers });
    },
    redirect(location: string, issuedCookie?: string) {
      headers.set('Location', location);
      if (issuedCookie) headers.append('Set-Cookie', issuedCookie);
      return new Response(null, { status: 303, headers });
    },
  };
}

/** Request handlers for the approved HTTP contract. The deployment owns rate limits and composition. */
export function createGoogleOAuthHttp(appOrigin: string, deps: Dependencies) {
  const parsed = new URL(appOrigin);
  if (parsed.protocol !== 'https:' || parsed.origin !== appOrigin || parsed.hostname.includes('*')) {
    throw Error('Invalid canonical Auth origin');
  }
  return {
    async login(request: Request): Promise<Response> {
      const response = responseContext(false);
      if (request.method !== 'POST') return response.methodNotAllowed('POST');
      if (request.headers.get('Origin') !== appOrigin) return response.problem('forbidden');
      try {
        const budget = createOAuthRequestBudget(10_000, () => performance.now(), request.signal);
        if (budget.expired()) return response.problem('temporarily_unavailable');
        const cookies = readCookies(request.headers.get('Cookie'));
        if (!cookies) return response.problem('malformed_request');
        const binding = BrowserBindingSecretSchema.safeParse(cookies.get('__Host-jls-browser'));
        if (!binding.success) return response.problem(cookies.has('__Host-jls-browser') ? 'malformed_request' : 'forbidden');
        const form = await loginForm(request, budget.signal);
        if (budget.expired()) return response.problem('temporarily_unavailable');
        if (!form) return response.problem('malformed_request');
        const parsedForm = parseAuthLoginForm(form);
        if (!parsedForm.ok) return response.problem('malformed_request');

        const browserSecret = binding.data;
        const csrfToken = parsedForm.value.csrfToken;
        const presentedSession = cookies.get('__Host-jls-session');
        const proof = await deps.resolveAction({
          browserHash: hashAuthActionSecret('browser', browserSecret), proofHash: hashAuthActionSecret('csrf-login', csrfToken),
          purpose: 'login', cookieFingerprint: fingerprintSessionCookie(presentedSession),
        }, budget.signal);
        if (budget.expired()) return response.problem('temporarily_unavailable');
        if (proof.kind !== 'resolved') return response.problem(proof.kind === 'denied' ? 'forbidden' : 'temporarily_unavailable');

        const result = await deps.begin({
          browserId: proof.browserId, operationId: proof.operationId, generation: proof.generation,
          browserSecret, csrfToken, presentedSession,
        }, budget.signal);
        if (result.kind !== 'redirect' || budget.expired()) {
          return response.problem(result.kind === 'denied' ? 'forbidden' : 'temporarily_unavailable');
        }
        return response.redirect(result.location, cookie('__Host-jls-oauth', result.flowSecret, 600));
      } catch { return response.problem('temporarily_unavailable'); }
    },

    async callback(request: Request): Promise<Response> {
      const response = responseContext(true);
      if (request.method !== 'GET') return response.methodNotAllowed('GET');
      try {
        const budget = createOAuthRequestBudget(10_000, () => performance.now(), request.signal);
        if (budget.expired()) return response.problem('temporarily_unavailable');
        const url = new URL(request.url);
        if (url.search.length > 25_000 || /%(?![0-9a-f]{2})/i.test(url.search) || request.body !== null) return response.problem('malformed_request');
        const query = parseAuthCallbackQuery(url.searchParams);
        if (!query.ok) return response.problem('malformed_request');
        if ('error' in query.value) return response.problem('forbidden');
        if (!/^[\x21-\x7e]{1,2048}$/.test(query.value.code)) return response.problem('malformed_request');
        const cookies = readCookies(request.headers.get('Cookie'));
        if (!cookies) return response.problem('malformed_request');
        const browserSecret = cookies.get('__Host-jls-browser');
        const flowSecret = cookies.get('__Host-jls-oauth');
        if (browserSecret === undefined || flowSecret === undefined) return response.problem('forbidden');
        if (!BrowserBindingSecretSchema.safeParse(browserSecret).success || !OAuthAttemptSecretSchema.safeParse(flowSecret).success) {
          return response.problem('malformed_request');
        }
        const sessionSecret = cookies.get('__Host-jls-session');
        let presentedSessionHash: string | null = null;
        let usableSessionSecret: string | undefined;
        if (sessionSecret !== undefined) {
          try {
            presentedSessionHash = hashSessionSecret(sessionSecret);
            usableSessionSecret = sessionSecret;
          } catch {
            // Exact malformed presentation stays distinct from absence and from a bearer.
            presentedSessionHash = fingerprintSessionCookie(sessionSecret).slice('present:'.length);
          }
        }
        const lookupInput = {
          browserHash: hashAuthActionSecret('browser', browserSecret), flowHash: hashAuthActionSecret('oauth', flowSecret), presentedSessionHash,
        };

        async function inspect() {
          return deps.inspectCallback(lookupInput, budget.signal);
        }
        let lookup = await inspect();
        if (budget.expired()) return response.problem('temporarily_unavailable');
        if (lookup.kind === 'pending') {
          const result = await deps.finish({
            browserId: lookup.browserId, attemptId: lookup.attemptId, browserSecret, flowSecret, authorizationCode: query.value.code,
          }, budget.signal);
          if (budget.expired()) return response.problem('temporarily_unavailable');
          if (result.kind === 'signed_in') {
            return response.redirect('/today', cookie('__Host-jls-session', result.sessionSecret, 604_800));
          }
          if (result.kind === 'denied') return response.problem('forbidden');
          if (result.kind === 'unavailable') return response.problem('temporarily_unavailable');
          lookup = await inspect();
          if (budget.expired()) return response.problem('temporarily_unavailable');
        }

        if (lookup.kind === 'completed_with_cookie' && usableSessionSecret !== undefined) {
          const verified = await deps.verifyCurrent({ sessionId: lookup.sessionId, sessionSecret: usableSessionSecret, browserSecret }, budget.signal);
          if (verified.kind === 'authorized' && !budget.expired()) return response.redirect('/today');
          return response.problem(verified.kind === 'denied' ? 'sign_in_restart_required' : 'temporarily_unavailable');
        }
        if (lookup.kind === 'restart_required' || lookup.kind === 'pending') return response.problem('sign_in_restart_required');
        return response.problem(lookup.kind === 'denied' ? 'forbidden' : 'temporarily_unavailable');
      } catch { return response.problem('temporarily_unavailable'); }
    },
  };
}
