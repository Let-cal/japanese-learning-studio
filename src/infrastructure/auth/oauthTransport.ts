import { createHash, randomBytes } from 'node:crypto';

export interface OAuthTransportConfiguration {
  readonly supabaseOrigin: unknown;
  readonly publishableKey: unknown;
  readonly appOrigin: unknown;
}
export type OAuthNotSent = { readonly kind: 'not_sent'; readonly reason: 'configuration' | 'invalid_input' | 'cancelled' };
export type OAuthTokenResult = OAuthNotSent
  /** A token response is not a verified identity or app session. */
  | { readonly kind: 'tokens'; readonly accessToken: string; readonly refreshToken: string }
  /** The durable caller must resolve/close its sent intent, never blindly resend. */
  | { readonly kind: 'outcome_unknown'; readonly reason: 'timeout' | 'cancelled' | 'transport' | 'upstream_rejected' | 'invalid_response' };
export interface OAuthTransport {
  authorizationUrl(verifier: unknown): { readonly kind: 'ready'; readonly url: string } | OAuthNotSent;
  exchange(input: unknown, signal?: AbortSignal): Promise<OAuthTokenResult>;
  refresh(input: unknown, signal?: AbortSignal): Promise<OAuthTokenResult>;
}
const notSent = (reason: OAuthNotSent['reason']): OAuthNotSent => Object.freeze({ kind: 'not_sent', reason });
const unknown = (reason: Extract<OAuthTokenResult, { kind: 'outcome_unknown' }>['reason']): OAuthTokenResult =>
  Object.freeze({ kind: 'outcome_unknown', reason });

function snapshot(value: unknown, names: readonly string[]): Record<string, unknown> | null {
  try {
    if (value === null || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== names.length) return null;
    const result: Record<string, unknown> = Object.create(null);
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !('value' in descriptor)) return null;
      result[name] = descriptor.value;
    }
    return result;
  } catch { return null; }
}
function validVerifier(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value);
}
function boundedToken(value: unknown, maximum = 8192): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum && /^[\x21-\x7e]+$/.test(value);
}
export function createPkceVerifier(): string {
  try { return randomBytes(32).toString('base64url'); }
  catch { throw new Error('PKCE generation failed'); }
}
export function derivePkceChallenge(verifier: unknown): string {
  if (!validVerifier(verifier)) throw new Error('Invalid PKCE verifier');
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/** Server transport only. Import oauthGateway from application code. No environment reads or automatic retries. */
export function createOAuthTransport(configuration: unknown, fetcher: typeof fetch = fetch,
  monotonicClock: () => number = () => performance.now()): OAuthTransport {
  let trusted: { origin: string; key: string; callback: string } | null = null;
  try {
    const config = snapshot(configuration, ['supabaseOrigin', 'publishableKey', 'appOrigin']);
    if (config && typeof config.supabaseOrigin === 'string' && /^https:\/\/[a-z0-9]{20}\.supabase\.co$/.test(config.supabaseOrigin)
      && typeof config.publishableKey === 'string' && /^sb_publishable_[A-Za-z0-9_-]{16,256}$/.test(config.publishableKey)
      && typeof config.appOrigin === 'string' && config.appOrigin.length <= 2048) {
      const app = new URL(config.appOrigin);
      if (app.protocol === 'https:' && app.origin === config.appOrigin && !app.username && !app.password && !app.hostname.includes('*')) {
        trusted = { origin: config.supabaseOrigin, key: config.publishableKey, callback: `${app.origin}/api/v1/auth/callback` };
      }
    }
  } catch { /* Invalid configuration supplies no transport capability. */ }

  async function send(grant: 'pkce' | 'refresh_token', body: object, signal?: AbortSignal): Promise<OAuthTokenResult> {
    if (!trusted) return notSent('configuration');
    if (signal?.aborted) return notSent('cancelled');
    let started: number;
    try { started = monotonicClock(); }
    catch { return notSent('configuration'); }
    if (signal?.aborted) return notSent('cancelled');
    if (!Number.isFinite(started) || started < 0) return notSent('configuration');
    const expired = () => {
      const current = monotonicClock();
      return !Number.isFinite(started) || !Number.isFinite(current) || current < started || current - started >= 5000;
    };
    const controller = new AbortController();
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let cancelledReader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let completed = false;
    const cancel = () => {
      controller.abort();
      if (reader && reader !== cancelledReader) {
        cancelledReader = reader;
        // Best-effort cleanup must not block the caller's deadline.
        try { void reader.cancel().catch(() => {}); } catch { /* No secret-bearing cleanup error escapes. */ }
      }
    };
    const releaseReader = () => {
      try {
        reader?.releaseLock();
        reader = undefined;
      } catch { /* The pending read owns the lock until it settles. */ }
    };
    const { promise: stop, resolve } = Promise.withResolvers<OAuthTokenResult>();
    const onAbort = () => { resolve(unknown('cancelled')); cancel(); };
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => { resolve(unknown('timeout')); cancel(); }, 5000);
    const request = (async (): Promise<OAuthTokenResult> => {
      try {
        const response = await fetcher(`${trusted.origin}/auth/v1/token?grant_type=${grant}`, {
          method: 'POST', headers: { apikey: trusted.key, 'Content-Type': 'application/json', Accept: 'application/json',
            'X-Supabase-Api-Version': '2024-01-01' },
          body: JSON.stringify(body), redirect: 'error', credentials: 'omit', cache: 'no-store', signal: controller.signal,
        });
        reader = response.body?.getReader();
        if (expired()) { cancel(); return unknown('timeout'); }
        if (completed || controller.signal.aborted) { cancel(); return unknown('cancelled'); }
        if (response.status !== 200) return unknown('upstream_rejected');
        if (response.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json' || !reader) {
          return unknown('invalid_response');
        }
        const chunks: Uint8Array[] = []; let length = 0;
        while (true) {
          const chunk = await reader.read();
          if (expired()) { cancel(); return unknown('timeout'); }
          if (completed || controller.signal.aborted) return unknown('cancelled');
          if (chunk.done) break;
          length += chunk.value.byteLength;
          if (length > 65_536) return unknown('invalid_response');
          chunks.push(chunk.value);
        }
        const bytes = new Uint8Array(length); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        let data: unknown;
        try { data = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
        catch { return unknown('invalid_response'); }
        if (!data || typeof data !== 'object' || Array.isArray(data)) return unknown('invalid_response');
        const value = data as Record<string, unknown>;
        if (value.token_type !== 'bearer' || !boundedToken(value.access_token) || !boundedToken(value.refresh_token)) return unknown('invalid_response');
        if (expired()) { cancel(); return unknown('timeout'); }
        return Object.freeze({ kind: 'tokens', accessToken: value.access_token, refreshToken: value.refresh_token });
      } catch { return unknown('transport'); }
      finally { if (completed) releaseReader(); }
    })();
    try {
      const result = await Promise.race([stop, request]);
      if (result.kind === 'tokens' && signal?.aborted) return unknown('cancelled');
      if (result.kind !== 'tokens') cancel();
      return result;
    } finally {
      completed = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      releaseReader();
    }
  }

  return Object.freeze({
    authorizationUrl(verifier: unknown) {
      if (!trusted) return notSent('configuration');
      if (!validVerifier(verifier)) return notSent('invalid_input');
      const url = new URL(`${trusted.origin}/auth/v1/authorize`);
      url.search = new URLSearchParams({ provider: 'google', redirect_to: trusted.callback,
        code_challenge: derivePkceChallenge(verifier), code_challenge_method: 's256' }).toString();
      return Object.freeze({ kind: 'ready' as const, url: url.href });
    },
    exchange(input: unknown, signal?: AbortSignal) {
      const value = snapshot(input, ['authorizationCode', 'codeVerifier']);
      if (!value || !boundedToken(value.authorizationCode, 2048) || !validVerifier(value.codeVerifier)) return Promise.resolve(notSent('invalid_input'));
      return send('pkce', { auth_code: value.authorizationCode, code_verifier: value.codeVerifier }, signal);
    },
    refresh(input: unknown, signal?: AbortSignal) {
      const value = snapshot(input, ['refreshToken']);
      if (!value || !boundedToken(value.refreshToken)) return Promise.resolve(notSent('invalid_input'));
      return send('refresh_token', { refresh_token: value.refreshToken }, signal);
    },
  });
}
