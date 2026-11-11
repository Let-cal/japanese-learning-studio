export interface AuthIdentityConfiguration {
  readonly supabaseOrigin: unknown;
  readonly publishableKey: unknown;
}

/** Expected identity and time must be copied from a fresh, same-request trusted DB snapshot. */
export interface AuthIdentityInput {
  readonly accessToken: unknown;
  readonly expectedAuthSubject: unknown;
  readonly expectedUpstreamSessionId: unknown;
  readonly trustedNow: unknown;
}

export type AuthIdentityResult =
  | { readonly kind: 'verified'; readonly authSubject: string; readonly upstreamSessionId: string; readonly expiresAt: number }
  | { readonly kind: 'rejected'; readonly reason: 'invalid_token' | 'identity_mismatch' | 'anonymous' }
  | { readonly kind: 'unavailable'; readonly reason: 'configuration' | 'invalid_facts' | 'timeout' | 'cancelled' | 'transport' | 'upstream_rejected' | 'invalid_response' };

export interface AuthIdentityVerifier {
  verify(input: unknown, signal?: AbortSignal): Promise<AuthIdentityResult>;
}

export interface AuthCandidateInput {
  readonly accessToken: unknown;
  readonly trustedNow: unknown;
}

type IdentityFields = Omit<Extract<AuthIdentityResult, { kind: 'verified' }>, 'kind'>;
type AuthVerificationFailure = Exclude<AuthIdentityResult, { kind: 'verified' }>;
export type AuthCandidateResult = ({ readonly kind: 'verified_candidate' } & IdentityFields) | AuthVerificationFailure;
export interface AuthCandidateVerifier {
  verifyCandidate(input: unknown, signal?: AbortSignal): Promise<AuthCandidateResult>;
}

type InternalResult = ({ readonly kind: 'identity' } & IdentityFields) | AuthVerificationFailure;
type UnavailableReason = Extract<AuthIdentityResult, { kind: 'unavailable' }>['reason'];
type RejectedReason = Extract<AuthIdentityResult, { kind: 'rejected' }>['reason'];
const unavailable = (reason: UnavailableReason): AuthVerificationFailure => Object.freeze({ kind: 'unavailable', reason });
const rejected = (reason: RejectedReason): AuthVerificationFailure => Object.freeze({ kind: 'rejected', reason });

function record(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

// No caller accessors, inherited data, symbols or unexpected own properties.
function snapshot(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (!record(value) || Reflect.ownKeys(value).length !== keys.length) return null;
  const result: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor)) return null;
    result[key] = descriptor.value;
  }
  return result;
}

function uuid(value: unknown): string | null {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
    ? value.toLowerCase() : null;
}

function timestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function numericDate(value: unknown): number | null {
  return timestamp(value) && Number.isSafeInteger(value * 1000) ? value * 1000 : null;
}

/** Structural decoding only. No decoded claim supplies identity before a positive Auth response. */
function payload(token: unknown): Record<string, unknown> | null {
  if (typeof token !== 'string' || token.length > 8192 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) return null;
  const parts = token.split('.');
  const bytes = parts.map(part => Buffer.from(part, 'base64url'));
  if (bytes.some((part, index) => part.toString('base64url') !== parts[index])) return null;
  const decoded: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes[1]));
  return record(decoded) ? decoded : null;
}

/**
 * Server-side identity primitive; application code imports authIdentityGateway.
 * Auth checks the EXACT bearer token's integrity over the network. This decoder
 * does not verify a JWT signature or establish owner/app-session authorization.
 * Request elapsed time is accounted for; stale caller-supplied DB facts are not repaired.
 */
export function createAuthIdentityVerifier(
  configuration: AuthIdentityConfiguration,
  fetcher: typeof fetch = fetch,
  monotonicClock: () => number = () => performance.now(),
): AuthIdentityVerifier {
  const verifyIdentity = createVerifier('continuation', configuration, fetcher, monotonicClock);
  return Object.freeze({ async verify(input: unknown, signal?: AbortSignal): Promise<AuthIdentityResult> {
    const result = await verifyIdentity(input, signal);
    if (result.kind !== 'identity') return result;
    if (signal?.aborted) return unavailable('cancelled');
    return Object.freeze({ kind: 'verified', authSubject: result.authSubject,
      upstreamSessionId: result.upstreamSessionId, expiresAt: result.expiresAt });
  } });
}

/**
 * Initial callback candidate only: no existing DB session is assumed. Before app
 * activation, the caller MUST compare this subject to the operator-approved owner
 * and generation under DB CAS. A nonowner candidate never grants app access.
 */
export function createAuthCandidateVerifier(
  configuration: AuthIdentityConfiguration,
  fetcher: typeof fetch = fetch,
  monotonicClock: () => number = () => performance.now(),
): AuthCandidateVerifier {
  const verifyIdentity = createVerifier('candidate', configuration, fetcher, monotonicClock);
  return Object.freeze({ async verifyCandidate(input: unknown, signal?: AbortSignal): Promise<AuthCandidateResult> {
    const result = await verifyIdentity(input, signal);
    if (result.kind !== 'identity') return result;
    if (signal?.aborted) return unavailable('cancelled');
    return Object.freeze({ kind: 'verified_candidate', authSubject: result.authSubject,
      upstreamSessionId: result.upstreamSessionId, expiresAt: result.expiresAt });
  } });
}

// The stage is selected only by the server factory above, never a request field.
function createVerifier(
  stage: 'continuation' | 'candidate',
  configuration: AuthIdentityConfiguration,
  fetcher: typeof fetch,
  monotonicClock: () => number,
): (input: unknown, signal?: AbortSignal) => Promise<InternalResult> {
  let trusted: { origin: string; key: string } | null = null;
  try {
    const config = snapshot(configuration, ['supabaseOrigin', 'publishableKey']);
    if (config && typeof config.supabaseOrigin === 'string' && /^https:\/\/[a-z0-9]{20}\.supabase\.co$/.test(config.supabaseOrigin)
      && typeof config.publishableKey === 'string' && /^sb_publishable_[A-Za-z0-9_-]{16,256}$/.test(config.publishableKey)) {
      trusted = { origin: config.supabaseOrigin, key: config.publishableKey };
    }
  } catch { /* Closed, sanitized capability on invalid configuration. */ }

  return async (input: unknown, signal?: AbortSignal): Promise<InternalResult> => {
    if (signal?.aborted) return unavailable('cancelled');
    if (!trusted) return unavailable('configuration');
    const { origin, key } = trusted;
    let accessToken: string;
    let claims: Record<string, unknown>;
    let expectedSubject: string | null = null;
    let expectedSession: string | null = null;
    let trustedNow: number;
    let started: number;
    try {
      const facts = snapshot(input, stage === 'continuation'
        ? ['accessToken', 'expectedAuthSubject', 'expectedUpstreamSessionId', 'trustedNow']
        : ['accessToken', 'trustedNow']);
      if (!facts || !timestamp(facts.trustedNow)) return unavailable('invalid_facts');
      if (stage === 'continuation') {
        expectedSubject = uuid(facts.expectedAuthSubject);
        expectedSession = uuid(facts.expectedUpstreamSessionId);
        if (!expectedSubject || !expectedSession) return unavailable('invalid_facts');
      }
      trustedNow = facts.trustedNow;
      let decoded: Record<string, unknown> | null;
      try { decoded = payload(facts.accessToken); } catch { return rejected('invalid_token'); }
      if (!decoded || typeof facts.accessToken !== 'string') return rejected('invalid_token');
      accessToken = facts.accessToken;
      claims = decoded;
      started = monotonicClock();
      if (!Number.isFinite(started) || started < 0) return unavailable('invalid_facts');
    } catch { return unavailable('invalid_facts'); }

    const controller = new AbortController();
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let cancelledReader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let completed = false;
    const cancel = () => {
      controller.abort();
      if (reader && reader !== cancelledReader) {
        cancelledReader = reader;
        // Broken cancellation must never extend the deadline.
        try { void reader.cancel().catch(() => {}); } catch { /* Best effort. */ }
      }
    };
    const releaseReader = () => {
      try {
        reader?.releaseLock();
        reader = undefined;
      } catch { /* The pending read owns the lock until it settles. */ }
    };
    const { promise: interruption, resolve } = Promise.withResolvers<InternalResult>();
    const onAbort = () => { resolve(unavailable('cancelled')); cancel(); };
    if (signal?.aborted) return unavailable('cancelled');
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => { resolve(unavailable('timeout')); cancel(); }, 5000);
    const request = (async (): Promise<InternalResult> => {
      try {
        const response = await fetcher(`${origin}/auth/v1/user`, {
          method: 'GET', headers: { apikey: key, Authorization: `Bearer ${accessToken}`, Accept: 'application/json',
            'X-Supabase-Api-Version': '2024-01-01' },
          cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal,
        });
        reader = response.body?.getReader();
        if (completed || controller.signal.aborted) {
          cancel();
          return unavailable(signal?.aborted ? 'cancelled' : 'timeout');
        }
        if (response.status !== 200 && response.status !== 401) return unavailable('upstream_rejected');
        const mediaType = response.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase();
        if (mediaType !== 'application/json' || !reader) return unavailable('invalid_response');
        const chunks: Uint8Array[] = [];
        let length = 0;
        while (true) {
          const chunk = await reader.read();
          if (completed || controller.signal.aborted) return unavailable(signal?.aborted ? 'cancelled' : 'timeout');
          if (chunk.done) break;
          length += chunk.value.byteLength;
          if (length > 64 * 1024) return unavailable('invalid_response');
          chunks.push(chunk.value);
        }
        const bytes = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        let user: unknown;
        try { user = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
        catch { return unavailable('invalid_response'); }
        if (!record(user)) return unavailable('invalid_response');
        if (response.status === 401) return user.code === 'bad_jwt' ? rejected('invalid_token') : unavailable('upstream_rejected');
        const responseSubject = uuid(user.id);
        if (!responseSubject || typeof user.is_anonymous !== 'boolean') return unavailable('invalid_response');
        if (user.is_anonymous) return rejected('anonymous');

        // Only the raw HTTP 200 user response above establishes Auth verification.
        const authSubject = uuid(claims.sub);
        const upstreamSessionId = uuid(claims.session_id);
        if (!authSubject || !upstreamSessionId) return rejected('invalid_token');
        if (authSubject !== responseSubject || (stage === 'continuation'
          && (authSubject !== expectedSubject || upstreamSessionId !== expectedSession))) {
          return rejected('identity_mismatch');
        }
        if (claims.is_anonymous === true) return rejected('anonymous');
        const expiresAt = numericDate(claims.exp);
        const notBefore = Object.hasOwn(claims, 'nbf') ? numericDate(claims.nbf) : 0;
        let finished: number;
        try { finished = monotonicClock(); } catch { return unavailable('invalid_facts'); }
        const elapsed = finished - started;
        // Expiry rounds forward conservatively; nbf must never become valid early.
        const effectiveNow = trustedNow + Math.ceil(elapsed);
        const notBeforeNow = trustedNow + Math.floor(elapsed);
        if (!Number.isFinite(finished) || elapsed < 0 || !timestamp(effectiveNow) || !timestamp(notBeforeNow)) return unavailable('invalid_facts');
        if (elapsed >= 5000) return unavailable('timeout');
        if (claims.iss !== `${origin}/auth/v1` || claims.aud !== 'authenticated' || claims.role !== 'authenticated'
          || claims.is_anonymous !== false || expiresAt === null || expiresAt === 0 || expiresAt <= effectiveNow
          || notBefore === null || notBefore > notBeforeNow) return rejected('invalid_token');
        return Object.freeze({ kind: 'identity', authSubject, upstreamSessionId, expiresAt });
      } catch { return unavailable('transport'); }
      finally {
        // A response that arrives after the race still owns its reader.
        if (completed) releaseReader();
      }
    })();
    try {
      const result = await Promise.race([interruption, request]);
      if (signal?.aborted) return unavailable('cancelled');
      if (result.kind !== 'identity') cancel();
      return result;
    } finally {
      completed = true;
      signal?.removeEventListener('abort', onAbort);
      clearTimeout(timer);
      releaseReader();
    }
  };
}
