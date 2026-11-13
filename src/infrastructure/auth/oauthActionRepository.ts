import { z } from 'zod';

const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const tokenVersion = integer.max(Number.MAX_SAFE_INTEGER - 1);
const priorGeneration = integer.max(Number.MAX_SAFE_INTEGER - 3);
const committedGeneration = integer.min(1).max(Number.MAX_SAFE_INTEGER - 2);
const instant = integer.max(253402300799999);
const cookieFingerprint = z.string().regex(/^(absent|present:[0-9a-f]{64})$/);
const pkceEnvelope = z.string().max(2048).regex(/^pkce-v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{58}\.[A-Za-z0-9_-]{22}$/);
const tokenEnvelope = z.string().max(49152).regex(/^v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$/);
const orphanEnvelope = z.string().max(49152).regex(/^orphan-v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$/);
const environment = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/);

const issueInput = z.strictObject({
  issuanceId: uuid, requestFingerprint: hash, browserId: uuid, browserHash: hash, proofId: uuid, proofHash: hash,
  purpose: z.enum(['login', 'logout', 'mutation']), cookieFingerprint, presentedSessionHash: hash.nullable(),
  operationId: uuid.nullable(), expectedTokenVersion: tokenVersion.nullable(),
  expectedControlVersion: integer.nullable(), expectedDatasetEpoch: uuid.nullable(),
}).refine(input => {
  if (input.cookieFingerprint === 'absent' && input.presentedSessionHash !== null) return false;
  if (input.purpose !== 'mutation') return input.operationId !== null;
  return input.operationId === null && input.presentedSessionHash !== null && input.expectedTokenVersion !== null
    && input.expectedControlVersion !== null && input.expectedDatasetEpoch !== null;
});
const beginInput = z.strictObject({
  browserHash: hash, proofHash: hash, operationId: uuid, cookieFingerprint,
  attemptId: uuid, flowHash: hash, pkceEnvelope, requestFingerprint: hash,
});
const callbackInput = z.strictObject({ browserHash: hash, flowHash: hash, attemptId: uuid, claimId: uuid });
const claimInput = callbackInput.extend({ browserId: uuid });
const resolveInput = callbackInput.extend({
  commitOperationId: uuid, requestFingerprint: hash, newSessionId: uuid, generation: priorGeneration,
});
const commitInput = resolveInput.extend({
  candidateId: uuid, verifiedSubject: uuid, verifiedUpstreamSessionId: uuid,
  newSessionHash: hash, tokenEnvelope, accessExpiresAt: instant,
});
const closeInput = callbackInput.extend({
  claimId: uuid.nullable(), closeOperationId: uuid, requestFingerprint: hash, candidateId: uuid.nullable(),
  verifiedSubject: uuid.nullable(), verifiedUpstreamSessionId: uuid.nullable(), tokenEnvelope: orphanEnvelope.nullable(),
  cleanupEnvironment: environment.nullable(),
}).refine(input => {
  const candidate = [input.candidateId, input.verifiedSubject, input.verifiedUpstreamSessionId, input.cleanupEnvironment];
  return input.tokenEnvelope === null ? candidate.every(value => value === null)
    : input.claimId !== null && candidate.every(value => value !== null);
});
const ackInput = z.strictObject({ sessionHash: hash, browserHash: hash, tokenVersion });
const retireInput = z.strictObject({ browserHash: hash, attemptId: uuid, sessionId: uuid, generation: committedGeneration });
const logoutInput = z.strictObject({ browserHash: hash, proofHash: hash, operationId: uuid, cookieFingerprint });

const browserLookup = z.strictObject({ browserHash: hash });
const actionLookup = browserLookup.extend({ proofHash: hash, purpose: z.enum(['login', 'logout']), cookieFingerprint });
const callbackLookup = browserLookup.extend({ flowHash: hash, presentedSessionHash: hash.nullable() });
const generation = integer.max(Number.MAX_SAFE_INTEGER - 1);

const browserLookupResult = z.union([
  z.strictObject({ kind: z.literal('active'), browserId: uuid, generation }),
  z.strictObject({ kind: z.literal('absent_or_expired') }),
]);
const actionLookupResult = z.union([
  z.strictObject({ kind: z.literal('resolved'), browserId: uuid, operationId: uuid, generation }),
  z.strictObject({ kind: z.literal('denied') }),
]);
const callbackLookupResult = z.union([
  z.strictObject({ kind: z.literal('pending'), attemptId: uuid, browserId: uuid }),
  z.strictObject({ kind: z.literal('completed_with_cookie'), attemptId: uuid, sessionId: uuid, generation: committedGeneration }),
  z.strictObject({ kind: z.enum(['in_progress', 'restart_required', 'denied']) }),
]);

const denied = z.strictObject({ kind: z.literal('denied') });
const deniedOrRestart = z.strictObject({ kind: z.enum(['denied', 'restart_required']) });
const issueResult = z.union([
  z.strictObject({ kind: z.literal('issued'), proofId: uuid, browserId: uuid, generation: priorGeneration, expiresAt: instant }),
  denied,
]);
const beginResult = z.union([
  z.strictObject({ kind: z.literal('begun'), attemptId: uuid, generation: priorGeneration, expiresAt: instant }),
  deniedOrRestart,
]);
const claimResult = z.union([
  z.strictObject({
    kind: z.literal('claimed'), now: instant, attemptId: uuid, claimId: uuid, browserId: uuid, pkceEnvelope,
    ownerId: uuid, authSubject: uuid, controlVersion: integer, datasetEpoch: uuid, generation: priorGeneration,
  }),
  deniedOrRestart,
]);
const markResult = z.strictObject({ kind: z.enum(['send_intent', 'denied', 'restart_required']) });
const committed = z.strictObject({ kind: z.literal('committed'), attemptId: uuid, sessionId: uuid, generation: committedGeneration });
const commitResult = z.union([committed, denied]);
const resolveResult = z.union([committed, denied, z.strictObject({ kind: z.literal('unresolved') })]);
const closeResult = z.strictObject({ kind: z.enum(['closed', 'denied']) });
const ackResult = z.strictObject({ kind: z.enum(['acknowledged', 'denied']) });
const retireResult = z.strictObject({ kind: z.enum(['retired', 'already_retired', 'denied']) });
const logoutResult = z.union([
  z.strictObject({ kind: z.literal('logged_out'), outcome: z.enum(['revoked', 'absent']), clearCookie: z.literal(true) }),
  denied,
]);

type FaultReason = 'configuration' | 'cancelled' | 'timeout' | 'transport' | 'upstream_rejected' | 'invalid_response';
export type OAuthActionFault = { readonly kind: 'unavailable'; readonly reason: FaultReason }
  | { readonly kind: 'outcome_unknown'; readonly reason: Exclude<FaultReason, 'configuration'> };
type InvalidInput = { readonly kind: 'invalid_input' };
type Result<T extends z.ZodType> = Promise<Readonly<z.infer<T>> | OAuthActionFault | InvalidInput>;

export interface OAuthActionRepository {
  resolveBrowser(input: z.input<typeof browserLookup>, signal?: AbortSignal): Result<typeof browserLookupResult>;
  resolveAction(input: z.input<typeof actionLookup>, signal?: AbortSignal): Result<typeof actionLookupResult>;
  inspectCallback(input: z.input<typeof callbackLookup>, signal?: AbortSignal): Result<typeof callbackLookupResult>;
  issueProof(input: z.input<typeof issueInput>, signal?: AbortSignal): Result<typeof issueResult>;
  beginLogin(input: z.input<typeof beginInput>, signal?: AbortSignal): Result<typeof beginResult>;
  callbackClaim(input: z.input<typeof claimInput>, signal?: AbortSignal): Result<typeof claimResult>;
  callbackMarkSent(input: z.input<typeof callbackInput>, signal?: AbortSignal): Result<typeof markResult>;
  callbackCommit(input: z.input<typeof commitInput>, signal?: AbortSignal): Result<typeof commitResult>;
  callbackResolve(input: z.input<typeof resolveInput>, signal?: AbortSignal): Result<typeof resolveResult>;
  callbackClose(input: z.input<typeof closeInput>, signal?: AbortSignal): Result<typeof closeResult>;
  deliveryAck(input: z.input<typeof ackInput>, signal?: AbortSignal): Result<typeof ackResult>;
  deliveryRetire(input: z.input<typeof retireInput>, signal?: AbortSignal): Result<typeof retireResult>;
  logout(input: z.input<typeof logoutInput>, signal?: AbortSignal): Result<typeof logoutResult>;
}

type Rpc = 'issue_proof' | 'begin_login' | 'callback_claim' | 'callback_mark_sent' | 'callback_commit' | 'callback_resolve'
  | 'callback_close' | 'delivery_ack' | 'delivery_retire' | 'logout'
  | 'browser_resolve' | 'action_resolve' | 'callback_inspect';

const readOnlyRpcs: ReadonlySet<Rpc> = new Set(['browser_resolve', 'action_resolve', 'callback_inspect', 'callback_resolve']);

function readFields(value: unknown, names: readonly string[]): Record<string, unknown> | null {
  try {
    if (value === null || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== names.length) return null;
    const fields: Record<string, unknown> = Object.create(null);
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !('value' in descriptor)) return null;
      fields[name] = descriptor.value;
    }
    return fields;
  } catch { return null; }
}

function callbackArguments(input: Omit<z.infer<typeof callbackInput>, 'claimId'> & { claimId: string | null }) {
  return { p_browser_hash: input.browserHash, p_flow_hash: input.flowHash, p_attempt_id: input.attemptId, p_claim_id: input.claimId };
}

function commitIdentity(input: z.infer<typeof resolveInput>) {
  return { ...callbackArguments(input), p_commit_operation_id: input.commitOperationId, p_request_fingerprint: input.requestFingerprint };
}

function matchesCommit(reply: z.infer<typeof resolveResult>, input: z.infer<typeof resolveInput>): boolean {
  return reply.kind !== 'committed' || (reply.attemptId === input.attemptId
    && reply.sessionId === input.newSessionId && reply.generation === input.generation + 1);
}

/** Application code obtains this fixed RPC capability through the server-only gateway. */
export function createOAuthActionRepository(configuration: unknown, fetcher: typeof fetch = fetch,
  monotonicClock: () => number = () => performance.now()): OAuthActionRepository {
  const config = readFields(configuration, ['supabaseOrigin', 'secretKey']);
  const origin = config?.supabaseOrigin;
  const key = config?.secretKey;
  const trusted = typeof origin === 'string' && /^https:\/\/[a-z0-9]{20}\.supabase\.co$/.test(origin)
    && typeof key === 'string' && /^sb_secret_[A-Za-z0-9_-]{16,256}$/.test(key) ? { origin, key } : null;

  async function post<T>(rpc: Rpc, args: object, decode: (value: unknown) => T | null,
    signal?: AbortSignal): Promise<T | OAuthActionFault> {
    let attempted = false;
    const fault = (reason: FaultReason): OAuthActionFault =>
      attempted && !readOnlyRpcs.has(rpc) && reason !== 'configuration'
        ? Object.freeze({ kind: 'outcome_unknown', reason })
        : Object.freeze({ kind: 'unavailable', reason });

    if (!trusted) return fault('configuration');
    if (signal?.aborted) return fault('cancelled');
    let started: number;
    try { started = monotonicClock(); } catch { return fault('configuration'); }
    if (signal?.aborted) return fault('cancelled');
    if (!Number.isFinite(started) || started < 0) return fault('configuration');

    const duration = 2000;
    const controller = new AbortController();
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let cancelledReader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let finished = false;
    const cancel = () => {
      controller.abort();
      if (reader && reader !== cancelledReader) {
        cancelledReader = reader;
        try { void reader.cancel().catch(() => {}); } catch { /* Cancellation cannot hold the deadline. */ }
      }
    };
    const release = () => {
      try { reader?.releaseLock(); } catch { /* A pending read may still hold the lock. */ }
    };
    const expired = () => {
      const now = monotonicClock();
      return !Number.isFinite(now) || now < started || now - started >= duration;
    };

    const { promise: stop, resolve: stopWith } = Promise.withResolvers<OAuthActionFault>();
    const abort = () => { stopWith(fault('cancelled')); cancel(); };
    signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => { stopWith(fault('timeout')); cancel(); }, duration);
    const request = (async () => {
      try {
        const body = JSON.stringify(args);
        if (expired()) return fault('timeout');
        if (controller.signal.aborted) return fault('cancelled');
        attempted = true;
        const response = await fetcher(`${trusted.origin}/rest/v1/rpc/jls_auth_${rpc}_v1`, {
          method: 'POST', headers: { apikey: trusted.key, 'Content-Type': 'application/json', Accept: 'application/json' },
          body, credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal,
        });
        reader = response.body?.getReader();
        if (finished || controller.signal.aborted) { cancel(); return fault('cancelled'); }
        if (expired()) return fault('timeout');
        if (response.status !== 200) return fault('upstream_rejected');
        if (!reader || response.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
          return fault('invalid_response');
        }

        const bytes = new Uint8Array(8192);
        let length = 0;
        while (true) {
          const chunk = await reader.read();
          if (finished || controller.signal.aborted) return fault('cancelled');
          if (expired()) return fault('timeout');
          if (chunk.done) break;
          if (length + chunk.value.byteLength > bytes.length) return fault('invalid_response');
          bytes.set(chunk.value, length);
          length += chunk.value.byteLength;
        }

        let result: T | null;
        try {
          const json = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length));
          result = decode(JSON.parse(json));
        } catch { return fault('invalid_response'); }
        if (expired()) return fault('timeout');
        return result ?? fault('invalid_response');
      } catch { return fault('transport'); }
      finally { if (finished) release(); }
    })();

    try {
      const result = await Promise.race([stop, request]);
      if (signal?.aborted) return fault('cancelled');
      if (result && typeof result === 'object' && 'reason' in result) cancel();
      return result;
    } finally {
      finished = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      release();
    }
  }

  async function call<I, O>(rpc: Rpc, value: unknown, input: z.ZodType<I> & { shape: object },
    output: z.ZodType<O>, args: (data: I) => object, signal?: AbortSignal,
    matches?: (result: O, data: I) => boolean): Promise<Readonly<O> | OAuthActionFault | InvalidInput> {
    const prepared = input.safeParse(readFields(value, Object.keys(input.shape)));
    if (!prepared.success) return Object.freeze({ kind: 'invalid_input' });
    return post(rpc, args(prepared.data), response => {
      const decoded = output.safeParse(response);
      return decoded.success && (!matches || matches(decoded.data, prepared.data)) ? Object.freeze(decoded.data) : null;
    }, signal);
  }

  const repository: OAuthActionRepository = {
    resolveBrowser: (input, signal) => call('browser_resolve', input, browserLookup, browserLookupResult,
      data => ({ p_browser_hash: data.browserHash }), signal),
    resolveAction: (input, signal) => call('action_resolve', input, actionLookup, actionLookupResult, data => ({
      p_browser_hash: data.browserHash, p_proof_hash: data.proofHash, p_purpose: data.purpose,
      p_cookie_fingerprint: data.cookieFingerprint,
    }), signal),
    inspectCallback: (input, signal) => call('callback_inspect', input, callbackLookup, callbackLookupResult, data => ({
      p_browser_hash: data.browserHash, p_flow_hash: data.flowHash, p_presented_session_hash: data.presentedSessionHash,
    }), signal, (reply, data) => reply.kind !== 'completed_with_cookie' || data.presentedSessionHash !== null),
    issueProof: (input, signal) => call('issue_proof', input, issueInput, issueResult, data => ({
      p_issuance_id: data.issuanceId, p_request_fingerprint: data.requestFingerprint,
      p_browser_id: data.browserId, p_browser_hash: data.browserHash, p_proof_id: data.proofId, p_proof_hash: data.proofHash,
      p_purpose: data.purpose, p_cookie_fingerprint: data.cookieFingerprint, p_presented_session_hash: data.presentedSessionHash,
      p_operation_id: data.operationId, p_expected_token_version: data.expectedTokenVersion,
      p_expected_control_version: data.expectedControlVersion, p_expected_dataset_epoch: data.expectedDatasetEpoch,
    }), signal, (reply, data) => reply.kind === 'denied' || (reply.proofId === data.proofId && reply.browserId === data.browserId)),
    beginLogin: (input, signal) => call('begin_login', input, beginInput, beginResult, data => ({
      p_browser_hash: data.browserHash, p_proof_hash: data.proofHash, p_operation_id: data.operationId,
      p_cookie_fingerprint: data.cookieFingerprint, p_attempt_id: data.attemptId, p_flow_hash: data.flowHash,
      p_pkce_envelope: data.pkceEnvelope, p_request_fingerprint: data.requestFingerprint,
    }), signal, (reply, data) => reply.kind !== 'begun' || reply.attemptId === data.attemptId),
    callbackClaim: (input, signal) => call('callback_claim', input, claimInput, claimResult, callbackArguments, signal,
      (reply, data) => reply.kind !== 'claimed' || (reply.attemptId === data.attemptId && reply.claimId === data.claimId
        && reply.browserId === data.browserId)),
    callbackMarkSent: (input, signal) => call('callback_mark_sent', input, callbackInput, markResult, callbackArguments, signal),
    callbackCommit: (input, signal) => call('callback_commit', input, commitInput, commitResult, data => ({
      ...commitIdentity(data), p_candidate_id: data.candidateId, p_verified_subject: data.verifiedSubject,
      p_verified_upstream_session_id: data.verifiedUpstreamSessionId, p_new_session_id: data.newSessionId,
      p_new_session_hash: data.newSessionHash, p_token_envelope: data.tokenEnvelope,
      p_access_expires_at: new Date(data.accessExpiresAt).toISOString(),
    }), signal, matchesCommit),
    callbackResolve: (input, signal) => call('callback_resolve', input, resolveInput, resolveResult, commitIdentity, signal, matchesCommit),
    callbackClose: (input, signal) => call('callback_close', input, closeInput, closeResult, data => ({
      ...callbackArguments(data), p_close_operation_id: data.closeOperationId, p_request_fingerprint: data.requestFingerprint,
      p_candidate_id: data.candidateId, p_verified_subject: data.verifiedSubject, p_verified_upstream_session_id: data.verifiedUpstreamSessionId,
      p_token_envelope: data.tokenEnvelope, p_cleanup_environment: data.cleanupEnvironment,
    }), signal),
    deliveryAck: (input, signal) => call('delivery_ack', input, ackInput, ackResult, data => ({
      p_browser_secret_hash: data.browserHash, p_session_secret_hash: data.sessionHash, p_expected_token_version: data.tokenVersion,
    }), signal),
    deliveryRetire: (input, signal) => call('delivery_retire', input, retireInput, retireResult, data => ({
      p_browser_secret_hash: data.browserHash, p_attempt_id: data.attemptId, p_session_id: data.sessionId, p_generation: data.generation,
    }), signal),
    logout: (input, signal) => call('logout', input, logoutInput, logoutResult, data => ({
      p_browser_secret_hash: data.browserHash, p_proof_hash: data.proofHash, p_operation_id: data.operationId,
      p_cookie_fingerprint: data.cookieFingerprint,
    }), signal),
  };
  return Object.freeze(repository);
}
