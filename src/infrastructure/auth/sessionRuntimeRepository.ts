import { z } from 'zod';
import { hashSessionSecret } from './sessionSecrets';
import { hashAuthActionSecret } from './authActionSecrets';

const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const version = integer.max(Number.MAX_SAFE_INTEGER - 1);
const instant = integer.nullable();
const denied = z.strictObject({ kind: z.literal('denied') });
const absent = z.strictObject({ kind: z.literal('absent'), now: integer });
const session = z.strictObject({ sessionId: uuid, ownerId: uuid, authSubject: uuid, upstreamSessionId: uuid,
  createdAt: integer, lastActivityAt: integer, reauthenticatedAt: instant, revokedAt: instant,
  deliveryState: z.enum(['unacknowledged','acknowledged']), deliveryAcknowledgedAt: instant });
const snapshotSchema = z.strictObject({ kind: z.literal('snapshot'), now: integer, session,
  owner: z.strictObject({ ownerId: uuid, authSubject: uuid, active: z.boolean(), controlVersion: integer, datasetEpoch: uuid.nullable() }),
  browser: z.strictObject({ browserId: uuid, generation: version, sessionGeneration: version,
    currentSessionId: uuid.nullable(), expiresAt: integer }),
  credential: z.strictObject({ tokenVersion: version, state: z.enum(['usable','prepared','sent_or_unknown','uncertain','reauthentication_required','revoked']),
    accessExpiresAt: integer, refreshAttemptId: uuid.nullable(), refreshLeaseExpiresAt: instant, refreshTransmissionIntentAt: instant }),
}).superRefine((value, context) => {
  const s = value.session; const c = value.credential;
  const validTime = (time: number | null) => time === null || (time >= s.createdAt && time <= value.now);
  if (s.createdAt > s.lastActivityAt || s.lastActivityAt > value.now || !validTime(s.reauthenticatedAt)
    || !validTime(s.revokedAt) || !validTime(s.deliveryAcknowledgedAt)
    || (s.deliveryState === 'acknowledged') !== (s.deliveryAcknowledgedAt !== null)
    || (c.state === 'usable' && (c.refreshAttemptId !== null || c.refreshLeaseExpiresAt !== null || c.refreshTransmissionIntentAt !== null))
    || (c.state === 'prepared' && (c.refreshAttemptId === null || c.refreshLeaseExpiresAt === null || c.refreshTransmissionIntentAt !== null))
    || (c.state === 'sent_or_unknown' && (c.refreshAttemptId === null || c.refreshLeaseExpiresAt === null || c.refreshTransmissionIntentAt === null))) {
    context.addIssue({ code: 'custom', message: 'Invalid control metadata' });
  }
});
const credentialSchema = z.strictObject({ kind: z.literal('credentials'), now: integer, sessionId: uuid, ownerId: uuid,
  authSubject: uuid, upstreamSessionId: uuid, datasetEpoch: uuid, controlVersion: integer, browserGeneration: version,
  tokenVersion: version, tokenEnvelope: z.string().max(49152).regex(/^v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$/),
  accessExpiresAt: integer }).refine(value => value.accessExpiresAt > value.now);
const confirmationSchema = z.strictObject({ kind: z.literal('confirmed'),
  context: z.strictObject({ sessionId: uuid, ownerId: uuid, authSubject: uuid, datasetEpoch: uuid }),
  tokenVersion: version, controlVersion: integer, browserGeneration: version });
const cookies = z.strictObject({ sessionSecret: z.unknown(), browserSecret: z.unknown() });
const facts = z.strictObject({ ...cookies.shape, tokenVersion: version, controlVersion: integer, datasetEpoch: uuid,
  sessionId: uuid, ownerId: uuid, authSubject: uuid, upstreamSessionId: uuid, browserGeneration: version });
const confirmationInput = facts.extend({ verifiedAuthSubject: uuid, verifiedUpstreamSessionId: uuid });

const fingerprint = z.string().regex(/^[0-9a-f]{64}$/);
const envelope = credentialSchema.shape.tokenEnvelope;
const refreshInput = facts.extend({ browserId: uuid, attemptId: uuid, requestFingerprint: fingerprint });
const finishInput = refreshInput.extend({
  finishOperationId: uuid, finishFingerprint: fingerprint, verifiedAuthSubject: uuid,
  verifiedUpstreamSessionId: uuid, tokenEnvelope: envelope, accessExpiresAt: integer.max(253402300799999),
});
const closeInput = refreshInput.extend({
  closeOperationId: uuid, closeFingerprint: fingerprint, disposition: z.enum(['pre_send', 'unknown']),
});
const latePairInput = closeInput.extend({
  disposition: z.literal('late_pair'), verifiedAuthSubject: uuid, verifiedUpstreamSessionId: uuid, tokenEnvelope: envelope,
});
const claimResult = z.union([
  denied,
  z.strictObject({ kind: z.enum(['busy', 'reauthentication_required']) }),
  z.strictObject({ kind: z.literal('claimed'), attemptId: uuid, tokenEnvelope: envelope, leaseExpiresAt: integer }),
]);
const sendResult = z.strictObject({ kind: z.enum(['transmit', 'already_sent', 'denied']) });
const committed = z.strictObject({ kind: z.literal('committed'), attemptId: uuid, sessionId: uuid, tokenVersion: version });
const finishResult = z.union([committed, denied]);
const resolveResult = z.union([finishResult, z.strictObject({ kind: z.literal('not_committed') })]);
const closeResult = z.strictObject({ kind: z.enum(['released', 'closed', 'late_pair_retained', 'denied']) });
const closeSuccess = { pre_send: 'released', unknown: 'closed', late_pair: 'late_pair_retained' } as const;

const cleanupClaimInput = z.strictObject({ sessionId: uuid, claimId: uuid });
const cleanupCompletionInput = cleanupClaimInput.extend({
  revision: version, outcome: z.enum(['completed', 'timeout', 'transport', 'rejected']),
});
const cleanupClaimResult = z.union([
  z.strictObject({ kind: z.enum(['denied', 'failed', 'credential_unavailable']) }),
  z.strictObject({ kind: z.literal('cleanup'), sessionId: uuid, claimId: uuid, revision: version,
    scope: z.literal('local'), ownerId: uuid, authSubject: uuid, upstreamSessionId: uuid, tokenEnvelope: envelope }),
]);
const cleanupCompletionResult = z.strictObject({ kind: z.enum(['completed', 'pending', 'failed', 'denied']) });
type Facts = z.infer<typeof facts>;
export type RuntimeSnapshot = z.infer<typeof snapshotSchema>;
export type RuntimeCredentials = z.infer<typeof credentialSchema>;
export type RuntimeConfirmation = z.infer<typeof confirmationSchema>;
export type RuntimeFault = { readonly kind: 'unavailable' | 'outcome_unknown'; readonly reason:
  'configuration' | 'cancelled' | 'timeout' | 'transport' | 'upstream_rejected' | 'invalid_response' };
type Invalid = { readonly kind: 'invalid_input' };
type RefreshReply<T extends z.ZodType> = z.infer<T> | RuntimeFault | Invalid;
export interface SessionRuntimeRepository {

  claimSessionCleanup(input: unknown, signal?: AbortSignal): Promise<RefreshReply<typeof cleanupClaimResult>>;
  completeSessionCleanup(input: unknown, signal?: AbortSignal): Promise<RefreshReply<typeof cleanupCompletionResult>>;
  claimRefresh(input: unknown, signal?: AbortSignal): Promise<RefreshReply<typeof claimResult>>;
  markRefreshSent(input: unknown, signal?: AbortSignal): Promise<RefreshReply<typeof sendResult>>;
  finishRefresh(input: unknown, signal?: AbortSignal): Promise<RefreshReply<typeof finishResult>>;
  resolveRefresh(input: unknown, signal?: AbortSignal): Promise<RefreshReply<typeof resolveResult>>;
  closeRefresh(input: unknown, signal?: AbortSignal): Promise<RefreshReply<typeof closeResult>>;
  snapshot(input: unknown, signal?: AbortSignal): Promise<RuntimeSnapshot | z.infer<typeof absent> | RuntimeFault | Invalid>;
  credentials(input: unknown, signal?: AbortSignal): Promise<RuntimeCredentials | z.infer<typeof denied> | RuntimeFault | Invalid>;
  confirm(input: unknown, signal?: AbortSignal): Promise<RuntimeConfirmation | z.infer<typeof denied> | RuntimeFault | Invalid>;
}
function fields(value: unknown, names: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || ![Object.prototype,null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== names.length) return null;
  const result: Record<string, unknown> = Object.create(null);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !('value' in descriptor)) return null;
    result[name] = descriptor.value;
  }
  return result;
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
const invalid = (): Invalid => Object.freeze({ kind: 'invalid_input' });
function parse<T>(schema: z.ZodType<T>, value: unknown): T | null {
  const result = schema.safeParse(value); return result.success ? freeze(result.data) : null;
}
function bound(value: RuntimeCredentials | RuntimeConfirmation, expected: Facts): boolean {
  const context = value.kind === 'confirmed' ? value.context : value;
  return context.sessionId === expected.sessionId && context.ownerId === expected.ownerId && context.authSubject === expected.authSubject
    && context.datasetEpoch === expected.datasetEpoch && value.tokenVersion === expected.tokenVersion
    && value.controlVersion === expected.controlVersion && value.browserGeneration === expected.browserGeneration
    && (value.kind === 'confirmed' || value.upstreamSessionId === expected.upstreamSessionId);
}
function argumentsFor(value: Facts, hashes: { p_session_secret_hash: string; p_browser_secret_hash: string }) {
  return { ...hashes, p_expected_token_version: value.tokenVersion,
    p_expected_control_version: value.controlVersion, p_expected_dataset_epoch: value.datasetEpoch };
}

function refreshArguments(value: z.infer<typeof refreshInput>, hashes: Parameters<typeof argumentsFor>[1]) {
  return {
    ...argumentsFor(value, hashes),
    p_session_id: value.sessionId, p_browser_id: value.browserId, p_browser_generation: value.browserGeneration,
    p_owner_id: value.ownerId, p_auth_subject: value.authSubject, p_upstream_session_id: value.upstreamSessionId,
    p_attempt_id: value.attemptId, p_request_fingerprint: value.requestFingerprint,
  };
}

function verifiedPairMatches(value: Facts & { verifiedAuthSubject: string; verifiedUpstreamSessionId: string }) {
  return value.authSubject === value.verifiedAuthSubject && value.upstreamSessionId === value.verifiedUpstreamSessionId;
}

type RuntimeRpc = 'jls_auth_session_snapshot_v1' | 'jls_auth_current_credentials_v1' | 'jls_auth_confirm_session_v1'
  | 'jls_auth_refresh_claim_v1' | 'jls_auth_refresh_mark_sent_v1' | 'jls_auth_refresh_finish_v1'
  | 'jls_auth_refresh_resolve_v1' | 'jls_auth_refresh_close_v1'
  | 'jls_auth_session_cleanup_claim_v1' | 'jls_auth_session_cleanup_complete_v1';

/** Fixed server control capability, not an owner guard or user-context data client. Import the server-only gateway in application code. */
export function createSessionRuntimeRepository(configuration: unknown, fetcher: typeof fetch = fetch,
  monotonicClock: () => number = () => performance.now()): SessionRuntimeRepository {
  let trusted: { origin: string; key: string } | null = null;
  try {
    const config = fields(configuration, ['supabaseOrigin','secretKey']);
    if (config && typeof config.supabaseOrigin === 'string' && /^https:\/\/[a-z0-9]{20}\.supabase\.co$/.test(config.supabaseOrigin)
      && typeof config.secretKey === 'string' && /^sb_secret_[A-Za-z0-9_-]{16,256}$/.test(config.secretKey)) {
      trusted = { origin: config.supabaseOrigin, key: config.secretKey };
    }
  } catch { /* Malformed configuration grants no transport capability. */ }
  async function post<T>(name: RuntimeRpc,
    body: object, decode: (value: unknown) => T | null, mutation: boolean, signal?: AbortSignal): Promise<T | RuntimeFault> {
    const fault = (reason: RuntimeFault['reason'], sent = true): RuntimeFault => Object.freeze({
      kind: mutation && sent ? 'outcome_unknown' : 'unavailable', reason });
    if (!trusted) return fault('configuration', false);
    if (signal?.aborted) return fault('cancelled', false);
    let started: number;
    try { started = monotonicClock(); } catch { return fault('configuration', false); }
    if (signal?.aborted) return fault('cancelled', false);
    if (!Number.isFinite(started) || started < 0) return fault('configuration', false);
    const controller = new AbortController();
    const expired = () => { const current = monotonicClock(); return !Number.isFinite(started) || !Number.isFinite(current)
      || current < started || current-started >= 2000; };
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let cancelledReader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let completed = false;
    const cancel = () => {
      controller.abort();
      if (reader && reader !== cancelledReader) {
        cancelledReader = reader;
        try { void reader.cancel().catch(() => {}); } catch { /* Cleanup cannot delay the deadline. */ }
      }
    };
    const releaseReader = () => {
      try {
        reader?.releaseLock();
        reader = undefined;
      } catch { /* The pending read owns the lock until it settles. */ }
    };
    const { promise: stop, resolve } = Promise.withResolvers<RuntimeFault>();
    const onAbort = () => { resolve(fault('cancelled')); cancel(); };
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => { resolve(fault('timeout')); cancel(); }, 2000);
    const request = (async (): Promise<T | RuntimeFault> => {
      try {
        const response = await fetcher(`${trusted.origin}/rest/v1/rpc/${name}`, { method: 'POST',
          headers: { apikey: trusted.key, 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body),
          credentials: 'omit', redirect: 'error', cache: 'no-store', signal: controller.signal });
        reader = response.body?.getReader();
        if (expired()) { cancel(); return fault('timeout'); }
        if (completed || controller.signal.aborted) { cancel(); return fault('cancelled'); }
        if (response.status !== 200) return fault('upstream_rejected');
        if (response.headers.get('Content-Type')?.split(';',1)[0].trim().toLowerCase() !== 'application/json' || !reader) return fault('invalid_response');
        let length = 0; const chunks: Uint8Array[] = [];
        while (true) {
          const chunk = await reader.read();
          if (expired()) { cancel(); return fault('timeout'); }
          if (completed || controller.signal.aborted) return fault('cancelled');
          if (chunk.done) break;
          length += chunk.value.byteLength;
          if (length > 65536) return fault('invalid_response');
          chunks.push(chunk.value);
        }
        const bytes = new Uint8Array(length); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk,offset); offset += chunk.byteLength; }
        let result: T | null;
        try { result = decode(JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes))); }
        catch { return fault('invalid_response'); }
        if (expired()) { cancel(); return fault('timeout'); }
        return result ?? fault('invalid_response');
      } catch { return fault('transport'); }
      finally { if (completed) releaseReader(); }
    })();
    try {
      const result = await Promise.race([stop,request]);
      if (signal?.aborted) return fault('cancelled');
      if (result && typeof result === 'object' && 'reason' in result) cancel();
      return result;
    } finally {
      completed = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      releaseReader();
    }
  }
  function input<T extends { sessionSecret?: unknown; browserSecret?: unknown }>(schema: z.ZodType<T>, value: unknown, keys: readonly string[]) {
    try {
      const copied = fields(value,keys); const parsed = copied && schema.safeParse(copied);
      if (!parsed || !parsed.success) return null;
      return { value: parsed.data, hashes: { p_session_secret_hash: hashSessionSecret(parsed.data.sessionSecret),
        p_browser_secret_hash: hashAuthActionSecret('browser',parsed.data.browserSecret) } };
    } catch { return null; }
  }
  function settleRefresh(mode: 'finish', value: unknown, signal?: AbortSignal): Promise<RefreshReply<typeof finishResult>>;
  function settleRefresh(mode: 'resolve', value: unknown, signal?: AbortSignal): Promise<RefreshReply<typeof resolveResult>>;
  function settleRefresh(mode: 'finish' | 'resolve', value: unknown, signal?: AbortSignal): Promise<RefreshReply<typeof resolveResult>> {
    const prepared = input(finishInput, value, Object.keys(finishInput.shape));
    if (!prepared || !verifiedPairMatches(prepared.value) || prepared.value.tokenVersion >= Number.MAX_SAFE_INTEGER - 1) {
      return Promise.resolve(invalid());
    }
    const expected = prepared.value;
    const settling = mode === 'finish';
    return post(settling ? 'jls_auth_refresh_finish_v1' : 'jls_auth_refresh_resolve_v1', {
      ...refreshArguments(expected, prepared.hashes),
      p_finish_operation_id: expected.finishOperationId, p_finish_fingerprint: expected.finishFingerprint,
      p_verified_subject: expected.verifiedAuthSubject, p_verified_upstream_session_id: expected.verifiedUpstreamSessionId,
      p_token_envelope: expected.tokenEnvelope, p_access_expires_at: new Date(expected.accessExpiresAt).toISOString(),
    }, value => {
      const decoded = parse(settling ? finishResult : resolveResult, value);
      if (decoded?.kind !== 'committed') return decoded;
      return decoded.attemptId === expected.attemptId && decoded.sessionId === expected.sessionId
        && decoded.tokenVersion === expected.tokenVersion + 1 ? decoded : null;
    }, settling, signal);
  }
  function cleanupInput<T>(schema: z.ZodType<T>, value: unknown, names: readonly string[]): T | null {
    try { return parse(schema, fields(value, names)); } catch { return null; }
  }
  return Object.freeze({
    async claimSessionCleanup(value: unknown, signal?: AbortSignal) {
      const expected = cleanupInput(cleanupClaimInput, value, Object.keys(cleanupClaimInput.shape));
      if (!expected) return invalid();
      const result = await post('jls_auth_session_cleanup_claim_v1', {
        p_session_id: expected.sessionId, p_claim_id: expected.claimId,
      }, value => {
        const decoded = parse(cleanupClaimResult, value);
        if (decoded?.kind !== 'cleanup') return decoded;
        return decoded.sessionId === expected.sessionId && decoded.claimId === expected.claimId ? decoded : null;
      }, true, signal);
      return result.kind === 'cleanup' && signal?.aborted
        ? Object.freeze({ kind: 'outcome_unknown', reason: 'cancelled' }) : result;
    },
    completeSessionCleanup(value: unknown, signal?: AbortSignal) {
      const expected = cleanupInput(cleanupCompletionInput, value, Object.keys(cleanupCompletionInput.shape));
      if (!expected) return Promise.resolve(invalid());
      return post('jls_auth_session_cleanup_complete_v1', {
        p_session_id: expected.sessionId, p_claim_id: expected.claimId, p_revision: expected.revision, p_outcome: expected.outcome,
      }, value => parse(cleanupCompletionResult, value), true, signal);
    },
    async claimRefresh(value: unknown, signal?: AbortSignal) {
      const prepared = input(refreshInput, value, Object.keys(refreshInput.shape));
      if (!prepared) return invalid();
      const result = await post('jls_auth_refresh_claim_v1', refreshArguments(prepared.value, prepared.hashes), value => {
        const decoded = parse(claimResult, value);
        return decoded?.kind === 'claimed' && decoded.attemptId !== prepared.value.attemptId ? null : decoded;
      }, true, signal);
      return result.kind === 'claimed' && signal?.aborted
        ? Object.freeze({ kind: 'outcome_unknown', reason: 'cancelled' }) : result;
    },
    async markRefreshSent(value: unknown, signal?: AbortSignal) {
      const prepared = input(refreshInput, value, Object.keys(refreshInput.shape));
      if (!prepared) return invalid();
      const result = await post('jls_auth_refresh_mark_sent_v1', refreshArguments(prepared.value, prepared.hashes),
        value => parse(sendResult, value), true, signal);
      return result.kind === 'transmit' && signal?.aborted
        ? Object.freeze({ kind: 'outcome_unknown', reason: 'cancelled' }) : result;
    },
    finishRefresh(value: unknown, signal?: AbortSignal) {
      return settleRefresh('finish', value, signal);
    },
    resolveRefresh(value: unknown, signal?: AbortSignal) {
      return settleRefresh('resolve', value, signal);
    },
    closeRefresh(value: unknown, signal?: AbortSignal) {
      const prepared = input(closeInput, value, Object.keys(closeInput.shape))
        ?? input(latePairInput, value, Object.keys(latePairInput.shape));
      if (!prepared) return Promise.resolve(invalid());
      const expected = prepared.value;
      if (expected.disposition === 'late_pair' && !verifiedPairMatches(expected)) return Promise.resolve(invalid());
      return post('jls_auth_refresh_close_v1', {
        ...refreshArguments(expected, prepared.hashes),
        p_close_operation_id: expected.closeOperationId, p_close_fingerprint: expected.closeFingerprint,
        p_disposition: expected.disposition,
        p_verified_subject: expected.disposition === 'late_pair' ? expected.verifiedAuthSubject : null,
        p_verified_upstream_session_id: expected.disposition === 'late_pair' ? expected.verifiedUpstreamSessionId : null,
        p_token_envelope: expected.disposition === 'late_pair' ? expected.tokenEnvelope : null,
      }, value => {
        const decoded = parse(closeResult, value);
        return decoded && (decoded.kind === 'denied' || decoded.kind === closeSuccess[expected.disposition]) ? decoded : null;
      }, true, signal);
    },
    async snapshot(value: unknown, signal?: AbortSignal) {
      const prepared = input(cookies,value,Object.keys(cookies.shape)); if (!prepared) return invalid();
      return post('jls_auth_session_snapshot_v1', prepared.hashes, value => parse(z.union([snapshotSchema,absent]),value),false,signal);
    },
    async credentials(value: unknown, signal?: AbortSignal) {
      const prepared = input(facts,value,Object.keys(facts.shape)); if (!prepared) return invalid();
      return post('jls_auth_current_credentials_v1',argumentsFor(prepared.value,prepared.hashes), value => {
        const decoded = parse(z.union([credentialSchema,denied]),value);
        return decoded && (decoded.kind === 'denied' || bound(decoded,prepared.value)) ? decoded : null;
      },false,signal);
    },
    async confirm(value: unknown, signal?: AbortSignal) {
      const prepared = input(confirmationInput,value,Object.keys(confirmationInput.shape)); if (!prepared) return invalid();
      const expected = prepared.value;
      if (expected.authSubject !== expected.verifiedAuthSubject || expected.upstreamSessionId !== expected.verifiedUpstreamSessionId) return invalid();
      return post('jls_auth_confirm_session_v1',{ ...argumentsFor(expected,prepared.hashes),
        p_verified_subject: expected.verifiedAuthSubject, p_verified_upstream_session_id: expected.verifiedUpstreamSessionId }, value => {
        const decoded = parse(z.union([confirmationSchema,denied]),value);
        return decoded && (decoded.kind === 'denied' || bound(decoded,expected)) ? decoded : null;
      },true,signal);
    },
  });
}
