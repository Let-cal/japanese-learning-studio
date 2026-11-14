import { z } from 'zod';
import { AbilitySchema, SafeExecutionSchema, SessionEventInputSchema, SessionEventReceiptSchema, UuidSchema, VersionSchema } from './learning.ts';
import { JobActionBodySchema, JobAcknowledgementSchema, JobStatusSchema } from './jobs.ts';
import { ManualDraftBatchBodySchema, ManualDraftReceiptSchema } from './manualDrafts.ts';
import { RepairStartSchema, RepairEventBodySchema, RepairReceiptSchema, SafeRepairSchema } from './repair.ts';
import { DisclosureRequestSchema, DisclosureDecisionSchema } from './disclosure.ts';
import { RecheckDecisionSchema, RecheckReceiptSchema, TargetedRecheckProjectionInputSchema, TargetedRecheckSchema } from './rechecks.ts';
import { ProblemSchema, problemSchemaForStatus, problemSchemaForCodes } from './problems.ts';
import type { ProblemCode } from './problems.ts';
import { AuthCallbackQuerySchema, AuthCsrfBodySchema, AuthCsrfSuccessSchema, AuthCsrfTokenSchema, AuthLoginFormSchema, BrowserBindingSecretSchema, OAuthAttemptSecretSchema, MeSuccessSchema } from './auth.ts';
import { MemoryNoteBodySchema, MemoryNoteSchema, MemoryNoteReceiptSchema } from './memoryNotes.ts';
import { commandKindByOperationId } from './acknowledgements.ts';
export { problemStatus } from './problems.ts';
export { MemoryNoteBodySchema, MemoryNoteSchema, MemoryNoteReceiptSchema } from './memoryNotes.ts';
const MetaSchema = z.strictObject({ requestId: UuidSchema, datasetEpoch: UuidSchema });
const envelope = (data: z.ZodType) => z.strictObject({ data, meta: MetaSchema });
const runtimeSchemas = {
  Ability: AbilitySchema, Version: VersionSchema, ManualDraftBatchBody: ManualDraftBatchBodySchema,
  ManualDraftReceipt: ManualDraftReceiptSchema, MemoryNoteBody: MemoryNoteBodySchema, MemoryNote: MemoryNoteSchema,
  RepairStart: RepairStartSchema, RepairEventBody: RepairEventBodySchema, RepairReceipt: RepairReceiptSchema,
  SafeRepair: SafeRepairSchema, DisclosureRequest: DisclosureRequestSchema, DisclosureDecision: DisclosureDecisionSchema,
  RecheckDecision: RecheckDecisionSchema, RecheckReceipt: RecheckReceiptSchema,
  TargetedRecheckProjectionInput: TargetedRecheckProjectionInputSchema, TargetedRecheck: TargetedRecheckSchema,
  JobActionBody: JobActionBodySchema, JobStatus: JobStatusSchema, JobAcknowledgement: JobAcknowledgementSchema,
  SessionEventBody: SessionEventInputSchema, SafeExecution: SafeExecutionSchema, Problem: ProblemSchema,
  ManualDraftSuccess: envelope(ManualDraftReceiptSchema), MemoryNoteSuccess: envelope(MemoryNoteSchema),
  MemoryNoteWriteSuccess: envelope(MemoryNoteReceiptSchema), RepairSuccess: envelope(SafeRepairSchema),
  RepairCommandSuccess: envelope(RepairReceiptSchema), RecheckSuccess: envelope(RecheckReceiptSchema),
  JobSuccess: envelope(JobStatusSchema), JobActionSuccess: envelope(JobAcknowledgementSchema),
  ExecutionSuccess: envelope(SafeExecutionSchema), SessionEventSuccess: envelope(SessionEventReceiptSchema),
  AuthCallbackQuery: AuthCallbackQuerySchema, AuthCsrfBody: AuthCsrfBodySchema, AuthCsrfSuccess: AuthCsrfSuccessSchema,
  AuthCsrfToken: AuthCsrfTokenSchema, BrowserBindingSecret: BrowserBindingSecretSchema,
  OAuthAttemptSecret: OAuthAttemptSecretSchema, MeSuccess: MeSuccessSchema, AuthLoginForm: AuthLoginFormSchema,
};
type SchemaObject = Record<string, unknown>;
interface Reference { $ref: string }
interface ResponseObject { description: string; headers?: Record<string, SchemaObject>; content?: Record<string, { schema: Reference }> }
interface OperationObject {
  operationId: string; description: string; 'x-implementationStatus': 'planned';
  security: Record<string, never[]>[]; parameters: Reference[];
  responses: Record<string, ResponseObject>; requestBody?: { required: boolean; content: Record<string, { schema: Reference }> };
  'x-commandKind'?: string;
  'x-body-byte-length'?: 0;
  'x-query-schema'?: Reference;
  'x-auth-purpose-authorizations'?: Record<string, string[]>;
  'x-max-body-bytes'?: number;
  'x-auth-proof'?: { in: 'body'; name: 'csrfToken'; purpose: 'login'; authoritative: true }
    & ({ operation: 'recovery'; scope: 'oauth-attempt' } | { operation?: never; scope?: never });
}
interface ApiDocument {
  openapi: string; jsonSchemaDialect: string; info: { title: string; version: string; description: string };
  'x-plannedOperations': { family: string; status: string; bodyContract: string }[]; 'x-authorizationOrder': string;
  paths: Record<string, Record<string, OperationObject>>;
  components: { securitySchemes: Record<string, SchemaObject>; parameters: Record<string, SchemaObject>; schemas: Record<string, SchemaObject> };
}
const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const parameter = (name: string) => ({ $ref: `#/components/parameters/${name}` });
const jsonContent = (name: string) => ({ 'application/json': { schema: ref(name) } });
const etag = { description: 'Strong resource version; canonical syntax "v0", "v1", ... .', schema: { type: 'string', pattern: '^"v(?:0|[1-9][0-9]*)"$' } };
const location = { description: 'Same-origin relative API resource location.', schema: { type: 'string', pattern: '^/api/v1/' } };
const statuses = [400, 401, 403, 404, 409, 412, 422, 428, 429, 503];

/** Deterministic core slice. Runtime routes, authentication and transactions remain future work. */
export function buildOpenApiDocument(): ApiDocument {
  const schemas: Record<string, SchemaObject> = Object.fromEntries(Object.entries(runtimeSchemas).map(([name, schema]) => [name, z.toJSONSchema(schema, { target: 'draft-2020-12', unrepresentable: 'throw' })]));
  for (const status of statuses) schemas[`Problem${status}`] = z.toJSONSchema(problemSchemaForStatus(status), { target: 'draft-2020-12', unrepresentable: 'throw' });
  const authErrors: Record<number, ProblemCode> = {
    400: 'malformed_request', 401: 'unauthenticated', 403: 'forbidden',
    409: 'sign_in_restart_required', 429: 'rate_limited', 503: 'temporarily_unavailable',
  };
  for (const [status, code] of Object.entries(authErrors)) schemas[`AuthProblem${status}`] = z.toJSONSchema(problemSchemaForCodes([code]), { target: 'draft-2020-12', unrepresentable: 'throw' });
  const paths: ApiDocument['paths'] = {};
  function operation(path: string, method: string, operationId: string, response: string, status: number, body?: string, match = false, description = '') {
    const mutation = method !== 'get';
    const commandKind = Object.entries(commandKindByOperationId).find(([id]) => id === operationId)?.[1];
    const parameters = [parameter('DatasetEpoch')];
    if (path.includes('{id}')) parameters.push(parameter('ResourceId'));
    if (mutation) parameters.push(parameter('IdempotencyKey'), parameter('Origin'), parameter('CsrfToken'));
    if (match) parameters.push(parameter('IfMatch'));
    const responses: Record<string, ResponseObject> = { [status]: { description: status === 202 ? 'Durable job acknowledgement only; no processing completion implied.' : 'Safe response after current authorization.', headers: { ETag: etag, ...(status === 201 || status === 202 ? { Location: location } : {}) }, content: jsonContent(response) } };
    for (const error of statuses) responses[error] = { description: `Sanitized problem (${error}).`, content: { 'application/problem+json': { schema: ref(`Problem${error}`) } } };
    (paths[`/api/v1${path}`] ??= {})[method] = {
      operationId, description: `Planned; not implemented. ${description}`, 'x-implementationStatus': 'planned', security: [{ OwnerSession: [] }],
      ...(commandKind ? { 'x-commandKind': commandKind } : {}),
      parameters, responses, ...(body ? { requestBody: { required: true, content: jsonContent(body) } } : {}),
    };
  }
  operation('/manual-draft-batches', 'post', 'createManualDraftBatch', 'ManualDraftSuccess', 201, 'ManualDraftBatchBody', true, 'If-Match is the lesson version, mapped to ConfirmedManualDraftBatch.lessonBaseVersion. All confirmed rows commit atomically; Location identifies the created batch.');
  operation('/vocabulary-items/{id}/memory-note', 'get', 'getMemoryNote', 'MemoryNoteSuccess', 200, undefined, false, 'Route id maps to itemId. An absent note is empty, anchor null, noteVersion 0 and ETag "v0"; reading does not create a note. Disclosure authorization is required.');
  operation('/vocabulary-items/{id}/memory-note', 'put', 'saveMemoryNote', 'MemoryNoteWriteSuccess', 200, 'MemoryNoteBody', true, 'Route id maps to itemId; If-Match maps to expectedNoteVersion. Body anchor is an immutable item revision. Version 0 is atomic create-if-absent; empty text clears with retained history.');
  operation('/guided-repairs', 'post', 'startGuidedRepair', 'RepairCommandSuccess', 201, 'RepairStart', false, 'Origin item/source/grade revisions in body are checked atomically. No repair ETag exists yet. Server resolves owner/dataset and historical first answer; Location identifies the repair.');
  operation('/guided-repairs/{id}', 'get', 'getGuidedRepair', 'RepairSuccess', 200, undefined, false, 'Safe repair projection; current disclosure authorization required; ETag belongs to repair execution.');
  operation('/guided-repairs/{id}/events', 'post', 'executeRepairEvent', 'RepairCommandSuccess', 201, 'RepairEventBody', true, 'Body maps to RepairEventInput.event, route id to repairId and If-Match to expectedRepairVersion. Origin Test ETag is never accepted as a substitute. Location identifies committed repair event.');
  operation('/targeted-recheck-decisions', 'post', 'acceptTargetedRecheck', 'RecheckSuccess', 201, 'RecheckDecision', false, 'Bounded additive mapping of approved domain port, not a scheduler implementation. Server sets proposedAt and resolves owner/dataset. Location identifies retained intent/decision. Ordinary FSRS due is separate.');
  operation('/jobs/{id}', 'get', 'getJob', 'JobSuccess', 200, undefined, false, 'Sanitized references only; no provider credentials, traces or provider/result URLs.');
  operation('/jobs/{id}/cancellation', 'post', 'cancelJob', 'JobActionSuccess', 200, 'JobActionBody', false, 'Allowed-state check is atomic. Cancellation prevents output application; it does not guarantee provider processing or billing stopped.');
  operation('/jobs/{id}/retries', 'post', 'retryJob', 'JobActionSuccess', 202, 'JobActionBody', false, 'Revalidate allowed state, current consent and budget. Unknown billable submission must not be retried automatically. Location identifies the durable job.');
  operation('/sessions/{id}/execution', 'get', 'getSessionExecution', 'ExecutionSuccess', 200, undefined, false, 'Safe current execution; no hidden keys, answer ruby, correct markers or reveal URLs. ETag is execution version.');
  operation('/sessions/{id}/events', 'post', 'executeSessionEvent', 'SessionEventSuccess', 201, 'SessionEventBody', true, 'Route id and If-Match merge as sessionId/expectedExecutionVersion; operation identity comes from Idempotency-Key. Server persists sticky assistance before reference release. Finish and answer serialize; committed replay precedes stale-version/state checks. Location identifies event.');
  // Auth has independent prerequisites. Do not route it through the domain operation builder.
  function authOperation(path: string, method: 'get' | 'post', operationId: string, status: number,
    security: OperationObject['security'], errors: number[], description: string, body?: string, response?: string,
    successHeaders: Record<string, SchemaObject> = {}, bodyMediaType = 'application/json'): OperationObject {
    const callback = path === '/auth/callback';
    const recovery = path === '/auth/recover';
    const headers: Record<string, SchemaObject> = {
      'Cache-Control': { description: 'Required on every Auth outcome.', schema: { type: 'string', const: 'private, no-store' } },
      'X-Request-Id': { description: 'Required correlation ID; never contains provider/query/cookie data.', schema: z.toJSONSchema(UuidSchema) },
      ...(!recovery ? { 'Set-Cookie': {
        description: 'Conditional issuance/expiration only after the corresponding verified state transition. Multiple Set-Cookie header fields, never comma-joined. Cookies: __Host-jls-session, __Host-jls-browser, __Host-jls-oauth; Secure; HttpOnly; SameSite=Lax; Path=/; no Domain. Session issuance only after confirmed commit; cookie secrets never appear in JSON.',
        schema: { type: 'string' },
      } } : {}),
      ...(callback ? { 'Referrer-Policy': { description: 'Required on every callback outcome.', schema: { type: 'string', const: 'no-referrer' } } } : {}),
    };
    const responses: Record<string, ResponseObject> = {
      [status]: { description: 'Planned Auth success after server verification; runtime absent.', headers: { ...headers, ...successHeaders }, ...(response ? { content: jsonContent(response) } : {}) },
    };
    for (const error of errors) responses[error] = {
      description: error === 409 ? 'Closed/uncertain exchange or undelivered sign-in requires a fresh login; never retry a one-use exchange blindly.' : error === 503 ? 'Dependency or unresolved commit outcome; never claim absence, success or restart until resolved.' : `Sanitized Auth problem (${error}).`,
      headers: { ...headers, ...(error === 429 ? { 'Retry-After': { description: 'Required bounded delay in seconds.', schema: { type: 'integer', minimum: 1, maximum: 3600 } } } : {}) },
      content: { 'application/problem+json': { schema: ref(`AuthProblem${error}`) } },
    };
    const result: OperationObject = {
      operationId, description: `Planned; not implemented. ${description} Unrelated browser headers/cookies are allowed; future raw-cookie parsing must reject duplicate relevant cookie names.`,
      'x-implementationStatus': 'planned', security,
      parameters: method === 'post' ? [parameter('Origin')] : [], responses,
      ...(body ? { requestBody: { required: true, content: { [bodyMediaType]: { schema: ref(body) } } } } : { 'x-body-byte-length': 0 as const }),
    };
    (paths[`/api/v1${path}`] ??= {})[method] = result;
    return result;
  }
  const csrf = authOperation('/auth/csrf', 'post', 'issueAuthCsrf', 200, [], [400, 401, 403, 429, 503],
    'Exact configured Origin is required; no prior proof. Login/logout purpose requires no active owner session or epoch. Mutation purpose additionally requires a valid owner session (401 otherwise). Proof binds exact presented session-cookie fingerprint/absence and browser generation; bounded malformed cookie text remains fingerprintable and never authorizes access.', 'AuthCsrfBody', 'AuthCsrfSuccess');
  csrf['x-auth-purpose-authorizations'] = { login: [], logout: [], mutation: ['OwnerSession'] };
  const login = authOperation('/auth/login', 'post', 'startAuthLogin', 303, [{ BrowserBinding: [] }], [400, 403, 429, 503],
    'Native top-level POST form, then external 303 navigation. Exact Origin, mandatory login-purpose csrfToken form-body proof AND browser binding. Only application/x-www-form-urlencoded; raw body at most 256 bytes. Reject duplicate/unknown fields before object construction. Body proof is authoritative; no X-CSRF-Token header alternative/fallback. The same-origin form may hold the proof in a hidden field, never URL/storage/logs. No returnTo, provider, owner fields or app state. Persist one bound OAuth attempt before redirecting. Proof syntax alone is not verification.', 'AuthLoginForm', undefined,
    { Location: { description: 'The exact approved Supabase authorize URL selected from server-only configuration after adapter validation; never derived from a request URL or returned as a JSON provider URL. Exact environment URL must be approved before runtime activation.', schema: { type: 'string', format: 'uri', pattern: '^https://' } } }, 'application/x-www-form-urlencoded');
  login['x-max-body-bytes'] = 256;
  login['x-auth-proof'] = { in: 'body', name: 'csrfToken', purpose: 'login', authoritative: true };
  const recovery = authOperation('/auth/recover', 'post', 'recoverAuthLogin', 204, [{ BrowserBinding: [], OAuthAttempt: [] }], [400, 403, 429, 503],
    'Requires exact Origin and an attempt-specific recovery proof from a same-origin server-rendered form. The login-class proof hash and persisted issuance fingerprint bind the exact OAuth flow. The body uses the login form wire shape and rejects duplicate fields and query parameters. A confirmed locked recovery or exact receipt replay returns an empty 204 with no cookie writes. Work still in progress or unconfirmed returns 503. After 204 reload sign-in state and obtain a fresh login proof.', 'AuthLoginForm', undefined, {}, 'application/x-www-form-urlencoded');
  recovery['x-max-body-bytes'] = 256;
  recovery['x-auth-proof'] = { in: 'body', name: 'csrfToken', purpose: 'login', operation: 'recovery', scope: 'oauth-attempt', authoritative: true };
  const callback = authOperation('/auth/callback', 'get', 'completeAuthCallback', 303, [{ OAuthAttempt: [], BrowserBinding: [] }], [400, 403, 409, 429, 503],
    'Request body forbidden. Query is exactly code OR error with optional error_code/error_description, never mixed; reject unknown keys, duplicate decoded names and controls before object construction. Decode URLSearchParams once; never log/echo provider query or errors. Supabase owns provider-facing state; no application state parameter. Verify one-use attempt, binding, owner and upstream identity. Fixed post-callback target is /today. Provider denial maps to forbidden. Closed/uncertain exchange requires fresh login (409); unresolved commit is 503.', undefined, undefined,
    { Location: { description: 'Fixed canonical S02 destination after confirmed session commit or safe matching-cookie retry.', schema: { type: 'string', const: '/today' } } });
  callback.parameters = ['AuthCallbackCode', 'AuthCallbackError', 'AuthCallbackErrorCode', 'AuthCallbackErrorDescription'].map(parameter);
  callback['x-query-schema'] = ref('AuthCallbackQuery');
  authOperation('/auth/logout', 'post', 'logout', 204, [{ AuthActionProof: [], BrowserBinding: [] }], [400, 403, 429, 503],
    'Exact Origin, logout-purpose Auth-action proof AND browser binding, including expired/revoked or explicitly absent presented session. Raw request body must be zero bytes: reject {}, null and whitespace. No active owner, current epoch, refresh, recent reauth, domain Idempotency-Key or ETag prerequisite. Stable proof identity and retained receipt bind exact cookie/absence and before/after generation. Confirm local revocation/absence before 204 and cookie expiration; unresolved commit returns 503. An old proof must not revoke or clear newer state.');
  authOperation('/me', 'get', 'getMe', 200, [{ OwnerSession: [] }], [400, 401, 403, 429, 503],
    'Request body forbidden. Server-verified owner session only; no client X-Dataset-Epoch assertion. Discovers current server datasetEpoch without extending idle lifetime. No email, owner/session/Auth-subject IDs, tokens or provider URLs.', undefined, 'MeSuccess');
  return {
    openapi: '3.1.0', jsonSchemaDialect: 'https://json-schema.org/draft/2020-12/schema',
    info: { title: 'M1 core API contract slice', version: '0.1.0', description: 'Planned contracts only. No running BFF/auth, transaction, provider or scheduling implementation is claimed.' },
    'x-plannedOperations': [
      'auth/session and logout', 'curricula/volumes/lessons', 'imports/source-pages/uploads/extractions', 'draft-items/approval-batches',
      'vocabulary library/details and occurrence-links', 'content-corrections/decisions and conflicts/resolutions',
      'session-presets/previews/creation/plan/results', 'attempts/grading-retries/review-requests', 'explanations',
      'media/content/issue-reports', 'changes feed', 'preferences', 'provider-consents/decisions',
      'notification-devices/reminder-acknowledgements', 'exports/downloads', 'restore-previews/account-data replacement',
    ].map(family => ({ family, status: 'planned', bodyContract: family === 'auth/session and logout' ? 'six Auth HTTP contracts specified; runtime not implemented' : 'not specified in this core slice' })),
    'x-authorizationOrder': 'Domain operations only: verify owner session and active dataset epoch before receipt lookup; validate Origin/CSRF on mutations. Identical safe committed replay precedes stale ETag/domain-state checks. IDs never grant authority. Auth uses the separate operation-specific requirements.',
    paths,
    components: {
      securitySchemes: {
        OwnerSession: { type: 'apiKey', in: 'cookie', name: '__Host-jls-session', description: 'Planned server-verified owner session; existing bare 43-character secret syntax unchanged. HttpOnly, Secure, SameSite=Lax, Path=/, no Domain; runtime auth absent. Bounded malformed presented cookie text remains fingerprintable for Auth proofs but never authorizes a session.' },
        AuthActionProof: { type: 'apiKey', in: 'header', name: 'X-CSRF-Token', description: 'Logout-purpose Auth-action header proof; jls-csrf-v1 plus canonical 32-byte base64url. Login instead requires its body csrfToken with no header fallback. Domain mutations retain their separate future CSRF requirement. Format is not verification; future verifier binds purpose, exact cookie/absence, browser generation and stable operation/receipt identity.', 'x-value-schema': ref('AuthCsrfToken') },
        BrowserBinding: { type: 'apiKey', in: 'cookie', name: '__Host-jls-browser', description: 'Browser binding, no owner authority. jls-browser-v1 plus canonical 32-byte base64url; server verification required. Secure; HttpOnly; SameSite=Lax; Path=/; no Domain.', 'x-value-schema': ref('BrowserBindingSecret') },
        OAuthAttempt: { type: 'apiKey', in: 'cookie', name: '__Host-jls-oauth', description: 'One-use OAuth attempt binding. jls-oauth-v1 plus canonical 32-byte base64url; server verification required. Secure; HttpOnly; SameSite=Lax; Path=/; no Domain.', 'x-value-schema': ref('OAuthAttemptSecret') },
      },
      parameters: {
        DatasetEpoch: { name: 'X-Dataset-Epoch', in: 'header', required: true, description: 'Client epoch assertion must match the server-selected active owner dataset; never an authorization grant.', schema: z.toJSONSchema(UuidSchema) },
        ResourceId: { name: 'id', in: 'path', required: true, schema: z.toJSONSchema(UuidSchema) },
        IdempotencyKey: { name: 'Idempotency-Key', in: 'header', required: true, description: 'Maps to operationId after verified owner/dataset binding.', schema: z.toJSONSchema(UuidSchema) },
        IfMatch: { name: 'If-Match', in: 'header', required: true, description: 'Resource-specific strong mutable version. Reject weak, wildcard and multiple validators. Parse and check safe integer <= 9007199254740991.', schema: etag.schema },
        Origin: { name: 'Origin', in: 'header', required: true, description: 'Validate exact configured same-origin allowlist.', schema: { type: 'string', minLength: 1 } },
        CsrfToken: { name: 'X-CSRF-Token', in: 'header', required: true, description: 'Verify session-bound CSRF token; never log or echo it.', schema: { type: 'string', minLength: 1 } },
        AuthCallbackCode: { name: 'code', in: 'query', required: false, description: 'Exactly one code OR the error branch. The x-query-schema closes keys/branches; reject duplicates before object construction, decode once, never log/echo.', schema: { type: 'string', minLength: 1, maxLength: 2048, pattern: '^[^\\u0000-\\u001f\\u007f-\\u009f]*$' } },
        AuthCallbackError: { name: 'error', in: 'query', required: false, description: 'Error branch discriminator; cannot coexist with code. Never log/echo.', schema: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[^\\u0000-\\u001f\\u007f-\\u009f]*$' } },
        AuthCallbackErrorCode: { name: 'error_code', in: 'query', required: false, description: 'Only with error, never code. Never log/echo.', schema: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[^\\u0000-\\u001f\\u007f-\\u009f]*$' } },
        AuthCallbackErrorDescription: { name: 'error_description', in: 'query', required: false, description: 'Only with error, never code. Empty permitted; never log/echo.', schema: { type: 'string', minLength: 0, maxLength: 2048, pattern: '^[^\\u0000-\\u001f\\u007f-\\u009f]*$' } },
      }, schemas,
    },
  };
}
export function serializeOpenApiDocument(): string { return `${JSON.stringify(buildOpenApiDocument(), null, 2)}\n`; }
