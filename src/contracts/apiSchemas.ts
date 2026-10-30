import { z } from 'zod';
import { AbilitySchema, SafeExecutionSchema, SessionEventInputSchema, SessionEventReceiptSchema, UuidSchema, VersionSchema } from './learning.ts';
import { JobActionBodySchema, JobAcknowledgementSchema, JobStatusSchema } from './jobs.ts';
import { ManualDraftBatchBodySchema, ManualDraftReceiptSchema } from './manualDrafts.ts';
import { RepairStartSchema, RepairEventBodySchema, RepairReceiptSchema, SafeRepairSchema } from './repair.ts';
import { DisclosureRequestSchema, DisclosureDecisionSchema } from './disclosure.ts';
import { RecheckDecisionSchema, RecheckReceiptSchema, TargetedRecheckProjectionInputSchema, TargetedRecheckSchema } from './rechecks.ts';
import { ProblemSchema, problemSchemaForStatus } from './problems.ts';
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
};
type SchemaObject = Record<string, unknown>;
interface Reference { $ref: string }
interface ResponseObject { description: string; headers?: Record<string, SchemaObject>; content: Record<string, { schema: Reference }> }
interface OperationObject {
  operationId: string; description: string; 'x-implementationStatus': 'planned';
  security: { OwnerSession: never[] }[]; parameters: Reference[];
  responses: Record<string, ResponseObject>; requestBody?: { required: boolean; content: Record<string, { schema: Reference }> };
  'x-commandKind'?: string;
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
  return {
    openapi: '3.1.0', jsonSchemaDialect: 'https://json-schema.org/draft/2020-12/schema',
    info: { title: 'M1 core API contract slice', version: '0.1.0', description: 'Planned contracts only. No running BFF/auth, transaction, provider or scheduling implementation is claimed.' },
    'x-plannedOperations': [
      'auth/session and logout', 'curricula/volumes/lessons', 'imports/source-pages/uploads/extractions', 'draft-items/approval-batches',
      'vocabulary library/details and occurrence-links', 'content-corrections/decisions and conflicts/resolutions',
      'session-presets/previews/creation/plan/results', 'attempts/grading-retries/review-requests', 'explanations',
      'media/content/issue-reports', 'changes feed', 'preferences', 'provider-consents/decisions',
      'notification-devices/reminder-acknowledgements', 'exports/downloads', 'restore-previews/account-data replacement',
    ].map(family => ({ family, status: 'planned', bodyContract: 'not specified in this core slice' })),
    'x-authorizationOrder': 'Verify owner session and active dataset epoch before receipt lookup; validate Origin/CSRF on mutations. Identical safe committed replay precedes stale ETag/domain-state checks. IDs never grant authority.',
    paths,
    components: {
      securitySchemes: { OwnerSession: { type: 'apiKey', in: 'cookie', name: '__Host-jls-session', description: 'Planned server-verified owner session; HttpOnly, Secure, Path=/; runtime auth absent.' } },
      parameters: {
        DatasetEpoch: { name: 'X-Dataset-Epoch', in: 'header', required: true, description: 'Client epoch assertion must match the server-selected active owner dataset; never an authorization grant.', schema: z.toJSONSchema(UuidSchema) },
        ResourceId: { name: 'id', in: 'path', required: true, schema: z.toJSONSchema(UuidSchema) },
        IdempotencyKey: { name: 'Idempotency-Key', in: 'header', required: true, description: 'Maps to operationId after verified owner/dataset binding.', schema: z.toJSONSchema(UuidSchema) },
        IfMatch: { name: 'If-Match', in: 'header', required: true, description: 'Resource-specific strong mutable version. Reject weak, wildcard and multiple validators. Parse and check safe integer <= 9007199254740991.', schema: etag.schema },
        Origin: { name: 'Origin', in: 'header', required: true, description: 'Validate exact configured same-origin allowlist.', schema: { type: 'string', minLength: 1 } },
        CsrfToken: { name: 'X-CSRF-Token', in: 'header', required: true, description: 'Verify session-bound CSRF token; never log or echo it.', schema: { type: 'string', minLength: 1 } },
      }, schemas,
    },
  };
}
export function serializeOpenApiDocument(): string { return `${JSON.stringify(buildOpenApiDocument(), null, 2)}\n`; }
