import { z } from 'zod';
import { UuidSchema, VersionSchema } from './learning.ts';
/** Fixed public descriptions prevent raw provider/source/answer text leaking into problems. */
export const problemRegistry = {
  malformed_request: [400, 'Malformed request.'],
  unauthenticated: [401, 'Owner session required.'],
  forbidden: [403, 'Operation not permitted.'],
  not_found: [404, 'Resource unavailable.'],
  invalid_command: [422, 'Command fields are invalid.'],
  idempotency_key_reused: [409, 'Operation identity already used for different input.'],
  test_reference_locked: [409, 'Finish the unfinished Test to view this reference.'],
  session_closed: [409, 'Session execution is closed.'],
  repair_origin_affected: [409, 'Repair origin requires review.'],
  version_conflict: [412, 'Resource version changed.'],
  execution_conflict: [409, 'Execution has a conflicting proposal.'],
  missing_precondition: [428, 'Required precondition is missing.'],
  rate_limited: [429, 'Request limit reached.'],
  temporarily_unavailable: [503, 'Service temporarily unavailable.'],
  unsafe_command_acknowledgement: [503, 'Safe acknowledgement unavailable.'],
  receipt_integrity_error: [503, 'Command receipt unavailable.'],
  receipt_policy_unsupported: [503, 'Command receipt policy unsupported.'],
} as const;
export type ProblemCode = keyof typeof problemRegistry;
export const problemStatus = Object.fromEntries(Object.entries(problemRegistry).map(([code, value]) => [code, value[0]])) as { [K in ProblemCode]: typeof problemRegistry[K][0] };
const variants = Object.entries(problemRegistry).map(([code, [status, message]]) => z.strictObject({
  type: z.literal(`urn:japanese-learning-studio:problem:${code}`), title: z.literal(message),
  status: z.literal(status), detail: z.literal(message), code: z.literal(code), requestId: UuidSchema,
  fieldErrors: z.array(z.strictObject({ path: z.array(z.union([z.string().regex(/^[a-zA-Z][a-zA-Z0-9]*$/), VersionSchema])), code: z.enum(['invalid_type', 'invalid_uuid', 'invalid_version', 'invalid_value', 'unexpected_field', 'invalid_etag', 'invalid_row_count', 'duplicate_row_id', 'too_long']) })).optional(),
  currentVersion: VersionSchema.optional(), conflictId: UuidSchema.optional(),
}));
export const ProblemSchema = z.union(variants);
export function problemSchemaForStatus(status: number) {
  return z.union(variants.filter((_, index) => Object.values(problemRegistry)[index][0] === status));
}
export type Problem = z.infer<typeof ProblemSchema>;
export function createProblem(code: ProblemCode, requestId: string, fields: { conflictId?: string; currentVersion?: number } = {}): Problem {
  const [status, message] = problemRegistry[code];
  return ProblemSchema.parse({ type: `urn:japanese-learning-studio:problem:${code}`, title: message, status, detail: message, code, requestId, ...fields });
}
