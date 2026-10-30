/** Opaque UUIDs identify resources; accepting their syntax never authorizes access. */
export type Uuid = string;
export type Ability = 'meaning' | 'kana' | 'kanji';
export type GradeOutcome = 'correct' | 'incorrect' | 'pending' | 'needsReview' | 'skipped';

/** expectedVersion is mutable execution state, never an immutable revision ID. */
export interface CommandContext {
  readonly ownerId: Uuid;
  readonly datasetEpoch: Uuid;
  readonly operationId: Uuid;
  readonly expectedVersion?: number;
}

export type FieldPath = readonly (string | number)[];
export type ValidationCode = 'invalid_type' | 'invalid_uuid' | 'invalid_version' | 'invalid_value'
  | 'unexpected_field' | 'invalid_etag' | 'invalid_row_count' | 'duplicate_row_id' | 'too_long';
export interface FieldError {
  readonly path: FieldPath;
  readonly code: ValidationCode;
  readonly message: string;
}
export type ValidationResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly errors: readonly FieldError[] };

export function fieldError(path: FieldPath, code: ValidationCode, message: string): FieldError {
  return { path: [...path], code, message };
}

/** Keep the record available to collect field errors; consumers must copy allowed fields. */
export function inspectObject(input: unknown, allowedFields: readonly string[], path: FieldPath = []): {
  readonly record: Record<string, unknown> | null;
  readonly errors: readonly FieldError[];
} {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return { record: null, errors: [fieldError(path, 'invalid_type', 'Expected an object.')] };
  }
  const record = input as Record<string, unknown>;
  const errors = Object.keys(record)
    .filter(key => !allowedFields.includes(key))
    .map(key => fieldError([...path, key], 'unexpected_field', 'Unexpected field.'));
  return { record, errors };
}

// Own fields only: inherited values cannot satisfy a required JSON field.
export function ownField(record: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

export function validationErrors(...results: readonly ValidationResult<unknown>[]): FieldError[] {
  return results.flatMap(result => result.ok ? [] : [...result.errors]);
}

export function parseUuid(input: unknown, path: FieldPath = []): ValidationResult<Uuid> {
  // No case conversion, version inference, ownership lookup or semantic normalization.
  if (typeof input !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(input)) {
    return { ok: false, errors: [fieldError(path, 'invalid_uuid', 'Expected a UUID.')] };
  }
  return { ok: true, value: input };
}

export function parseVersion(input: unknown, path: FieldPath = []): ValidationResult<number> {
  if (typeof input !== 'number' || !Number.isSafeInteger(input) || input < 0) {
    return { ok: false, errors: [fieldError(path, 'invalid_version', 'Expected a nonnegative safe integer version.')] };
  }
  return { ok: true, value: input };
}

/** Nonblank checks never trim, normalize, repair or impose hidden text length limits. */
export function parseText(input: unknown, path: FieldPath, allowBlank = false): ValidationResult<string> {
  if (typeof input !== 'string') {
    return { ok: false, errors: [fieldError(path, 'invalid_type', 'Expected a string.')] };
  }
  if (!allowBlank && input.trim().length === 0) {
    return { ok: false, errors: [fieldError(path, 'invalid_value', 'Expected nonblank text.')] };
  }
  return { ok: true, value: input };
}

export function parseAbility(input: unknown): ValidationResult<Ability> {
  if (input === 'meaning' || input === 'kana' || input === 'kanji') return { ok: true, value: input };
  return { ok: false, errors: [fieldError([], 'invalid_value', 'Unknown ability.')] };
}

export function parseGradeOutcome(input: unknown): ValidationResult<GradeOutcome> {
  if (input === 'correct' || input === 'incorrect' || input === 'pending' || input === 'needsReview' || input === 'skipped') {
    return { ok: true, value: input };
  }
  return { ok: false, errors: [fieldError([], 'invalid_value', 'Unknown grade outcome.')] };
}

export function parseCommandContext(input: unknown): ValidationResult<CommandContext> {
  const { record, errors: objectErrors } = inspectObject(input, ['ownerId', 'datasetEpoch', 'operationId', 'expectedVersion']);
  if (!record) return { ok: false, errors: objectErrors };
  const ownerId = parseUuid(ownField(record, 'ownerId'), ['ownerId']);
  const datasetEpoch = parseUuid(ownField(record, 'datasetEpoch'), ['datasetEpoch']);
  const operationId = parseUuid(ownField(record, 'operationId'), ['operationId']);
  const hasVersion = Object.hasOwn(record, 'expectedVersion');
  const expectedVersion = hasVersion ? parseVersion(record.expectedVersion, ['expectedVersion']) : { ok: true as const, value: undefined };
  const errors = [...objectErrors, ...validationErrors(ownerId, datasetEpoch, operationId, expectedVersion)];
  if (!ownerId.ok || !datasetEpoch.ok || !operationId.ok || !expectedVersion.ok || errors.length) return { ok: false, errors };
  return { ok: true, value: {
    ownerId: ownerId.value, datasetEpoch: datasetEpoch.value, operationId: operationId.value,
    ...(hasVersion ? { expectedVersion: expectedVersion.value } : {}),
  } };
}

/** Canonical strong resource ETag syntax is exactly "v<base-10 version>". */
export function formatVersionETag(version: unknown): ValidationResult<string> {
  const parsed = parseVersion(version);
  return parsed.ok ? { ok: true, value: `"v${parsed.value}"` } : parsed;
}

export function parseVersionETag(input: unknown): ValidationResult<number> {
  if (typeof input !== 'string' || !/^"v(?:0|[1-9][0-9]*)"$/.test(input)) {
    return { ok: false, errors: [fieldError([], 'invalid_etag', 'Expected a canonical strong version ETag.')] };
  }
  const version = Number(input.slice(2, -1));
  const parsed = parseVersion(version);
  return parsed.ok ? parsed : { ok: false, errors: [fieldError([], 'invalid_etag', 'ETag version exceeds the safe integer range.')] };
}
