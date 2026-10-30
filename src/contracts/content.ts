import { fieldError, inspectObject, ownField, parseText, parseUuid, parseVersion, validationErrors } from './common';
import type { FieldError, Uuid, ValidationResult } from './common';

/** Names are transport-neutral camelCase. A row ID is a stable client-generated UUID. */
export interface ManualDraftRow {
  readonly clientRowId: Uuid;
  readonly writtenForm: string;
  readonly kana: string;
  readonly vietnameseSense: string;
  readonly context?: string;
}
export interface ManualDraftInput {
  readonly source: 'manualEntry';
  readonly rows: readonly ManualDraftRow[];
}
export interface ManualDraftRowError {
  readonly rowIndex: number;
  readonly clientRowId: Uuid | null;
  readonly errors: readonly FieldError[];
}
/** A preview validates only; it neither approves content nor starts learning/SRS. */
export interface ManualDraftPreview {
  readonly source: 'manualEntry';
  readonly validRows: readonly ManualDraftRow[];
  readonly rowErrors: readonly ManualDraftRowError[];
  readonly errors: readonly FieldError[];
}
export interface ConfirmedManualDraftBatch extends ManualDraftInput {
  readonly lessonId: Uuid;
  readonly lessonBaseVersion: number;
}

function parseRow(input: unknown, rowIndex: number): ValidationResult<ManualDraftRow> {
  const path = ['rows', rowIndex];
  const { record, errors: objectErrors } = inspectObject(input, ['clientRowId', 'writtenForm', 'kana', 'vietnameseSense', 'context'], path);
  if (!record) return { ok: false, errors: objectErrors };
  const clientRowId = parseUuid(ownField(record, 'clientRowId'), [...path, 'clientRowId']);
  const writtenForm = parseText(ownField(record, 'writtenForm'), [...path, 'writtenForm']);
  const kana = parseText(ownField(record, 'kana'), [...path, 'kana']);
  const vietnameseSense = parseText(ownField(record, 'vietnameseSense'), [...path, 'vietnameseSense']);
  const hasContext = Object.hasOwn(record, 'context');
  const context = hasContext ? parseText(record.context, [...path, 'context'], true) : { ok: true as const, value: undefined };
  const errors = [...objectErrors, ...validationErrors(clientRowId, writtenForm, kana, vietnameseSense, context)];
  if (!clientRowId.ok || !writtenForm.ok || !kana.ok || !vietnameseSense.ok || !context.ok || errors.length) return { ok: false, errors };
  return { ok: true, value: {
    clientRowId: clientRowId.value, writtenForm: writtenForm.value, kana: kana.value, vietnameseSense: vietnameseSense.value,
    ...(hasContext ? { context: context.value } : {}),
  } };
}

function preview(input: unknown, allowedFields: readonly string[]): ManualDraftPreview {
  const { record, errors: objectErrors } = inspectObject(input, allowedFields);
  const errors = [...objectErrors];
  const validRows: ManualDraftRow[] = [];
  const rowErrors: ManualDraftRowError[] = [];
  if (!record) return { source: 'manualEntry', validRows, rowErrors, errors };
  if (ownField(record, 'source') !== 'manualEntry') errors.push(fieldError(['source'], 'invalid_value', 'Expected explicit manualEntry provenance.'));
  const rows = ownField(record, 'rows');
  if (!Array.isArray(rows)) {
    errors.push(fieldError(['rows'], 'invalid_type', 'Expected an array of rows.'));
    return { source: 'manualEntry', validRows, rowErrors, errors };
  }
  if (rows.length < 1 || rows.length > 10) {
    errors.push(fieldError(['rows'], 'invalid_row_count', 'Expected 1–10 rows.'));
    return { source: 'manualEntry', validRows, rowErrors, errors };
  }
  // Materialize holes as invalid undefined rows rather than skipping their validation.
  const submittedRows: unknown[] = Array.from(rows);
  const ids = submittedRows.map(value => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
    const id = parseUuid(ownField(value as Record<string, unknown>, 'clientRowId'));
    return id.ok ? id.value : null;
  });
  // UUID spelling remains untouched; case differences still identify the same UUID.
  const counts = new Map<string, number>();
  for (const id of ids) if (id !== null) counts.set(id.toLowerCase(), (counts.get(id.toLowerCase()) ?? 0) + 1);
  submittedRows.forEach((value, rowIndex) => {
    const result = parseRow(value, rowIndex);
    const issues = result.ok ? [] : [...result.errors];
    const clientRowId = ids[rowIndex];
    if (clientRowId !== null && (counts.get(clientRowId.toLowerCase()) ?? 0) > 1) {
      issues.push(fieldError(['rows', rowIndex, 'clientRowId'], 'duplicate_row_id', 'Row ID must be unique within the batch.'));
    }
    if (issues.length) rowErrors.push({ rowIndex, clientRowId, errors: issues });
    else if (result.ok) validRows.push(result.value);
  });
  return { source: 'manualEntry', validRows, rowErrors, errors };
}

export function previewManualDrafts(input: unknown): ManualDraftPreview {
  return preview(input, ['source', 'rows']);
}

export function parseManualDraftInput(input: unknown): ValidationResult<ManualDraftInput> {
  const result = previewManualDrafts(input);
  const errors = [...result.errors, ...result.rowErrors.flatMap(row => row.errors)];
  return errors.length ? { ok: false, errors } : { ok: true, value: { source: 'manualEntry', rows: result.validRows } };
}

/** Only the exact confirmed row values/IDs and lesson base version are represented. */
export function parseConfirmedManualDraftBatch(input: unknown): ValidationResult<ConfirmedManualDraftBatch> {
  const result = preview(input, ['source', 'rows', 'lessonId', 'lessonBaseVersion']);
  const { record } = inspectObject(input, ['source', 'rows', 'lessonId', 'lessonBaseVersion']);
  const errors = [...result.errors, ...result.rowErrors.flatMap(row => row.errors)];
  if (!record) return { ok: false, errors };
  const lessonId = parseUuid(ownField(record, 'lessonId'), ['lessonId']);
  const lessonBaseVersion = parseVersion(ownField(record, 'lessonBaseVersion'), ['lessonBaseVersion']);
  errors.push(...validationErrors(lessonId, lessonBaseVersion));
  if (!lessonId.ok || !lessonBaseVersion.ok || errors.length) return { ok: false, errors };
  return { ok: true, value: { source: 'manualEntry', rows: result.validRows, lessonId: lessonId.value, lessonBaseVersion: lessonBaseVersion.value } };
}
