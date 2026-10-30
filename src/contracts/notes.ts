import { fieldError, inspectObject, ownField, parseText, parseUuid, parseVersion, validationErrors } from './common';
import type { FieldPath, Uuid, ValidationResult } from './common';

/** The absent representation is a read projection, not a stored revision or mutation. */
export interface AbsentMemoryNote {
  readonly state: 'absent';
  readonly itemId: Uuid;
  readonly body: '';
  readonly anchoredItemRevisionId: null;
  readonly noteVersion: 0;
}
export interface ExistingMemoryNote {
  readonly state: 'existing';
  readonly itemId: Uuid;
  readonly body: string;
  readonly anchoredItemRevisionId: Uuid;
  readonly noteVersion: number;
}
export type MemoryNote = AbsentMemoryNote | ExistingMemoryNote;

/** Both preconditions are explicit; a later command must check them atomically. */
export interface MemoryNoteWrite {
  readonly itemId: Uuid;
  readonly body: string;
  readonly anchoredItemRevisionId: Uuid;
  readonly expectedNoteVersion: number;
}
/** A safe acknowledgement contains no reusable protected note body. */
export interface MemoryNoteReceipt {
  readonly itemId: Uuid;
  readonly anchoredItemRevisionId: Uuid;
  readonly noteVersion: number;
}

function parseBody(input: unknown): ValidationResult<string> {
  const text = parseText(input, ['body'], true);
  if (!text.ok) return text;
  let codePoints = 0;
  for (const _codePoint of text.value) {
    if (++codePoints > 2000) {
      return { ok: false, errors: [fieldError(['body'], 'too_long', 'Memory note must be at most 2000 Unicode code points.')] };
    }
  }
  return text;
}

function parseStoredVersion(input: unknown, path: FieldPath): ValidationResult<number> {
  const result = parseVersion(input, path);
  if (result.ok && result.value === 0) return { ok: false, errors: [fieldError(path, 'invalid_version', 'Existing notes require a positive version.')] };
  return result;
}

export function absentMemoryNote(itemId: unknown): ValidationResult<AbsentMemoryNote> {
  const id = parseUuid(itemId, ['itemId']);
  return id.ok ? { ok: true, value: { state: 'absent', itemId: id.value, body: '', anchoredItemRevisionId: null, noteVersion: 0 } } : id;
}

export function parseMemoryNote(input: unknown): ValidationResult<MemoryNote> {
  const { record, errors: objectErrors } = inspectObject(input, ['state', 'itemId', 'body', 'anchoredItemRevisionId', 'noteVersion']);
  if (!record) return { ok: false, errors: objectErrors };
  const itemId = parseUuid(ownField(record, 'itemId'), ['itemId']);
  const body = parseBody(ownField(record, 'body'));
  const state = ownField(record, 'state');
  const errors = [...objectErrors, ...validationErrors(itemId, body)];
  if (state === 'absent') {
    if (ownField(record, 'body') !== '') errors.push(fieldError(['body'], 'invalid_value', 'An absent note has an empty body.'));
    if (ownField(record, 'noteVersion') !== 0) errors.push(fieldError(['noteVersion'], 'invalid_version', 'An absent note has version zero.'));
    if (ownField(record, 'anchoredItemRevisionId') !== null) errors.push(fieldError(['anchoredItemRevisionId'], 'invalid_value', 'An absent note has no anchor.'));
    if (!itemId.ok || !body.ok || errors.length) return { ok: false, errors };
    return absentMemoryNote(itemId.value);
  }
  if (state !== 'existing') errors.push(fieldError(['state'], 'invalid_value', 'Expected absent or existing note state.'));
  const anchor = parseUuid(ownField(record, 'anchoredItemRevisionId'), ['anchoredItemRevisionId']);
  const noteVersion = parseStoredVersion(ownField(record, 'noteVersion'), ['noteVersion']);
  errors.push(...validationErrors(anchor, noteVersion));
  if (!itemId.ok || !body.ok || !anchor.ok || !noteVersion.ok || errors.length) return { ok: false, errors };
  return { ok: true, value: { state: 'existing', itemId: itemId.value, body: body.value, anchoredItemRevisionId: anchor.value, noteVersion: noteVersion.value } };
}

export function parseMemoryNoteWrite(input: unknown): ValidationResult<MemoryNoteWrite> {
  const { record, errors: objectErrors } = inspectObject(input, ['itemId', 'body', 'anchoredItemRevisionId', 'expectedNoteVersion']);
  if (!record) return { ok: false, errors: objectErrors };
  const itemId = parseUuid(ownField(record, 'itemId'), ['itemId']);
  const body = parseBody(ownField(record, 'body'));
  const anchor = parseUuid(ownField(record, 'anchoredItemRevisionId'), ['anchoredItemRevisionId']);
  const expectedNoteVersion = parseVersion(ownField(record, 'expectedNoteVersion'), ['expectedNoteVersion']);
  const errors = [...objectErrors, ...validationErrors(itemId, body, anchor, expectedNoteVersion)];
  if (!itemId.ok || !body.ok || !anchor.ok || !expectedNoteVersion.ok || errors.length) return { ok: false, errors };
  return { ok: true, value: { itemId: itemId.value, body: body.value, anchoredItemRevisionId: anchor.value, expectedNoteVersion: expectedNoteVersion.value } };
}

export function parseMemoryNoteReceipt(input: unknown): ValidationResult<MemoryNoteReceipt> {
  const { record, errors: objectErrors } = inspectObject(input, ['itemId', 'anchoredItemRevisionId', 'noteVersion']);
  if (!record) return { ok: false, errors: objectErrors };
  const itemId = parseUuid(ownField(record, 'itemId'), ['itemId']);
  const anchor = parseUuid(ownField(record, 'anchoredItemRevisionId'), ['anchoredItemRevisionId']);
  const noteVersion = parseStoredVersion(ownField(record, 'noteVersion'), ['noteVersion']);
  const errors = [...objectErrors, ...validationErrors(itemId, anchor, noteVersion)];
  if (!itemId.ok || !anchor.ok || !noteVersion.ok || errors.length) return { ok: false, errors };
  return { ok: true, value: { itemId: itemId.value, anchoredItemRevisionId: anchor.value, noteVersion: noteVersion.value } };
}
