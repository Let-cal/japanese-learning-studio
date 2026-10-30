import { describe, expect, it } from 'vitest';
import { parseConfirmedManualDraftBatch, parseManualDraftInput, previewManualDrafts } from '../../src/contracts/content';

const lessonId = 'd9834a49-ff2c-4945-808b-eb0346ed96d4';
const row = (n = 1) => ({ clientRowId: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, writtenForm: '  生  ', kana: 'せい・セイ', vietnameseSense: '  sự sống, sinh ra  ', context: '文脈: tiếng Việt đậm dấu' });
const input = (rows: unknown[]) => ({ source: 'manualEntry', rows });

describe('manual draft contracts', () => {
  it.each([1, 10])('accepts %s rows while preserving Japanese, Vietnamese, whitespace and context', count => {
    const value = input(Array.from({ length: count }, (_, i) => row(i + 1)));
    expect(parseManualDraftInput(value)).toEqual({ ok: true, value });
    expect(previewManualDrafts(value)).toMatchObject({ validRows: value.rows, rowErrors: [], errors: [] });
  });
  it.each([0, 11])('reports out-of-bounds row count %s', count => {
    const value = input(Array.from({ length: count }, (_, i) => row(i + 1)));
    expect(parseManualDraftInput(value).ok).toBe(false);
    expect(previewManualDrafts(value).errors).toEqual(expect.arrayContaining([expect.objectContaining({ code: 'invalid_row_count', path: ['rows'] })]));
  });
  it('rejects an oversized batch before accessing any row elements', () => {
    const rows = new Array(11);
    Object.defineProperty(rows, 0, { get() { throw new Error('Out-of-range rows must not be read.'); } });
    Object.freeze(rows);
    const value = Object.freeze(input(rows));
    expect(previewManualDrafts(value)).toEqual({
      source: 'manualEntry', validRows: [], rowErrors: [],
      errors: [expect.objectContaining({ code: 'invalid_row_count', path: ['rows'] })],
    });
    expect(parseManualDraftInput(value).ok).toBe(false);
    expect(parseConfirmedManualDraftBatch({ ...value, lessonId, lessonBaseVersion: 0 }).ok).toBe(false);
  });
  it('keeps valid rows and reports invalid text by row without discarding the input', () => {
    const valid = Object.freeze(row());
    const invalid = Object.freeze({ ...row(2), kana: '  ', vietnameseSense: 123 });
    const value = Object.freeze({ source: 'manualEntry', rows: Object.freeze([valid, invalid, null]) });
    const preview = previewManualDrafts(value);
    expect(preview.validRows).toEqual([row()]);
    expect(preview.rowErrors).toEqual([
      expect.objectContaining({ rowIndex: 1, clientRowId: row(2).clientRowId, errors: expect.arrayContaining([
        expect.objectContaining({ path: ['rows', 1, 'kana'] }), expect.objectContaining({ path: ['rows', 1, 'vietnameseSense'] }),
      ]) }),
      expect.objectContaining({ rowIndex: 2, clientRowId: null }),
    ]);
    expect(value.rows[1]).toBe(invalid);
    expect(invalid.kana).toBe('  ');
    expect(parseManualDraftInput(value).ok).toBe(false);
  });
  it('marks every occurrence of a duplicate stable row ID invalid rather than deduplicating', () => {
    const preview = previewManualDrafts(input([row(), row(), row(3)]));
    expect(preview.validRows).toEqual([row(3)]);
    expect(preview.rowErrors.map(error => error.rowIndex)).toEqual([0, 1]);
    expect(preview.rowErrors.every(error => error.errors.some(issue => issue.code === 'duplicate_row_id'))).toBe(true);
  });
  it('reports a missing sparse-array row as invalid input rather than throwing or silently skipping it', () => {
    const preview = previewManualDrafts(input(new Array(1)));
    expect(preview.validRows).toEqual([]);
    expect(preview.rowErrors).toEqual([expect.objectContaining({ rowIndex: 0, clientRowId: null })]);
    expect(parseManualDraftInput(input(new Array(1))).ok).toBe(false);
  });
  it.each(['writtenForm', 'kana', 'vietnameseSense'])('rejects blank required field %s', field => {
    expect(parseManualDraftInput(input([{ ...row(), [field]: '\n\t  ' }])).ok).toBe(false);
  });
  it('accepts optional empty context and does not invent linguistic constraints or hidden length limits', () => {
    expect(parseManualDraftInput(input([{ ...row(), context: '' }])).ok).toBe(true);
    const { context: _context, ...withoutContext } = row();
    expect(parseManualDraftInput(input([withoutContext])).ok).toBe(true);
    expect(parseManualDraftInput(input([{ ...row(), writtenForm: 'VI khác', kana: 'カナかながガ', vietnameseSense: 'đ'.repeat(3000) }])).ok).toBe(true);
  });
  it.each([
    null, [], { rows: [row()] }, { source: 'imagePage', rows: [row()] },
    { ...input([row()]), answerKey: 'private' }, input([{ ...row(), approved: true }]),
    input([{ ...row(), sourcePageId: lessonId }]), input([{ ...row(), context: null }]),
    input([{ ...row(), clientRowId: 'row-1' }]),
  ])('rejects unexpected/private fields, invalid provenance and field types: %j', value => {
    expect(parseManualDraftInput(value).ok).toBe(false);
  });
  it('copies accepted rows so editing the result cannot change submitted text', () => {
    const submitted = input([row()]);
    const preview = previewManualDrafts(submitted);
    expect(preview.validRows[0]).not.toBe(submitted.rows[0]);
    expect(preview.validRows).not.toBe(submitted.rows);
  });
  it('retains exact confirmed rows, stable IDs and the lesson base version including zero', () => {
    const value = { ...input([row()]), lessonId, lessonBaseVersion: 0 };
    const result = parseConfirmedManualDraftBatch(Object.freeze(value));
    expect(result).toEqual({ ok: true, value });
    if (result.ok) expect(result.value.rows[0]).not.toBe(value.rows[0]);
  });
  it.each([
    { lessonId: 'invalid' }, { lessonBaseVersion: -1 }, { lessonBaseVersion: '0' },
    { lessonBaseVersion: undefined }, { approved: true }, { itemRevisionId: lessonId },
    { rows: [row(), row()] },
  ])('rejects invalid confirmed batches: %j', override => {
    expect(parseConfirmedManualDraftBatch({ ...input([row()]), lessonId, lessonBaseVersion: 0, ...override }).ok).toBe(false);
  });
});
