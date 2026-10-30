import { describe, expect, it, vi } from 'vitest';
import { absentMemoryNote, parseMemoryNote, parseMemoryNoteReceipt, parseMemoryNoteWrite } from '../../src/contracts/notes';
import { formatVersionETag } from '../../src/contracts/common';

const itemId = '00a2ab2c-b924-43e0-bde0-2ba8429a7593';
const anchor = 'e137a434-e83e-4bdc-ab2c-d1c4555384c1';
const note = { state: 'existing', itemId, body: '  覚える: giữ nguyên dấu  ', anchoredItemRevisionId: anchor, noteVersion: 3 };
const write = { itemId, body: note.body, anchoredItemRevisionId: anchor, expectedNoteVersion: 3 };

describe('memory note contracts', () => {
  it('represents absence without fabricating a persisted anchor or mutation', () => {
    const expected = { state: 'absent', itemId, body: '', anchoredItemRevisionId: null, noteVersion: 0 };
    expect(absentMemoryNote(itemId)).toEqual({ ok: true, value: expected });
    expect(parseMemoryNote(expected)).toEqual({ ok: true, value: expected });
    expect(formatVersionETag(0)).toEqual({ ok: true, value: '"v0"' });
    expect(absentMemoryNote('invalid').ok).toBe(false);
  });
  it('preserves existing note content, revision anchor and version independently', () => {
    expect(parseMemoryNote(Object.freeze(note))).toEqual({ ok: true, value: note });
    expect(parseMemoryNote({ ...note, body: '' }).ok).toBe(true);
  });
  it('accepts an empty-body clear and an expected version zero for create-if-absent', () => {
    expect(parseMemoryNoteWrite({ ...write, body: '', expectedNoteVersion: 0 })).toEqual({ ok: true, value: { itemId, body: '', anchoredItemRevisionId: anchor, expectedNoteVersion: 0 } });
  });
  it.each(['あ'.repeat(2000), '𠮷'.repeat(2000), `${'😀'.repeat(1999)}đ`])('counts Unicode code points rather than UTF16 units at the limit', body => {
    expect(parseMemoryNoteWrite({ ...write, body }).ok).toBe(true);
    expect(parseMemoryNote({ ...note, body }).ok).toBe(true);
  });
  it.each(['あ'.repeat(2001), '𠮷'.repeat(2001), `${'😀'.repeat(2000)}đ`])('rejects 2001 Unicode code points without truncation', body => {
    const value = Object.freeze({ ...write, body });
    const result = parseMemoryNoteWrite(value);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors).toContainEqual(expect.objectContaining({ path: ['body'], code: 'too_long' }));
    expect(value.body).toBe(body);
    expect(parseMemoryNote({ ...note, body }).ok).toBe(false);
  });
  it('rejects an oversized astral note after reading only the first 2001 code points', () => {
    const body = `${'𠮷'.repeat(2001)}đ`;
    const nativeIterator = String.prototype[Symbol.iterator];
    let codePointsRead = 0;
    const iterator = vi.spyOn(String.prototype, Symbol.iterator).mockImplementation(function* (this: string): Generator<string, undefined, unknown> {
      for (const codePoint of nativeIterator.call(this)) {
        codePointsRead += 1;
        yield codePoint;
      }
      return undefined;
    });
    try {
      const result = parseMemoryNoteWrite(Object.freeze({ ...write, body }));
      expect(result).toEqual({ ok: false, errors: [expect.objectContaining({ path: ['body'], code: 'too_long' })] });
      expect(codePointsRead).toBe(2001);
      expect(body).toBe(`${'𠮷'.repeat(2001)}đ`);
    } finally {
      iterator.mockRestore();
    }
  });
  it.each([
    null, [], { ...note, itemId: 1 }, { ...note, body: null }, { ...note, anchoredItemRevisionId: 'r1' },
    { ...note, noteVersion: 0 }, { ...note, noteVersion: 0.1 }, { ...note, noteVersion: Number.MAX_SAFE_INTEGER + 1 },
    { ...note, answerKey: 'private' }, { ...note, state: 'absent' },
    { ...note, state: 'absent', body: '', noteVersion: 0 },
  ])('returns explicit errors for invalid note representations: %j', value => {
    expect(parseMemoryNote(value).ok).toBe(false);
  });
  it.each([
    null, {}, { ...write, itemId: 'item-1' }, { ...write, body: 0 },
    { ...write, expectedNoteVersion: -1 }, { ...write, expectedNoteVersion: '3' },
    { ...write, expectedNoteVersion: undefined }, { ...write, noteVersion: 3 },
    { ...write, anchoredItemRevisionId: 'revision-1' }, { ...write, anchoredItemRevisionId: undefined }, { ...write, ownerId: itemId },
  ])('rejects malformed writes, missing or invalid anchor preconditions and protected fields: %j', value => {
    expect(parseMemoryNoteWrite(value).ok).toBe(false);
  });
  it('returns a fresh parsed write and retains original text and anchor in caller data', () => {
    const input = Object.freeze(write);
    const result = parseMemoryNoteWrite(input);
    expect(result).toEqual({ ok: true, value: write });
    if (result.ok) expect(result.value).not.toBe(input);
    expect(note.anchoredItemRevisionId).toBe(anchor);
  });
  it('validates a safe acknowledgement without reusable note text', () => {
    const receipt = { itemId, anchoredItemRevisionId: anchor, noteVersion: 4 };
    expect(parseMemoryNoteReceipt(receipt)).toEqual({ ok: true, value: receipt });
    expect(parseMemoryNoteReceipt({ ...receipt, body: 'protected cue' }).ok).toBe(false);
    expect(parseMemoryNoteReceipt({ ...receipt, noteVersion: 0 }).ok).toBe(false);
    expect(parseMemoryNoteReceipt({ ...receipt, anchoredItemRevisionId: 'revision-4' }).ok).toBe(false);
    expect(parseMemoryNoteReceipt({ ...receipt, itemId: 'invalid' }).ok).toBe(false);
  });
});
