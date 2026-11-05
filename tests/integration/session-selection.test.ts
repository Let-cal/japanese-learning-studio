import { describe, expect, it } from 'vitest';
import { selectSession, type LearningItemSnapshot, type SessionSelectionInput } from '../../src/domain/learning/selectSession';

const item = (id: string, overrides: Partial<LearningItemSnapshot> = {}): LearningItemSnapshot => ({
  itemId: id, itemRevisionId: `${id}-r1`, lessonId: 'lesson-one', state: 'approved',
  sourceRevisions: [{ sourceRevisionId: 'source-r1', state: 'valid' }], studiedAbilities: [],
  materials: [
    { ability: 'meaning', prompt: '見直す — 計画を見直します。', inputKind: 'text', reviewed: true },
    { ability: 'kana', prompt: '見直す', inputKind: 'text', reviewed: true },
    { ability: 'kanji', prompt: 'Choose the written form for みなおす (review).', inputKind: 'choice', reviewed: true, options: [{ optionId: 'review', label: '見直す' }, { optionId: 'continue', label: '続ける' }] },
  ], ...overrides,
});
const select = (items: readonly LearningItemSnapshot[], changes: Partial<SessionSelectionInput> = {}) => selectSession({
  items, selectedItemIds: items.map(value => value.itemId), abilities: ['meaning'], order: 'selection', ...changes,
});

describe('pure frozen session selection', () => {
  it('distinguishes 70 studied items out of 100 selected from 300 ability questions', () => {
    const items = Array.from({ length: 100 }, (_, index) => item(`item-${index}`, { studiedAbilities: index < 70 ? ['meaning'] : [] }));
    const result = select(items, { abilities: ['meaning', 'kana', 'kanji'] });
    expect(result.counts).toEqual({ selectedItems: 100, availableItems: 100, studiedItems: 70, uniqueQuestionItems: 100, abilityQuestions: 300 });
    expect(result.exclusions).toEqual([]);
    expect(new Set(result.questions.map(q => `${q.itemId}:${q.ability}`)).size).toBe(300);
    expect(items[99].studiedAbilities).toEqual([]);
  });

  it('preserves a small exact cross-lesson subset without filling from the rest of the library', () => {
    const result = select([item('a'), item('b', { lessonId: 'lesson-two' }), item('c')], { selectedItemIds: ['b', 'a'], abilities: ['kana', 'meaning'] });
    expect(result.questions.map(q => [q.itemId, q.lessonId, q.ability])).toEqual([
      ['b', 'lesson-two', 'kana'], ['b', 'lesson-two', 'meaning'], ['a', 'lesson-one', 'kana'], ['a', 'lesson-one', 'meaning'],
    ]);
    expect(result.counts.abilityQuestions).toBe(4);
  });

  it('reports unavailable, draft and disputed items with no replacement or activation', () => {
    const items = [item('draft', { state: 'draft' }), item('disputed', { state: 'disputed' }), item('missing-source', { sourceRevisions: [] }), item('unavailable', { sourceRevisions: [{ sourceRevisionId: 's2', state: 'unavailable' }] }), item('source-disputed', { sourceRevisions: [{ sourceRevisionId: 's3', state: 'disputed' }] }), item('valid')];
    const result = select(items, { selectedItemIds: ['not-found', ...items.map(value => value.itemId)] });
    expect(result.questions.map(q => q.itemId)).toEqual(['valid']);
    expect(result.exclusions).toEqual([
      { itemId: 'not-found', reason: 'missing_item' }, { itemId: 'draft', reason: 'not_approved' },
      { itemId: 'disputed', reason: 'disputed_item' }, { itemId: 'missing-source', reason: 'unavailable_source' },
      { itemId: 'unavailable', reason: 'unavailable_source' }, { itemId: 'source-disputed', reason: 'disputed_source' },
    ]);
    expect(result.counts).toEqual({ selectedItems: 7, availableItems: 1, studiedItems: 0, uniqueQuestionItems: 1, abilityQuestions: 1 });
    expect(items.every(value => value.studiedAbilities.length === 0)).toBe(true);
  });

  it('reduces insufficient choices and missing/unreviewed material explicitly', () => {
    const items = [item('one-choice', { materials: [{ ability: 'kanji', prompt: '認識', inputKind: 'choice', reviewed: true, options: [{ optionId: 'a', label: '見直す' }] }] }), item('missing', { materials: [] }), item('unreviewed', { materials: [{ ability: 'kanji', prompt: '認識', inputKind: 'choice', reviewed: false, options: [{ optionId: 'a', label: '見直す' }, { optionId: 'b', label: '続ける' }] }] }), item('two-choices')];
    const result = select(items, { abilities: ['kanji'] });
    expect(result.questions.map(q => q.itemId)).toEqual(['two-choices']);
    expect(result.questions[0].options).toHaveLength(2);
    expect(result.exclusions).toEqual([
      { itemId: 'one-choice', ability: 'kanji', reason: 'insufficient_choices' },
      { itemId: 'missing', ability: 'kanji', reason: 'unavailable_material' },
      { itemId: 'unreviewed', ability: 'kanji', reason: 'unreviewed_material' },
    ]);
  });

  it('does not create a choice question from duplicate option identities or labels', () => {
    for (const options of [
      [{ optionId: 'a', label: '見直す' }, { optionId: 'a', label: '続ける' }],
      [{ optionId: 'a', label: '見直す' }, { optionId: 'b', label: ' 見直す ' }],
    ]) {
      const result = select([item('a', { materials: [{ ability: 'kanji', prompt: '認識', inputKind: 'choice', reviewed: true, options }] })], { abilities: ['kanji'] });
      expect(result.questions).toEqual([]);
      expect(result.exclusions).toEqual([{ itemId: 'a', ability: 'kanji', reason: 'invalid_choices' }]);
    }
  });

  it.each(['source', 'random'] as const)('uses the exact injected %s order', order => {
    const result = select([item('a'), item('b'), item('c')], { order, orderedItemIds: ['c', 'a', 'b'], abilities: ['kana'] });
    expect(result.questions.map(q => q.itemId)).toEqual(['c', 'a', 'b']);
  });

  it('rejects duplicate and incomplete order permutations rather than silently repairing them', () => {
    for (const orderedItemIds of [undefined, ['a'], ['a', 'a'], ['a', 'c'], ['a', 'b', 'c']]) {
      expect(() => select([item('a'), item('b')], { order: 'random', orderedItemIds })).toThrow();
    }
  });

  it('rejects a hole in selected abilities instead of emitting an undefined ability exclusion', () => {
    const sparseAbilities = new Array<SessionSelectionInput['abilities'][number]>(1);
    expect(() => select([item('a')], { abilities: sparseAbilities })).toThrow(TypeError);
    expect(() => select([item('a', { studiedAbilities: sparseAbilities })])).toThrow(TypeError);
  });

  it.each(['source', 'random'] as const)('rejects a hole in injected %s order instead of emitting an undefined item identity', order => {
    const sparseOrder = new Array<string>(1);
    expect(() => select([item('a')], { order, orderedItemIds: sparseOrder })).toThrow(TypeError);
  });

  it('applies a requested question limit without silent padding or ability replacement', () => {
    const result = select([item('a'), item('b')], { abilities: ['kana', 'meaning'], questionLimit: 3 });
    expect(result.questions.map(q => [q.itemId, q.ability])).toEqual([['a', 'kana'], ['a', 'meaning'], ['b', 'kana']]);
    expect(result.exclusions).toEqual([{ itemId: 'b', ability: 'meaning', reason: 'question_limit' }]);
    expect(result.counts.abilityQuestions).toBe(3);
  });

  it('copies and freezes immutable revision associations and options without mutating caller content', () => {
    const input = item('a');
    const result = select([input], { abilities: ['kanji'] });
    expect(result.questions[0]).toEqual({ itemId: 'a', itemRevisionId: 'a-r1', lessonId: 'lesson-one', sourceRevisionIds: ['source-r1'], ability: 'kanji', prompt: 'Choose the written form for みなおす (review).', inputKind: 'choice', options: [{ optionId: 'review', label: '見直す' }, { optionId: 'continue', label: '続ける' }] });
    (input.sourceRevisions as { sourceRevisionId: string; state: 'valid' }[])[0].sourceRevisionId = 'changed';
    expect(result.questions[0].sourceRevisionIds).toEqual(['source-r1']);
    expect(Object.isFrozen(result.questions[0].options?.[0])).toBe(true);
    expect(Object.isFrozen(result.questions[0].sourceRevisionIds)).toBe(true);
    expect(Object.isFrozen(result.questions)).toBe(true);
    expect(Object.isFrozen(input)).toBe(false);
  });

  it('rejects duplicate inputs and unsafe technical sizes before building questions', () => {
    for (const changes of [
      { selectedItemIds: ['a', 'a'] }, { abilities: ['kana', 'kana'] as const },
      { abilities: [] }, { questionLimit: 0 }, { questionLimit: 1.5 },
      { questionLimit: 3001 }, { selectedItemIds: Array.from({ length: 1001 }, (_, index) => `i${index}`) },
    ]) expect(() => select([item('a')], changes)).toThrow();
    expect(() => select([item('a'), item('a')])).toThrow();
  });

  it('retains affected historical coverage without treating it as an eligible question', () => {
    const result = select([item('affected', { state: 'disputed', studiedAbilities: ['meaning'] })]);
    expect(result.counts).toEqual({ selectedItems: 1, availableItems: 0, studiedItems: 1, uniqueQuestionItems: 0, abilityQuestions: 0 });
    expect(result.questions).toEqual([]);
  });

  it('supports a genuinely empty selection without filling it', () => {
    expect(select([item('a')], { selectedItemIds: [] })).toEqual({
      questions: [], exclusions: [], counts: { selectedItems: 0, availableItems: 0, studiedItems: 0, uniqueQuestionItems: 0, abilityQuestions: 0 },
    });
  });

  it('rejects malformed snapshots and order modes without inventing revisions or formats', () => {
    for (const overrides of [
      { itemRevisionId: '' }, { sourceRevisions: [{ sourceRevisionId: '', state: 'valid' as const }] },
      { studiedAbilities: ['other'] as unknown as LearningItemSnapshot['studiedAbilities'] },
      { materials: [{ ability: 'kana', prompt: '見直す', reviewed: true, inputKind: 'choice' }] as unknown as LearningItemSnapshot['materials'] },
      { materials: [item('x').materials[0], item('x').materials[0]] },
    ]) expect(() => select([item('a', overrides)])).toThrow();
    expect(() => select([item('a')], { order: 'other' as 'selection' })).toThrow();
    expect(() => select([item('a')], { orderedItemIds: ['a'] })).toThrow();
  });
});
