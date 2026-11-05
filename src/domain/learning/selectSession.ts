/** Internal pure selection types, not authenticated transport or persistence contracts. */
export type LearningAbility = 'meaning' | 'kana' | 'kanji';
export interface ChoiceOption { readonly optionId: string; readonly label: string }
export type QuestionMaterial =
  | { readonly ability: 'meaning' | 'kana'; readonly prompt: string; readonly reviewed: boolean; readonly inputKind: 'text' }
  | { readonly ability: 'kanji'; readonly prompt: string; readonly reviewed: boolean; readonly inputKind: 'choice'; readonly options: readonly ChoiceOption[] };
export interface LearningItemSnapshot {
  readonly itemId: string;
  readonly itemRevisionId: string;
  readonly lessonId: string;
  readonly state: 'approved' | 'draft' | 'disputed';
  readonly sourceRevisions: readonly { readonly sourceRevisionId: string; readonly state: 'valid' | 'disputed' | 'unavailable' }[];
  readonly studiedAbilities: readonly LearningAbility[];
  readonly materials: readonly QuestionMaterial[];
}
export interface SessionSelectionInput {
  readonly items: readonly LearningItemSnapshot[];
  readonly selectedItemIds: readonly string[];
  readonly abilities: readonly LearningAbility[];
  readonly order: 'selection' | 'source' | 'random';
  /** Caller computes source/random order; must be a permutation of selectedItemIds. */
  readonly orderedItemIds?: readonly string[];
  readonly questionLimit?: number;
}
export interface SelectedQuestion {
  readonly itemId: string;
  readonly itemRevisionId: string;
  readonly lessonId: string;
  readonly sourceRevisionIds: readonly string[];
  readonly ability: LearningAbility;
  readonly prompt: string;
  readonly inputKind: 'text' | 'choice';
  readonly options?: readonly ChoiceOption[];
}
export type SelectionExclusionReason = 'missing_item' | 'not_approved' | 'disputed_item' | 'unavailable_source' | 'disputed_source' | 'unavailable_material' | 'unreviewed_material' | 'insufficient_choices' | 'invalid_choices' | 'question_limit';
export interface SelectionExclusion { readonly itemId: string; readonly ability?: LearningAbility; readonly reason: SelectionExclusionReason }
export interface SessionSelection {
  readonly questions: readonly SelectedQuestion[];
  readonly exclusions: readonly SelectionExclusion[];
  readonly counts: {
    readonly selectedItems: number;
    readonly availableItems: number;
    /** Existing learning coverage only; never a mastery or correctness percentage. */
    readonly studiedItems: number;
    readonly uniqueQuestionItems: number;
    readonly abilityQuestions: number;
  };
}
// Technical work bounds only. Larger libraries are narrowed by the caller before selection.
const MAX_ITEMS = 1_000;
const MAX_QUESTIONS = 3_000;
const ABILITIES: readonly LearningAbility[] = ['meaning', 'kana', 'kanji'];

function boundedArray(value: unknown, maximum: number, name: string): asserts value is readonly unknown[] {
  if (!Array.isArray(value)) throw new TypeError(`${name} must be an array`);
  if (value.length > maximum) throw new RangeError(`${name} exceeds technical bound`);
}
function text(value: unknown, name: string, maximum = 128): asserts value is string {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError(`${name} must be nonblank text`);
  if (value.length > maximum) throw new RangeError(`${name} exceeds technical text bound`);
}
function unique(values: readonly unknown[], name: string): void {
  if (new Set(values).size !== values.length) throw new TypeError(`${name} must be unique`);
}
function abilities(values: unknown, name: string): asserts values is readonly LearningAbility[] {
  boundedArray(values, 3, name);
  for (const value of values) {
    if (!ABILITIES.includes(value as LearningAbility)) throw new TypeError(`Unknown ${name}`);
  }
  unique(values, name);
}
function validateItem(item: LearningItemSnapshot): void {
  if (!item || typeof item !== 'object') throw new TypeError('Item snapshot must be an object');
  text(item.itemId, 'Item ID'); text(item.itemRevisionId, 'Item revision'); text(item.lessonId, 'Lesson ID');
  if (!['approved', 'draft', 'disputed'].includes(item.state)) throw new TypeError('Unknown item state');
  abilities(item.studiedAbilities, 'studied abilities');
  boundedArray(item.sourceRevisions, 100, 'Source revisions');
  for (const source of item.sourceRevisions) {
    if (!source || typeof source !== 'object') throw new TypeError('Source revision must be an object');
    text(source.sourceRevisionId, 'Source revision ID');
    if (!['valid', 'disputed', 'unavailable'].includes(source.state)) throw new TypeError('Unknown source state');
  }
  unique(item.sourceRevisions.map(source => source.sourceRevisionId), 'Source revision IDs');
  boundedArray(item.materials, 3, 'Question materials');
  for (const material of item.materials) {
    if (!material || typeof material !== 'object' || !ABILITIES.includes(material.ability)) throw new TypeError('Unknown material ability');
    text(material.prompt, 'Question prompt', 16_384);
    if (typeof material.reviewed !== 'boolean') throw new TypeError('Material review state must be explicit');
    if (material.ability === 'kanji') {
      if (material.inputKind !== 'choice') throw new TypeError('Kanji recognition requires choice material');
      boundedArray(material.options, 20, 'Choice options');
    } else if (material.inputKind !== 'text') throw new TypeError('Production material requires text input');
  }
  unique(item.materials.map(material => material.ability), 'Material abilities');
}

function itemExclusion(item: LearningItemSnapshot): SelectionExclusionReason | undefined {
  if (item.state === 'draft') return 'not_approved';
  if (item.state === 'disputed') return 'disputed_item';
  if (item.sourceRevisions.some(source => source.state === 'disputed')) return 'disputed_source';
  if (!item.sourceRevisions.length || item.sourceRevisions.some(source => source.state !== 'valid')) return 'unavailable_source';
}
function materialExclusion(material: QuestionMaterial | undefined): SelectionExclusionReason | undefined {
  if (!material) return 'unavailable_material';
  if (!material.reviewed) return 'unreviewed_material';
  if (material.inputKind !== 'choice') return;
  if (material.options.length < 2) return 'insufficient_choices';
  const ids = new Set<string>();
  const labels = new Set<string>();
  for (const option of material.options) {
    if (!option || typeof option.optionId !== 'string' || !option.optionId.trim() || option.optionId.length > 128 ||
      typeof option.label !== 'string' || !option.label.trim() || option.label.length > 16_384) return 'invalid_choices';
    const label = option.label.trim().normalize('NFC');
    if (ids.has(option.optionId) || labels.has(label)) return 'invalid_choices';
    ids.add(option.optionId); labels.add(label);
  }
}

/**
 * Select only explicit reviewed snapshots. No I/O, randomness, grading, scheduling or activation.
 * This projection carries no authorization/expiry/preview hash; the application must revalidate
 * source/item revisions at start and receipt time. Caller owns semantic choice validity.
 */
export function selectSession(input: SessionSelectionInput): SessionSelection {
  if (!input || typeof input !== 'object') throw new TypeError('Selection input must be an object');
  boundedArray(input.items, MAX_ITEMS, 'Item snapshots');
  boundedArray(input.selectedItemIds, MAX_ITEMS, 'Selected item IDs');
  for (const id of input.selectedItemIds) text(id, 'Selected item ID');
  unique(input.selectedItemIds, 'Selected item IDs');
  abilities(input.abilities, 'Selected abilities');
  if (!input.abilities.length) throw new TypeError('Select at least one ability');
  const limit = input.questionLimit ?? MAX_QUESTIONS;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_QUESTIONS) throw new RangeError('Invalid question limit');
  if (!['selection', 'source', 'random'].includes(input.order)) throw new TypeError('Unknown question order');
  let orderedIds = input.selectedItemIds;
  if (input.order !== 'selection') {
    boundedArray(input.orderedItemIds, MAX_ITEMS, 'Ordered item IDs');
    unique(input.orderedItemIds, 'Ordered item IDs');
    const selectedIds = new Set(input.selectedItemIds);
    if (input.orderedItemIds.length !== selectedIds.size) {
      throw new TypeError('Order must be an exact permutation of selected IDs');
    }
    for (const id of input.orderedItemIds) {
      if (!selectedIds.has(id as string)) throw new TypeError('Order must be an exact permutation of selected IDs');
    }
    orderedIds = input.orderedItemIds as readonly string[];
  } else if (input.orderedItemIds !== undefined) throw new TypeError('Selection order cannot specify another order');
  for (const item of input.items) validateItem(item);
  unique(input.items.map(item => item.itemId), 'Item snapshots');
  const byId = new Map(input.items.map(item => [item.itemId, item]));
  const questions: SelectedQuestion[] = [];
  const exclusions: SelectionExclusion[] = [];
  let availableItems = 0;
  let studiedItems = 0;
  for (const itemId of orderedIds) {
    const item = byId.get(itemId);
    const excluded = item ? itemExclusion(item) : 'missing_item';
    // Coverage is a separate historical count across selected snapshots, including affected ones.
    if (item?.studiedAbilities.length) studiedItems++;
    if (excluded || !item) { exclusions.push(Object.freeze({ itemId, reason: excluded ?? 'missing_item' })); continue; }
    availableItems++;
    for (const ability of input.abilities) {
      const material = item.materials.find(candidate => candidate.ability === ability);
      const reason = materialExclusion(material) ?? (questions.length >= limit ? 'question_limit' : undefined);
      if (reason || !material) { exclusions.push(Object.freeze({ itemId, ability, reason: reason ?? 'unavailable_material' })); continue; }
      questions.push(Object.freeze({
        itemId, itemRevisionId: item.itemRevisionId, lessonId: item.lessonId,
        sourceRevisionIds: Object.freeze(item.sourceRevisions.map(source => source.sourceRevisionId)),
        ability, prompt: material.prompt, inputKind: material.inputKind,
        ...(material.inputKind === 'choice' ? { options: Object.freeze(material.options.map(option => Object.freeze({ optionId: option.optionId, label: option.label }))) } : {}),
      }));
    }
  }
  return Object.freeze({
    questions: Object.freeze(questions), exclusions: Object.freeze(exclusions),
    counts: Object.freeze({ selectedItems: input.selectedItemIds.length, availableItems, studiedItems,
      uniqueQuestionItems: new Set(questions.map(question => question.itemId)).size, abilityQuestions: questions.length }),
  });
}
