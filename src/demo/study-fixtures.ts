import { sampleWords } from './fixtures';
import type { LearningAbility, LearningItemSnapshot, SelectedQuestion } from '@/domain/learning/selectSession';

// Fixed identities bridge only the four original public examples. These are not personal records.
export const sampleStudyWords = sampleWords.map((word, index) => ({
  ...word,
  itemId: `10000000-0000-4000-8000-00000000000${index + 1}`,
  itemRevisionId: `20000000-0000-4000-8000-00000000000${index + 1}`,
  sourceRevisionId: `30000000-0000-4000-8000-00000000000${index + 1}`,
}));
export const sampleAbilities: readonly LearningAbility[] = ['meaning', 'kana', 'kanji'];
export const abilityLabels: Record<LearningAbility, string> = { meaning: 'Meaning', kana: 'Kana', kanji: 'Kanji' };

export function sampleSnapshots(selectedItemIds: readonly string[]): LearningItemSnapshot[] {
  const options = sampleStudyWords.filter(word => selectedItemIds.includes(word.itemId))
    .map(word => ({ optionId: word.itemId, label: word.word }));
  return sampleStudyWords.map(word => ({
    itemId: word.itemId, itemRevisionId: word.itemRevisionId,
    lessonId: '40000000-0000-4000-8000-000000000001', state: 'approved',
    sourceRevisions: [{ sourceRevisionId: word.sourceRevisionId, state: 'valid' }],
    studiedAbilities: [],
    materials: [
      { ability: 'meaning', prompt: `${word.word} — ${word.context}`, reviewed: true, inputKind: 'text' },
      { ability: 'kana', prompt: `${word.word} — ${word.context}`, reviewed: true, inputKind: 'text' },
      { ability: 'kanji', prompt: `${word.kana} — ${word.meaning}`, reviewed: true, inputKind: 'choice', options },
    ],
  }));
}

// Public sample keys are deliberately separate from selection/question snapshots. No AI grading.
const meaningKeys: Readonly<Record<string, readonly string[]>> = {
  review: ['xem lại', 'cân nhắc lại', 'xem lại; cân nhắc lại'],
  continue: ['tiếp tục'], prepare: ['sự chuẩn bị', 'chuẩn bị'], rest: ['nghỉ giải lao'],
};
export type SampleVerdict = 'matched' | 'incorrect' | 'pending';
export interface SampleAnswer {
  readonly questionIndex: number;
  readonly rawAnswer: string;
  readonly comparisonForm: string;
  readonly verdict: SampleVerdict;
  readonly assisted: boolean;
}
export function sampleKey(question: SelectedQuestion): string {
  const word = sampleStudyWords.find(word => word.itemId === question.itemId)!;
  return question.ability === 'meaning' ? word.meaning : question.ability === 'kana' ? word.kana : word.word;
}
export function gradeSample(question: SelectedQuestion, comparisonForm: string): SampleVerdict {
  const word = sampleStudyWords.find(word => word.itemId === question.itemId)!;
  if (question.ability === 'meaning') return meaningKeys[word.id].includes(comparisonForm) ? 'matched' : 'pending';
  return comparisonForm === (question.ability === 'kana' ? word.kana : word.itemId) ? 'matched' : 'incorrect';
}

export function shuffleSampleIds(ids: readonly string[]): string[] {
  const ordered = [...ids];
  for (let index = ordered.length - 1; index > 0; index--) {
    const target = Math.floor(Math.random() * (index + 1));
    [ordered[index], ordered[target]] = [ordered[target], ordered[index]];
  }
  return ordered;
}
