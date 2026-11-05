import type { LearningAbility } from './selectSession';

export interface NormalizedAnswer { readonly rawAnswer: string; readonly comparisonForm: string }
export type AnswerInputRejection = 'empty' | 'wrong_input_type' | 'invalid_kana' | 'invalid_choice' | 'too_long';
export type AnswerInputClassification =
  | ({ readonly accepted: true } & NormalizedAnswer)
  | { readonly accepted: false; readonly reason: AnswerInputRejection };

// Technical work bound, not a linguistic length rule. Check before normalization/regex work.
const MAX_ANSWER_CODE_UNITS = 16_384;
const KANA_ONLY_MEANING = /^[\p{Script=Hiragana}\p{Script=Katakana}\u30fc\uff70\u3099\u309a\uff9e\uff9f\p{P}\p{Z}\s]+$/u;
const HAS_KANA = /[\p{Script=Hiragana}\p{Script=Katakana}]/u;
// No transliteration, compatibility folding, space removal or phonetic equivalence.
const KANA_STRING = /^(?:[ぁ-ゖァ-ヺ]|[ｦ-ﾝ][ﾞﾟ]?)(?:[ぁ-ゖァ-ヺーｰゝゞヽヾ]|[ｦ-ﾝ][ﾞﾟ]?)*$/u;

function assertAbility(ability: LearningAbility): void {
  if (ability !== 'meaning' && ability !== 'kana' && ability !== 'kanji') throw new TypeError('Unknown learning ability');
}

/** Text comparison form only. Never changes the original answer or decides correctness. */
export function normalizeAnswer(rawAnswer: string, ability: LearningAbility): NormalizedAnswer {
  assertAbility(ability);
  if (typeof rawAnswer !== 'string') throw new TypeError('Answer must be text');
  if (rawAnswer.length > MAX_ANSWER_CODE_UNITS) throw new RangeError('Answer exceeds technical text bound');
  return Object.freeze({ rawAnswer, comparisonForm: rawAnswer.trim().normalize('NFC') });
}

/** NT1 format check after IME completion; caller owns composition and immutable answer events. */
export function classifyAnswerInput(rawAnswer: unknown, ability: LearningAbility, validOptionIds?: readonly string[]): AnswerInputClassification {
  assertAbility(ability);
  if (typeof rawAnswer !== 'string') return Object.freeze({ accepted: false, reason: 'wrong_input_type' });
  if (rawAnswer.length > MAX_ANSWER_CODE_UNITS) return Object.freeze({ accepted: false, reason: 'too_long' });
  const normalized = normalizeAnswer(rawAnswer, ability);
  if (!normalized.comparisonForm) return Object.freeze({ accepted: false, reason: 'empty' });
  if (ability === 'kanji') {
    // Option identities are opaque: whitespace/script normalization must not select another ID.
    if (!validOptionIds || validOptionIds.length < 2 || validOptionIds.length > 20 ||
      new Set(validOptionIds).size !== validOptionIds.length || !validOptionIds.includes(rawAnswer)) {
      return Object.freeze({ accepted: false, reason: 'invalid_choice' });
    }
    return Object.freeze({ accepted: true, rawAnswer, comparisonForm: rawAnswer });
  }
  if (ability === 'kana' && !KANA_STRING.test(normalized.comparisonForm)) {
    return Object.freeze({ accepted: false, reason: 'invalid_kana' });
  }
  if (ability === 'meaning' && HAS_KANA.test(normalized.comparisonForm) && KANA_ONLY_MEANING.test(normalized.comparisonForm)) {
    return Object.freeze({ accepted: false, reason: 'wrong_input_type' });
  }
  return Object.freeze({ accepted: true, ...normalized });
}
