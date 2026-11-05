import { describe, expect, it } from 'vitest';
import { classifyAnswerInput, normalizeAnswer } from '../../src/domain/learning/normalizeAnswer';

describe('answer input, without semantic grading or evidence side effects', () => {
  it('retains raw text while trimming and canonically composing the comparison', () => {
    expect(normalizeAnswer('  は\u3099ん  ', 'kana')).toEqual({ rawAnswer: '  は\u3099ん  ', comparisonForm: 'ばん' });
    expect(normalizeAnswer('  ca\u0300 phe\u0302  ', 'meaning')).toEqual({ rawAnswer: '  ca\u0300 phe\u0302  ', comparisonForm: 'cà phê' });
  });

  it.each([
    ['きやく', 'きゃく'], ['きて', 'きって'], ['びよう', 'びょう'],
    ['おう', 'おお'], ['じ', 'ぢ'], ['ず', 'づ'], ['は', 'ば'],
    ['カナ', 'かな'], ['ｶﾅ', 'カナ'], ['コー', 'コウ'],
  ])('preserves the distinction between %s and %s', (first, second) => {
    expect(normalizeAnswer(first, 'kana').comparisonForm).not.toBe(normalizeAnswer(second, 'kana').comparisonForm);
  });

  it.each(['きやく', 'きゃく', 'おう', 'おお', 'ば', 'ぱ', 'きて', 'きって', 'カタカナ', 'スーパー', 'ｶﾞ', 'ﾊﾟ'])('accepts valid kana %s without judging correctness', raw => {
    expect(classifyAnswerInput(raw, 'kana')).toEqual({ accepted: true, rawAnswer: raw, comparisonForm: raw });
  });

  it.each(['', ' \n\t '])('rejects empty text for all abilities', raw => {
    for (const ability of ['meaning', 'kana', 'kanji'] as const) {
      expect(classifyAnswerInput(raw, ability, ['a', 'b'])).toEqual({ accepted: false, reason: 'empty' });
    }
  });

  it.each([null, undefined, 42, {}, ['かな']])('rejects non-string input without coercing %j', raw => {
    for (const ability of ['meaning', 'kana', 'kanji'] as const) {
      expect(classifyAnswerInput(raw, ability, ['a', 'b'])).toEqual({ accepted: false, reason: 'wrong_input_type' });
    }
  });

  it.each(['かな', 'カナ', 'かな。', 'かな カナ', 'ｶﾅ'])('rejects kana-only meaning input %s', raw => {
    expect(classifyAnswerInput(raw, 'meaning')).toEqual({ accepted: false, reason: 'wrong_input_type' });
  });

  it.each(['xem lại', 'ca phe', '準備', '123', 'かな tiếng Việt'])('does not guess semantic validity of non-kana-only meaning %s', raw => {
    expect(classifyAnswerInput(raw, 'meaning').accepted).toBe(true);
  });

  it.each(['n', 'かn', 'konnichiha', 'tiếng Việt', 'かな1', '今日', 'かな。', 'か な', 'ー', '\u3099', 'か\u3099\u3099', 'ｶﾞﾞ', 'かﾞ', 'カーﾞ'])('rejects incompatible or unfinished kana %s', raw => {
    expect(classifyAnswerInput(raw, 'kana')).toEqual({ accepted: false, reason: 'invalid_kana' });
  });

  it('confirms only the exact caller-supplied choice identity and preserves its raw value', () => {
    expect(classifyAnswerInput('a', 'kanji', ['a', 'b'])).toEqual({ accepted: true, rawAnswer: 'a', comparisonForm: 'a' });
    for (const raw of [' a ', 'A', '準備', '__proto__', 'c']) {
      expect(classifyAnswerInput(raw, 'kanji', ['a', 'b'])).toEqual({ accepted: false, reason: 'invalid_choice' });
    }
    expect(classifyAnswerInput('a', 'kanji')).toEqual({ accepted: false, reason: 'invalid_choice' });
  });

  it('bounds work before processing giant text', () => {
    expect(classifyAnswerInput('あ'.repeat(16_385), 'kana')).toEqual({ accepted: false, reason: 'too_long' });
    expect(() => normalizeAnswer('a'.repeat(16_385), 'meaning')).toThrow(RangeError);
  });

  it('rejects unknown abilities rather than guessing a fallback format', () => {
    expect(() => normalizeAnswer('かな', 'other' as 'kana')).toThrow(TypeError);
    expect(() => classifyAnswerInput('かな', 'other' as 'kana')).toThrow(TypeError);
  });
});
