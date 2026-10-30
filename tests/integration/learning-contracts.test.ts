import { describe, expect, it } from 'vitest';
import { SessionEventInputSchema, SafeExecutionSchema } from '../../src/contracts/learning';
const id = '11111111-1111-4111-8111-111111111111';
describe('learning transport boundaries', () => {
  it('accepts typed events without trusting client assistance or authority', () => {
    expect(SessionEventInputSchema.parse({ kind: 'answer', questionId: id, rawAnswer: '  きょう\u3099  ' })).toEqual({ kind: 'answer', questionId: id, rawAnswer: '  きょう\u3099  ' });
    for (const extra of [{ assisted: false }, { ownerId: id }, { expectedExecutionVersion: 1 }, { correctAnswer: '今日' }]) {
      expect(SessionEventInputSchema.safeParse({ kind: 'answer', questionId: id, rawAnswer: '今日', ...extra }).success).toBe(false);
    }
    expect(SessionEventInputSchema.safeParse({ kind: 'finish', questionId: id }).success).toBe(false);
  });
  it('never accepts answer-bearing execution DTO fields', () => {
    const safe = { sessionId: id, executionVersion: 1, mode: 'test', status: 'paused', question: { questionId: id, itemId: id, ability: 'kana', prompt: '今日', inputKind: 'text' } };
    expect(SafeExecutionSchema.safeParse(safe).success).toBe(true);
    for (const extra of [{ ruby: 'きょう' }, { correctOptionId: id }, { referenceUrl: 'https://example.com' }]) {
      expect(SafeExecutionSchema.safeParse({ ...safe, question: { ...safe.question, ...extra } }).success).toBe(false);
    }
    expect(SafeExecutionSchema.safeParse({ ...safe, executionVersion: Number.MAX_SAFE_INTEGER + 1 }).success).toBe(false);
  });
});
