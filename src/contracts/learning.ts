import { z } from 'zod';

// Match existing opaque UUID syntax without introducing normalization or authorization.
export const UuidSchema = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
export const VersionSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
export const StoredVersionSchema = VersionSchema.min(1);
export const UtcInstantSchema = z.iso.datetime({ offset: false });
export const AbilitySchema = z.enum(['meaning', 'kana', 'kanji']);
export const LearningModeSchema = z.enum(['practice', 'test']);
export const SessionStatusSchema = z.enum(['active', 'paused', 'finished']);

/** Transport body only. Route ID and If-Match are merged by the future authenticated BFF. */
export const SessionEventInputSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('answer'), questionId: UuidSchema, rawAnswer: z.string() }),
  z.strictObject({ kind: z.literal('help'), questionId: UuidSchema }),
  z.strictObject({ kind: z.literal('modeChanged'), questionId: UuidSchema, mode: LearningModeSchema }),
  z.strictObject({ kind: z.literal('next'), questionId: UuidSchema }),
  z.strictObject({ kind: z.literal('skip'), questionId: UuidSchema }),
  z.strictObject({ kind: z.literal('pause') }),
  z.strictObject({ kind: z.literal('resume') }),
  z.strictObject({ kind: z.literal('finish') }),
]);
const SafeQuestionSchema = z.strictObject({
  questionId: UuidSchema, itemId: UuidSchema, ability: AbilitySchema, prompt: z.string(),
  inputKind: z.enum(['text', 'choice']),
  options: z.array(z.strictObject({ optionId: UuidSchema, label: z.string() })).min(2).optional(),
});
/** Keys, ruby, correctness markers and media/reference URLs are absent even in paused Test DTOs. */
export const SafeExecutionSchema = z.strictObject({
  sessionId: UuidSchema, executionVersion: StoredVersionSchema, mode: LearningModeSchema,
  status: SessionStatusSchema, question: SafeQuestionSchema.nullable(),
});
export const SessionEventReceiptSchema = z.strictObject({ sessionId: UuidSchema, eventId: UuidSchema, executionVersion: StoredVersionSchema });
export type LearningMode = z.infer<typeof LearningModeSchema>;
export type SessionStatus = z.infer<typeof SessionStatusSchema>;
export type SessionEventInput = z.infer<typeof SessionEventInputSchema>;
export type SafeExecution = z.infer<typeof SafeExecutionSchema>;
export type SessionEventReceipt = z.infer<typeof SessionEventReceiptSchema>;
