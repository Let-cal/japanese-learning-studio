import { z } from 'zod';
import { AbilitySchema, StoredVersionSchema, UtcInstantSchema, UuidSchema, VersionSchema } from './learning.ts';
const binding = { itemId: UuidSchema, ability: AbilitySchema, itemRevisionId: UuidSchema, sourceRevisionIds: z.array(UuidSchema).min(1), repairPolicyVersion: StoredVersionSchema };
const attempt = { kind: z.literal('attempt'), ...binding, sessionId: UuidSchema, questionId: UuidSchema, attemptId: UuidSchema, gradeRevisionId: UuidSchema };
const contentPractice = { kind: z.literal('contentPractice'), ...binding };
export const RepairOriginReferenceSchema = z.discriminatedUnion('kind', [z.strictObject(attempt), z.strictObject(contentPractice)]);
/** Server-resolved historical snapshot; never accept this as a client start payload. */
export const RepairOriginSchema = z.discriminatedUnion('kind', [
  z.strictObject({ ...attempt, ownerId: UuidSchema, datasetEpoch: UuidSchema, firstAnswer: z.string() }),
  z.strictObject({ ...contentPractice, ownerId: UuidSchema, datasetEpoch: UuidSchema }),
]);
export const RepairStartSchema = z.strictObject({ origin: RepairOriginReferenceSchema });
export const RepairEventBodySchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('understood') }),
  z.strictObject({ kind: z.literal('microcheckSubmitted'), rawAnswer: z.string() }),
  z.strictObject({ kind: z.literal('deferred') }),
  z.strictObject({ kind: z.literal('cancelled') }),
  z.strictObject({ kind: z.literal('recheckProposed'), requestedNotBefore: UtcInstantSchema }),
  z.strictObject({ kind: z.literal('recheckAccepted'), proposalId: UuidSchema }),
]);
/** Application input merges route ID + repair If-Match, never the origin Test version. */
export const RepairEventInputSchema = z.strictObject({ repairId: UuidSchema, expectedRepairVersion: VersionSchema, event: RepairEventBodySchema });
export const RepairReceiptSchema = z.strictObject({ repairId: UuidSchema, repairVersion: StoredVersionSchema, eventId: UuidSchema.optional() });
export const SafeRepairSchema = z.strictObject({ repairId: UuidSchema, repairVersion: StoredVersionSchema, origin: RepairOriginReferenceSchema, status: z.enum(['active', 'deferred', 'cancelled', 'completed', 'originAffected']) });
export type RepairOrigin = z.infer<typeof RepairOriginSchema>;
export type RepairStart = z.infer<typeof RepairStartSchema>;
export type RepairEventInput = z.infer<typeof RepairEventInputSchema>;
export type RepairReceipt = z.infer<typeof RepairReceiptSchema>;
