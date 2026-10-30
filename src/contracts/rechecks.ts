import { z } from 'zod';
import { AbilitySchema, StoredVersionSchema, UtcInstantSchema, UuidSchema } from './learning.ts';
import type { CommandContext } from './common';
export const RecheckOriginRefSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('repair'), repairId: UuidSchema }),
  z.strictObject({ kind: z.literal('attempt'), attemptId: UuidSchema, gradeRevisionId: UuidSchema }),
]);
const binding = { originRef: RecheckOriginRefSchema, itemId: UuidSchema, ability: AbilitySchema, itemRevisionId: UuidSchema, sourceRevisionIds: z.array(UuidSchema).min(1), policyVersion: StoredVersionSchema };
export const RecheckDecisionSchema = z.discriminatedUnion('decision', [
  z.strictObject({ decision: z.literal('accept'), ...binding, requestedNotBefore: UtcInstantSchema }),
  z.strictObject({ decision: z.literal('defer'), ...binding }),
  z.strictObject({ decision: z.literal('cancel'), ...binding }),
  z.strictObject({ decision: z.literal('snooze'), ...binding, requestedNotBefore: UtcInstantSchema }),
]);
export const RecheckReceiptSchema = z.strictObject({ intentId: UuidSchema, intentVersion: StoredVersionSchema, status: z.enum(['accepted', 'deferred', 'cancelled', 'snoozed']) });
const IntentSchema = z.strictObject({ ...binding, intentId: UuidSchema, intentVersion: StoredVersionSchema, proposedAt: UtcInstantSchema, requestedNotBefore: UtcInstantSchema.nullable(), status: z.enum(['accepted', 'deferred', 'cancelled', 'snoozed', 'satisfied']), satisfiedByAttemptId: UuidSchema.optional() });
export const TargetedRecheckProjectionInputSchema = z.strictObject({ ownerId: UuidSchema, datasetEpoch: UuidSchema, intents: z.array(IntentSchema), ordinaryDue: z.array(z.strictObject({ itemId: UuidSchema, ability: AbilitySchema, dueAt: UtcInstantSchema.nullable() })) });
export const TargetedRecheckSchema = z.strictObject({ ownerId: UuidSchema, datasetEpoch: UuidSchema, itemId: UuidSchema, ability: AbilitySchema, originRefs: z.array(RecheckOriginRefSchema).min(1), intentIds: z.array(UuidSchema).min(1), targetedNotBefore: UtcInstantSchema, ordinaryFsrsDueAt: UtcInstantSchema.nullable() });
export type RecheckDecision = z.infer<typeof RecheckDecisionSchema>;
export type RecheckReceipt = z.infer<typeof RecheckReceiptSchema>;
export type TargetedRecheckProjectionInput = z.infer<typeof TargetedRecheckProjectionInputSchema>;
export type TargetedRecheck = z.infer<typeof TargetedRecheckSchema>;
/** Task 7 implements persistence/projection; these signatures prove no scheduling behavior. */
export interface TargetedRecheckPort {
  acceptTargetedRecheck(context: CommandContext, input: RecheckDecision): Promise<RecheckReceipt>;
  projectTargetedRechecks(input: TargetedRecheckProjectionInput): TargetedRecheck[];
}
