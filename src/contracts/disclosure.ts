import { z } from 'zod';
import { UuidSchema } from './learning.ts';
export const DisclosureRequestSchema = z.strictObject({
  target: z.discriminatedUnion('kind', [
    z.strictObject({ kind: z.enum(['itemDetail', 'memoryNote', 'comparison', 'sourceMedia']), itemId: UuidSchema }),
    z.strictObject({ kind: z.enum(['attempt', 'explanation', 'sessionResults', 'export']), id: UuidSchema }),
  ]),
  presentation: z.enum(['direct', 'mixed']),
});
export const DisclosureDecisionSchema = z.discriminatedUnion('decision', [
  z.strictObject({ decision: z.literal('allowed') }),
  z.strictObject({ decision: z.literal('blocked'), code: z.literal('test_reference_locked'), action: z.literal('finishTest') }),
  z.strictObject({ decision: z.literal('redacted'), code: z.literal('test_reference_locked'), action: z.literal('finishTest') }),
]);
/** Contracts only: authorization must query every unfinished Test in the active dataset. */
export type DisclosureRequest = z.infer<typeof DisclosureRequestSchema>;
export type DisclosureDecision = z.infer<typeof DisclosureDecisionSchema>;
