import { z } from 'zod';
import { StoredVersionSchema, UtcInstantSchema, UuidSchema } from './learning.ts';
export const JobStateSchema = z.enum(['queued', 'running', 'retry_wait', 'blocked_consent', 'blocked_budget', 'awaiting_local_device', 'submission_unknown', 'needs_review', 'failed', 'succeeded', 'cancelled', 'superseded']);
export const JobStatusSchema = z.strictObject({
  jobId: UuidSchema, jobVersion: StoredVersionSchema, state: JobStateSchema,
  retryAt: UtcInstantSchema.optional(),
  resultRef: z.strictObject({ kind: z.enum(['attempt', 'explanation', 'extraction', 'export', 'restorePreview']), id: UuidSchema }).optional(),
});
/** Cancellation/retry action is determined by the route, never by a provider URL or model. */
export const JobActionBodySchema = z.strictObject({});
export const JobAcknowledgementSchema = z.strictObject({ jobId: UuidSchema, jobVersion: StoredVersionSchema, state: JobStateSchema });
export type JobState = z.infer<typeof JobStateSchema>;
export type JobStatus = z.infer<typeof JobStatusSchema>;
export type JobAcknowledgement = z.infer<typeof JobAcknowledgementSchema>;
