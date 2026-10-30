import { expect, it } from 'vitest';
import { JobStatusSchema } from '../../src/contracts/jobs';
const id = '11111111-1111-4111-8111-111111111111';
it('represents every approved job state while refusing provider credentials and arbitrary result URLs', () => {
  for (const state of ['queued','running','retry_wait','blocked_consent','blocked_budget','awaiting_local_device','submission_unknown','needs_review','failed','succeeded','cancelled','superseded']) {
    expect(JobStatusSchema.safeParse({ jobId: id, jobVersion: 1, state }).success).toBe(true);
  }
  for (const extra of [{ providerToken: 'secret' }, { resultUrl: 'https://example.com' }, { resultRef: { kind: 'attempt', id, url: 'https://example.com' } }]) {
    expect(JobStatusSchema.safeParse({ jobId: id, jobVersion: 1, state: 'succeeded', ...extra }).success).toBe(false);
  }
  expect(JobStatusSchema.safeParse({ jobId: id, jobVersion: 1, state: 'retry_wait', retryAt: '2026-10-30T10:00:00+07:00' }).success).toBe(false);
});
