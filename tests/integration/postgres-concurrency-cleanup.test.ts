import { describe, expect, it, vi } from 'vitest';
import { signal, withConcurrentProof } from '../postgres/concurrency';

describe('network-free concurrent fixture cleanup (not SQL proof)', () => {
  it('releases every barrier and drains transactions before returning a failed assertion', async () => {
    const original = new Error('lock observation failed'); let finished = false;
    let release = () => {};
    try {
      await expect(withConcurrentProof(async scope => {
        const gate = scope.barrier(); release = gate.release;
        scope.start(gate.hold().then(() => { finished = true; }));
        await gate.wait(); throw original;
      })).rejects.toBe(original);
      expect(finished).toBe(true);
    } finally { release(); }
  });
  it('preserves an early transaction error beside the observation failure', async () => {
    const sql = new Error('SQL setup failed'); const observation = new Error('barrier deadline');
    await expect(withConcurrentProof(async scope => {
      await scope.start(Promise.reject(sql)); throw observation;
    })).rejects.toMatchObject({ errors: [observation, sql], cause: observation });
  });
  it('a missing PID signal times out with no repeating polling timers', async () => {
    vi.useFakeTimers();
    try {
      const pid = signal<number>();
      const result = expect(pid.wait(5)).rejects.toThrow(/deadline/);
      await vi.advanceTimersByTimeAsync(5); await result;
      expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });
  it('surfaces setup failure before PID arrival and clears its deadline timer', async () => {
    vi.useFakeTimers();
    const sql = new Error('connection failed before onClient');
    try {
      await expect(withConcurrentProof(async scope => {
        const pid = signal<number>(); const task = scope.start(Promise.reject(sql));
        await scope.wait(pid.promise, task);
      })).rejects.toBe(sql);
      expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });
});
