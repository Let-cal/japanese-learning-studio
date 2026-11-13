/** The signal interrupts in-flight I/O and the monotonic check also fences delayed timers. */
export function createOAuthRequestBudget(milliseconds: number, clock: () => number, parent?: AbortSignal) {
  const started = clock();
  const timeout = AbortSignal.timeout(milliseconds);
  const signal = parent ? AbortSignal.any([parent, timeout]) : timeout;
  const elapsed = () => clock() - started;
  return {
    signal, elapsed,
    expired() {
      const duration = elapsed();
      return signal.aborted || !Number.isFinite(duration) || duration < 0 || duration >= milliseconds;
    },
  };
}
