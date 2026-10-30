export type Observed<T> = { ok: true; value: T } | { ok: false; error: unknown };
export const observe = <T>(task: Promise<T>): Promise<Observed<T>> => task.then(value => ({ ok: true, value }), error => ({ ok: false, error }));
export async function bounded<T>(promise: Promise<T>, ms = 2500): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('Fixture barrier deadline exceeded.')), ms); })]); }
  finally { clearTimeout(timer); }
}
export function signal<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve, wait: (ms = 2500) => bounded(promise, ms) };
}
export function barrier() {
  const arrival = signal<void>(); const continuation = signal<void>();
  return { arrival: arrival.promise, wait: () => arrival.wait(), hold: async () => { arrival.resolve(); await continuation.promise; }, release: () => continuation.resolve() };
}
export interface ConcurrentScope {
  start<T>(task: Promise<T>): Promise<Observed<T>>;
  barrier(): ReturnType<typeof barrier>;
  wait<T>(arrival: Promise<T>, task: Promise<Observed<unknown>>, ms?: number): Promise<T>;
}
export async function withConcurrentProof<T>(action: (scope: ConcurrentScope) => Promise<T>): Promise<T> {
  const tasks: Promise<Observed<unknown>>[] = [];
  const gates: ReturnType<typeof barrier>[] = [];
  const result = await observe(action({
    start(task) { const observed = observe(task); tasks.push(observed); return observed; },
    barrier() { const gate = barrier(); gates.push(gate); return gate; },
    wait(arrival, task, ms = 2500) {
      return bounded(Promise.race([arrival, task.then(outcome => {
        if (!outcome.ok) throw outcome.error;
        throw new Error('Fixture transaction completed before its expected signal.');
      })]), ms);
    },
  }));
  // Never return to Vitest (and its next reset/teardown) with a started transaction outstanding.
  for (const gate of gates) gate.release();
  const outcomes = await Promise.all(tasks);
  if (!result.ok) {
    const errors = [...new Set([result.error, ...outcomes.flatMap(outcome => outcome.ok ? [] : [outcome.error])])];
    if (errors.length > 1) throw new AggregateError(errors, 'Concurrent fixture failed; all started transactions drained.', { cause: result.error });
    throw result.error;
  }
  return result.value;
}
