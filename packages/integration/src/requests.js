// Test-only global fetch replacement: callers must run suites and requests sequentially.
// Await every publishing operation in run; detached work cannot be unwound here.
export async function withRequestLimits({
  signal, run, cleanup, requestTimeout = 15_000, publishTimeout = 180_000
}) {
  const realFetch = globalThis.fetch;
  const publishSignal = AbortSignal.any([
    AbortSignal.timeout(publishTimeout), ...(signal ? [signal] : [])
  ]);
  let cleaningUp = false;
  globalThis.fetch = async (input, init = {}) => {
    const signals = [AbortSignal.timeout(requestTimeout)];
    if (!cleaningUp) signals.push(publishSignal);
    if (init.signal) signals.push(init.signal);
    const requestSignal = AbortSignal.any(signals);
    try {
      // Do not delegate another publish request after cancellation.
      requestSignal.throwIfAborted();
      return await realFetch(input, { ...init, signal: requestSignal });
    } catch {
      // Never retain the original error/cause: it can contain signed URLs or credentials.
      throw new Error('Live integration request failed, timed out, or was cancelled (URL and credentials omitted)');
    }
  };
  try {
    return await run();
  } finally {
    // Unlike a runner timeout hook or Promise.race, wait for run to unwind before
    // cleanup. Each cleanup request gets a fresh deadline, not the publish signal.
    // Aborting fetch cannot guarantee a remote server will not persist a late PUT;
    // callers must track attempted uploads and may still need manual prefix cleanup.
    cleaningUp = true;
    try { await cleanup(); } finally { globalThis.fetch = realFetch; }
  }
}
