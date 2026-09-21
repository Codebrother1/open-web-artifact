/**
 * Count requests to ONE storage host by method and Authorization scheme, and
 * whether any OWA bearer material reached it. Records nothing else — never a
 * URL, header value, signature or body. Install before withRequestLimits so the
 * limiter wraps the meter; call restore() after the limited run has finished.
 */
export function meterRequests(endpointHost) {
  const counts = { methods: {}, schemes: {}, bearer: 0 };
  const real = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    const target = String(url);
    if (new URL(target).host === endpointHost) {
      const method = (options.method ?? 'GET').toUpperCase();
      counts.methods[method] = (counts.methods[method] ?? 0) + 1;
      const auth = new Headers(options.headers ?? {}).get('authorization');
      const scheme = auth ? auth.split(' ')[0] : (target.includes('X-Amz-Signature=') ? 'presigned' : 'none');
      counts.schemes[scheme] = (counts.schemes[scheme] ?? 0) + 1;
      if (/^bearer$/i.test(scheme) || /owa1\./.test(target)) counts.bearer++;
    }
    return real(url, options);
  };
  return {
    counts,
    snapshot: () => ({ ...counts.methods }),
    /** Requests of one method since a snapshot. */
    since: (before, method) => (counts.methods[method] ?? 0) - (before[method] ?? 0),
    restore: () => { globalThis.fetch = real; }
  };
}

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
