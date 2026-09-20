import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { inspect } from 'node:util';
import { withRequestLimits } from '../src/requests.js';

const safeMessage = 'Live integration request failed, timed out, or was cancelled (URL and credentials omitted)';
const dummyUrl = 'https://discard.invalid/put?X-Amz-Credential=DISPOSABLE_KEY&X-Amz-Signature=DISPOSABLE_SIGNATURE';

// Top-level tests run sequentially: only these offline checks mock global fetch.
for (const cancellation of ['caller abort', 'publish deadline', 'request deadline']) {
  test(`${cancellation}: first PUT unwinds before independent cleanup; no later PUT`, async t => {
    const controller = new AbortController();
    const events = [];
    const scheduled = [];
    const cleanupSignals = [];
    let runSettled = false;
    let putSignal;
    t.mock.method(globalThis, 'fetch', async (_input, { method, signal }) => {
      events.push(method);
      assert.equal(signal.aborted, false);
      if (method === 'PUT') {
        putSignal = signal;
        if (cancellation === 'caller abort') queueMicrotask(() => controller.abort(new Error('DISPOSABLE_ABORT')));
        try {
          // A referenced timer also keeps AbortSignal.timeout alive in this mock.
          await delay(5_000, undefined, { signal });
        } finally {
          // Model slow rejection/unwinding, which a Promise.race would leave running.
          await delay(10);
          events.push('PUT settled');
        }
      } else {
        assert.equal(runSettled, true);
        assert.notEqual(signal, putSignal);
        cleanupSignals.push(signal);
      }
      return new Response(null, { status: 204 });
    });
    const delegate = globalThis.fetch;
    await assert.rejects(withRequestLimits({
      signal: controller.signal,
      requestTimeout: cancellation === 'request deadline' ? 25 : 5_000,
      publishTimeout: cancellation === 'publish deadline' ? 25 : 5_000,
      run: async () => {
        try {
          for (const key of ['first', 'second', 'third']) {
            scheduled.push(key);
            await fetch(`${dummyUrl}&key=${key}`, { method: 'PUT' });
          }
        } finally {
          await delay(10);
          runSettled = true;
          events.push('run settled');
        }
      },
      cleanup: async () => {
        assert.equal(putSignal.aborted, true);
        await fetch(dummyUrl, { method: 'DELETE' });
        await fetch(dummyUrl, { method: 'HEAD' });
      }
    }), { message: safeMessage });
    assert.deepEqual(scheduled, ['first']);
    assert.deepEqual(events, ['PUT', 'PUT settled', 'run settled', 'DELETE', 'HEAD']);
    assert.notEqual(cleanupSignals[0], cleanupSignals[1]);
    assert.equal(globalThis.fetch, delegate);
  });
}

test('normal flow delegates to real loopback fetch, returns run result, then cleans up', async () => {
  const events = [];
  const server = createServer((req, res) => {
    events.push(`${req.method} ${req.url}`);
    req.resume();
    req.on('end', () => res.writeHead(204).end());
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  const realFetch = globalThis.fetch;
  try {
    const result = await withRequestLimits({
      requestTimeout: 5_000, publishTimeout: 5_000,
      run: async () => {
        for (const key of ['first', 'second']) {
          const res = await fetch(`${base}/${key}`, { method: 'PUT', body: key });
          assert.equal(res.status, 204);
          await res.arrayBuffer();
        }
        events.push('run settled');
        return 'published';
      },
      cleanup: async () => {
        for (const key of ['first', 'second']) {
          const res = await fetch(`${base}/${key}`, { method: 'DELETE' });
          assert.equal(res.status, 204);
          await res.arrayBuffer();
        }
      }
    });
    assert.equal(result, 'published');
    assert.deepEqual(events, ['PUT /first', 'PUT /second', 'run settled', 'DELETE /first', 'DELETE /second']);
    assert.equal(globalThis.fetch, realFetch);
  } finally {
    const closed = once(server, 'close');
    server.close();
    server.closeAllConnections();
    await closed;
  }
});

test('network errors omit disposable signed URLs, credentials and nested causes', async t => {
  t.mock.method(globalThis, 'fetch', async () => {
    throw new Error(`Network failure: ${dummyUrl}; DISPOSABLE_SECRET`, {
      cause: new Error('DISPOSABLE_TOKEN')
    });
  });
  const delegate = globalThis.fetch;
  let cleaned = false;
  await assert.rejects(withRequestLimits({
    run: () => fetch(dummyUrl, { method: 'PUT' }),
    cleanup: async () => { cleaned = true; }
  }), error => {
    assert.equal(error.message, safeMessage);
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(inspect(error), /DISPOSABLE|discard\.invalid|X-Amz/);
    return true;
  });
  assert.equal(cleaned, true);
  assert.equal(globalThis.fetch, delegate);
});

test('an aborted publish cannot delegate later requests even if run catches errors', async t => {
  const controller = new AbortController();
  const methods = [];
  t.mock.method(globalThis, 'fetch', async (_input, { method, signal }) => {
    methods.push(method);
    assert.equal(signal.aborted, false);
    return new Response(null, { status: 204 });
  });
  controller.abort(new Error('DISPOSABLE_ABORT'));
  await withRequestLimits({
    signal: controller.signal,
    run: async () => {
      for (let i = 0; i < 3; i++) await assert.rejects(fetch(dummyUrl, { method: 'PUT' }), { message: safeMessage });
    },
    cleanup: () => fetch(dummyUrl, { method: 'DELETE' })
  });
  assert.deepEqual(methods, ['DELETE']);
});

test('cleanup requests have their own deadlines and fetch is restored on cleanup error', async t => {
  t.mock.method(globalThis, 'fetch', (_input, { signal }) => delay(5_000, undefined, { signal }));
  const delegate = globalThis.fetch;
  const events = [];
  await assert.rejects(withRequestLimits({
    requestTimeout: 25,
    run: async () => { events.push('run settled'); },
    cleanup: async () => {
      events.push('cleanup');
      await fetch(dummyUrl, { method: 'DELETE' });
    }
  }), { message: safeMessage });
  assert.deepEqual(events, ['run settled', 'cleanup']);
  assert.equal(globalThis.fetch, delegate);
});
