import test from "node:test";
import assert from "node:assert/strict";
import { createPoller } from "../src/services/polling.js";
import { request } from "../src/services/api.js";
const tick = () => new Promise((resolve) => setTimeout(resolve, 5));
class Visibility extends EventTarget {
  hidden = false;
}

test("polling waits for completion, ignores stale results, and cancels on disposal", async () => {
  const visibility = new Visibility();
  const pending = [];
  const results = [];
  const poller = createPoller({
    interval: 10,
    visibility,
    load: ({ signal }) =>
      new Promise((resolve) => pending.push({ signal, resolve })),
    onData: (data) => results.push(data),
    onError: assert.fail,
  });
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(pending.length, 1);
  const refreshed = poller.refresh();
  assert.equal(pending[0].signal.aborted, true);
  pending[1].resolve("current");
  await refreshed;
  pending[0].resolve("stale");
  await tick();
  assert.deepEqual(results, ["current"]);
  poller.dispose();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(pending.length, 2);
});

test("hidden tabs abort work and resume immediately when visible", async () => {
  const visibility = new Visibility();
  const signals = [];
  const poller = createPoller({
    visibility,
    load: ({ signal }) => {
      signals.push(signal);
      return new Promise(() => {});
    },
    onData: assert.fail,
    onError: assert.fail,
  });
  visibility.hidden = true;
  visibility.dispatchEvent(new Event("visibilitychange"));
  assert.equal(signals[0].aborted, true);
  await tick();
  assert.equal(signals.length, 1);
  visibility.hidden = false;
  visibility.dispatchEvent(new Event("visibilitychange"));
  assert.equal(signals.length, 2);
  poller.dispose();
  assert.equal(signals[1].aborted, true);
});

test("request timeout, HTTP failures, and external cancellation release their resources", async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => ({ ok: false, status: 503 });
    await assert.rejects(request("/api/status"), /503/);
    globalThis.fetch = (_, { signal }) =>
      new Promise((_, reject) => {
        if (signal.aborted) reject(signal.reason);
        else
          signal.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          });
      });
    await assert.rejects(request("/api/status", { timeout: 5 }), {
      name: "TimeoutError",
    });
    const controller = new AbortController();
    const task = request("/api/status", { signal: controller.signal });
    controller.abort();
    await assert.rejects(task, { name: "AbortError" });
  } finally {
    globalThis.fetch = original;
  }
});
