import assert from "node:assert/strict";
import test from "node:test";
import { CerebroClient } from "../src/cerebro/client.js";
import { testConfig } from "./fixtures.js";

function stalledFetch(): { fetchImpl: typeof fetch; calls: () => number } {
  let callCount = 0;
  const fetchImpl: typeof fetch = (_input, init = {}) => {
    callCount += 1;
    return new Promise<Response>((_resolve, reject) => {
      const signal = init.signal;
      assert(signal, "Cerebro requests must carry a timeout signal");
      const testGuard = setTimeout(() => reject(new Error("request timeout signal did not fire")), 1_000);
      signal.addEventListener("abort", () => {
        clearTimeout(testGuard);
        reject(signal.reason);
      }, { once: true });
    });
  };
  return { fetchImpl, calls: () => callCount };
}

test("direct Cerebro reads stop at the configured request timeout", async () => {
  const stalled = stalledFetch();
  const config = testConfig({ cerebro: { requestTimeoutMs: 20 } });
  const client = new CerebroClient(config, { fetchImpl: stalled.fetchImpl });

  await assert.rejects(client.listSourceRuntimes());
  assert.equal(stalled.calls(), 1);
});

test("Cerebro SDK bootstrap calls stop at the configured request timeout", async () => {
  const stalled = stalledFetch();
  const config = testConfig({ cerebro: { requestTimeoutMs: 20 } });
  const client = new CerebroClient(config, { fetchImpl: stalled.fetchImpl });

  await assert.rejects(client.ensureCompanionRuntime());
  assert.equal(stalled.calls(), 1);
});
