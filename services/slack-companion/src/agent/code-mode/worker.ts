import {
  newQuickJSWASMModule,
  newVariant,
  RELEASE_SYNC,
  type QuickJSContext,
  type QuickJSDeferredPromise,
  type QuickJSRuntime,
} from "quickjs-emscripten";
import type {
  ParentToSandboxMessage,
  SandboxExecuteMessage,
  SandboxResultMessage,
  SandboxToolResultMessage,
} from "./protocol.js";

const WASM_PAGE_BYTES = 64 * 1024;
const WASM_INITIAL_PAGES = 256;

process.once("message", (message: ParentToSandboxMessage) => {
  if (message?.type !== "execute") return;
  void execute(message).then(sendAndExit, (error) => sendAndExit(failure(message.requestId, error)));
});

async function execute(message: SandboxExecuteMessage): Promise<SandboxResultMessage> {
  const wasmPages = Math.max(
    WASM_INITIAL_PAGES,
    Math.ceil(message.limits.memoryLimitBytes / WASM_PAGE_BYTES),
  );
  const wasmMemory = new WebAssembly.Memory({ initial: wasmPages, maximum: wasmPages });
  const quickjs = await newQuickJSWASMModule(newVariant(RELEASE_SYNC, { wasmMemory }));
  const runtime = quickjs.newRuntime();
  runtime.setMemoryLimit(message.limits.memoryLimitBytes);
  runtime.setMaxStackSize(Math.min(512 * 1024, Math.max(64 * 1024, Math.floor(message.limits.memoryLimitBytes / 8))));
  const deadline = Date.now() + message.limits.timeoutMs;
  runtime.setInterruptHandler(() => Date.now() >= deadline);
  runtime.setModuleLoader(() => { throw new Error("Code Mode imports are disabled."); });
  const vm = runtime.newContext();
  const deferred = new Map<string, QuickJSDeferredPromise>();
  let callSequence = 0;

  const onParentMessage = (incoming: ParentToSandboxMessage) => {
    if (incoming?.type !== "tool_result" || incoming.requestId !== message.requestId) return;
    settleToolCall(incoming, deferred, vm, runtime);
  };
  process.on("message", onParentMessage);

  try {
    const host = vm.newObject();
    for (const name of message.toolNames) {
      const fn = vm.newFunction(name, (argumentsHandle) => {
        const argumentsJson = vm.getString(argumentsHandle);
        const callId = `${message.requestId}:${++callSequence}`;
        const pending = vm.newPromise();
        deferred.set(callId, pending);
        process.send?.({ type: "tool_call", requestId: message.requestId, callId, name, argumentsJson });
        return pending.handle;
      });
      vm.setProp(host, name, fn);
      fn.dispose();
    }
    vm.setProp(vm.global, "__cerebroCodeModeHost", host);
    host.dispose();

    const toolNamesJson = JSON.stringify(message.toolNames);
    const bootstrap = vm.evalCode(`(() => {
      const host = globalThis.__cerebroCodeModeHost;
      delete globalThis.__cerebroCodeModeHost;
      for (const name of ["process", "require", "fetch", "WebAssembly", "eval", "Function"]) {
        Object.defineProperty(globalThis, name, { value: undefined, configurable: false, writable: false });
      }
      const tools = Object.create(null);
      for (const name of ${toolNamesJson}) {
        Object.defineProperty(tools, name, {
          value: async (args = {}) => JSON.parse(await host[name](JSON.stringify(args))),
          enumerable: true,
          configurable: false,
          writable: false,
        });
      }
      return Object.freeze(tools);
    })()`, "code-mode-bootstrap.js");
    const toolsHandle = vm.unwrapResult(bootstrap);
    const program = vm.evalCode(`(async (tools) => { "use strict";\n${message.script}\n})`, "code-mode-program.js");
    const programHandle = vm.unwrapResult(program);
    const invocation = vm.callFunction(programHandle, vm.undefined, toolsHandle);
    programHandle.dispose();
    toolsHandle.dispose();
    const promiseHandle = vm.unwrapResult(invocation);
    const initialJobs = runtime.executePendingJobs();
    if (initialJobs.error) vm.unwrapResult(initialJobs);
    initialJobs.dispose();
    const promiseState = vm.getPromiseState(promiseHandle);
    let valueHandle;
    if (promiseState.type === "fulfilled") {
      valueHandle = promiseState.value;
      promiseHandle.dispose();
    } else if (promiseState.type === "rejected") {
      promiseState.error.dispose();
      promiseHandle.dispose();
      throw new Error("guest_rejected");
    } else {
      const resolved = await vm.resolvePromise(promiseHandle);
      promiseHandle.dispose();
      valueHandle = vm.unwrapResult(resolved);
    }
    if (deferred.size > 0) {
      valueHandle.dispose();
      return failure(message.requestId, new Error("unawaited_tool_call"), "unawaited_tool_call");
    }
    const serializer = vm.unwrapResult(vm.evalCode("(value) => JSON.stringify({ value: value === undefined ? null : value })"));
    const serialized = vm.unwrapResult(vm.callFunction(serializer, vm.undefined, valueHandle));
    serializer.dispose();
    valueHandle.dispose();
    const resultJson = vm.getString(serialized);
    serialized.dispose();
    if (Buffer.byteLength(resultJson, "utf8") > message.limits.maxOutputBytes) {
      return { type: "result", requestId: message.requestId, ok: false, errorCode: "output_limit", error: "Code Mode output exceeded the configured limit." };
    }
    return { type: "result", requestId: message.requestId, ok: true, resultJson };
  } catch (error) {
    return failure(message.requestId, error, Date.now() >= deadline ? "timeout" : undefined);
  } finally {
    process.off("message", onParentMessage);
    for (const pending of deferred.values()) {
      if (pending.alive) pending.dispose();
    }
    deferred.clear();
    vm.dispose();
    runtime.dispose();
  }
}

function settleToolCall(
  message: SandboxToolResultMessage,
  deferred: Map<string, QuickJSDeferredPromise>,
  vm: QuickJSContext,
  runtime: QuickJSRuntime,
): void {
  const pending = deferred.get(message.callId);
  if (!pending) return;
  deferred.delete(message.callId);
  const handle = message.ok
    ? vm.newString(message.payloadJson ?? "null")
    : vm.newError(message.error ?? "Nested tool failed.");
  if (message.ok) pending.resolve(handle);
  else pending.reject(handle);
  handle.dispose();
  const jobs = runtime.executePendingJobs();
  if (jobs.error) jobs.error.dispose();
}

function failure(requestId: string, error: unknown, forcedCode?: string): SandboxResultMessage {
  const text = error instanceof Error ? error.message.toLowerCase() : "";
  const errorCode = forcedCode ?? (text.includes("memory") ? "memory_limit" : "execution_failed");
  const message = errorCode === "timeout"
    ? "Code Mode execution timed out."
    : errorCode === "memory_limit"
      ? "Code Mode execution exceeded the memory limit."
      : "Code Mode script failed.";
  return { type: "result", requestId, ok: false, errorCode, error: message };
}

function sendAndExit(message: SandboxResultMessage): void {
  process.send?.(message, () => process.exit(0));
}
