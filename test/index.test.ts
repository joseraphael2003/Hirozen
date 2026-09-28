// Plugin-level regression test for the orphaned-link guard in src/index.ts (doc §15.1 B, V1.1).
//
// The bug: `session_shutdown` nulls `connectPromise` while a connect is in flight, so a second call
// runs a second connect; when the abandoned attempt later fails its stale-sha check it closes its own
// link, and that late close used to release the *live* module state. A tool call after it then built a
// third connect, which `findOwner` refused with E_IN_USE naming omp's own pid.
//
// The host is a stub `pi`/`ctx` (pattern: temp/t6-smoke.ts); a real WebSocket client plays the loader.
import { afterAll, expect, spyOn, test } from "bun:test";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { zod } from "@oh-my-pi/pi-coding-agent";
import type { AgentToolResult, ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

import hirozen from "../src/index";
import { install, sha256File } from "../src/install";
import { ZenLink } from "../src/link";

/** The three loader modules as this checkout hashes them: the shas the plugin accepts in `ready`. */
const LOADER_SHA = sha256File(fileURLToPath(new URL("../loader/loader.sys.mjs", import.meta.url)));
const CHILD_SOURCE = fileURLToPath(new URL("../loader/HirozenChild.sys.mjs", import.meta.url));
const PARENT_SOURCE = fileURLToPath(new URL("../loader/HirozenParent.sys.mjs", import.meta.url));

const hmacHex = (key: string, message: string) => createHmac("sha256", key).update(message).digest("hex");

type Frame = Record<string, unknown>;

const dirs: string[] = [];
const loaders: FakeLoader[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

/** A Zen install folder that passes verify(): a `zen.exe` marker plus the plugin's own loader. */
function fakeZenDir(): string {
  const zenDir = tempDir("hirozen-index-zen-");
  writeFileSync(join(zenDir, "zen.exe"), "not really zen");
  install(zenDir);
  return zenDir;
}

/**
 * The loader's end of the link: polls the profile for the handoff, connects out, authenticates and
 * answers requests. With `holdReady` the handshake stops after the auth frame, so a test can complete
 * `connect()` later; that is exactly the in-flight connect the orphan guard has to survive.
 */
class FakeLoader {
  readonly requests: Frame[] = [];
  readonly closed: Promise<{ code: number; reason: string }>;
  #ws: WebSocket | null = null;
  #handlers = new Map<string, (frame: Frame) => void>();
  #resolveClosed: (value: { code: number; reason: string }) => void;
  #stopped = false;
  #requestQueue: Frame[] = [];
  #requestWaiters: ((frame: Frame) => void)[] = [];

  constructor(
    readonly profileDir: string,
    readonly options: { holdReady?: boolean } = {},
  ) {
    const { promise, resolve } = Promise.withResolvers<{ code: number; reason: string }>();
    this.closed = promise;
    this.#resolveClosed = resolve;
    loaders.push(this);
  }

  on(method: string, handler: (frame: Frame) => void): this {
    this.#handlers.set(method, handler);
    return this;
  }

  send(frame: unknown): void {
    this.#ws?.send(JSON.stringify(frame));
  }

  reply(frame: Frame, result: unknown): void {
    this.send({ id: frame.id, result });
  }

  /** Resolves with the next request the loader side sends, or one that already arrived. */
  nextRequest(): Promise<Frame> {
    const queued = this.#requestQueue.shift();
    if (queued) return Promise.resolve(queued);
    const { promise, resolve } = Promise.withResolvers<Frame>();
    this.#requestWaiters.push(resolve);
    return promise;
  }

  /** The `ready` frame, sent by `start()` unless `holdReady` left it for the test to release. */
  sendReady(loaderSha256 = LOADER_SHA): void {
    this.send({
      type: "ready",
      loaderVersion: "1.0.0-test",
      loaderSha256,
      childSha256: sha256File(CHILD_SOURCE),
      parentSha256: sha256File(PARENT_SOURCE),
      zenVersion: "1.22.3b",
      platformVersion: "156.0.1",
      zenPid: process.pid,
    });
  }

  /** Consumes the handoff, connects, and authenticates; resolves with the ready frame still pending. */
  async start(timeoutMs = 4_000): Promise<void> {
    const path = join(this.profileDir, "hirozen-handoff.json");
    const deadline = Date.now() + timeoutMs;
    let handoff: { port: number; nonce: string } | null = null;
    while (handoff === null) {
      try {
        const raw = JSON.parse(readFileSync(path, "utf8")) as { port: number; nonce: string };
        if (typeof raw.port === "number" && typeof raw.nonce === "string") handoff = raw;
      } catch {
        // not written yet
      }
      if (handoff === null && Date.now() > deadline) throw new Error("connect() never wrote the handoff file");
      // Poll for the real condition (the handoff file appearing on the link's own async path); fake
      // timers would break the WebSocket round trips this loop is waiting for.
      if (handoff === null) {
        const sleep = Promise.withResolvers<void>();
        setTimeout(sleep.resolve, 10);
        await sleep.promise;
      }
    }
    rmSync(path, { force: true }); // the loader consumes it

    const ws = new WebSocket(`ws://127.0.0.1:${handoff.port}/hirozen`);
    this.#ws = ws;
    const opened = Promise.withResolvers<void>();
    ws.addEventListener("open", () => opened.resolve(), { once: true });
    ws.addEventListener("error", () => opened.reject(new Error("the fake loader socket errored")), { once: true });
    await opened.promise;

    ws.addEventListener("message", event => {
      const frame = JSON.parse(String(event.data)) as Frame;
      if (typeof frame.challenge === "string") {
        const myChallenge = randomBytes(32).toString("hex");
        ws.send(JSON.stringify({ type: "auth", mac: hmacHex(handoff.nonce, `loader:${frame.challenge}`), challenge: myChallenge }));
        return;
      }
      if (frame.type === "auth") {
        // The handshake is complete only now: anything sent earlier would be refused with 4002.
        if (!this.options.holdReady) this.sendReady();
        return;
      }
      if (typeof frame.id === "number" && typeof frame.method === "string") {
        this.requests.push(frame);
        const waiter = this.#requestWaiters.shift();
        if (waiter) waiter(frame);
        else this.#requestQueue.push(frame);
        if (this.#stopped) return;
        this.#handlers.get(frame.method)?.(frame);
      }
    });
    ws.addEventListener("close", event => {
      this.#stopped = true; // the loader stops answering once the link is gone
      this.#resolveClosed({ code: event.code, reason: event.reason });
    });
  }

  close(): void {
    if (this.#ws && this.#ws.readyState !== WebSocket.CLOSED) this.#ws.close();
  }

  /** Closes with an explicit code/reason, so a test can play Firefox's own 4010/4011 stop. */
  closeWith(code: number, reason: string): void {
    if (this.#ws && this.#ws.readyState !== WebSocket.CLOSED) this.#ws.close(code, reason);
  }
}

type Host = {
  pi: ExtensionAPI;
  ctx: ExtensionContext;
  notifications: string[];
  tools: Map<string, StubTool>;
  commands: Map<string, { handler: (args: string, ctx: ExtensionContext) => unknown }>;
  events: Map<string, (event: unknown, ctx: ExtensionContext) => unknown>;
};

/** What the stub keeps from a registered tool: the handler plus the approval surface omp reads. */
type StubTool = {
  execute: (...args: unknown[]) => Promise<AgentToolResult<unknown>>;
  approval?: unknown;
  formatApprovalDetails?: (args: unknown) => string | string[] | undefined;
};

/** A stub host: the real schema builder, captured registrations, recorded notifications. */
function makeHost(cwd: string): Host {
  const notifications: string[] = [];
  const tools = new Map<string, StubTool>();
  const commands = new Map<string, { handler: (args: string, ctx: ExtensionContext) => unknown }>();
  const events = new Map<string, (event: unknown, ctx: ExtensionContext) => unknown>();

  const ctx = {
    hasUI: true,
    agent: { kind: "main", id: "Main", name: "main", depth: 0 },
    cwd,
    ui: { notify: (message: string) => notifications.push(message) },
    setTimeout: (callback: () => void, ms: number) => setTimeout(callback, ms),
    clearTimer: (timer: unknown) => clearTimeout(timer as ReturnType<typeof setTimeout>),
  } as unknown as ExtensionContext;

  const pi = {
    zod,
    pi: { getAgentDir: () => cwd },
    on: (name: string, handler: (event: unknown, ctx: ExtensionContext) => unknown) => {
      events.set(name, handler);
    },
    registerTool: (tool: { name: string } & StubTool) => {
      tools.set(tool.name, tool);
    },
    registerCommand: (name: string, options: { handler: (args: string, ctx: ExtensionContext) => unknown }) => {
      commands.set(name, options);
    },
  } as unknown as ExtensionAPI;

  return { pi, ctx, notifications, tools, commands, events };
}

async function callTool(host: Host, name: string, params: unknown = {}): Promise<AgentToolResult<unknown>> {
  const tool = host.tools.get(name);
  if (!tool) throw new Error(`tool ${name} is not registered`);
  return tool.execute("call-1", params, undefined, undefined, host.ctx);
}

/** Runs a registered command, i.e. what the user types as `/hirozen-connect`. */
async function runCommand(host: Host, name: string, args = ""): Promise<void> {
  const command = host.commands.get(name);
  if (!command) throw new Error(`command ${name} is not registered`);
  await command.handler(args, host.ctx);
}

/**
 * Poll for a condition the plugin reaches on its own async path (link events, notifications)
 * instead of waiting a guessed duration. Fake timers would break the WebSocket round trips this
 * loop is waiting for, so the poll interval is real; it is only how often the condition is re-checked.
 */
async function waitFor(condition: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("condition was never met");
    const sleep = Promise.withResolvers<void>();
    setTimeout(sleep.resolve, 5);
    await sleep.promise;
  }
}

function textOf(result: AgentToolResult<unknown>): string {
  return result.content.map(item => (item.type === "text" ? item.text : `<${item.type}>`)).join("\n");
}

/** The absolute deadline a request frame carries: the loader checks it before it acts on anything. */
function frameDeadline(frame: Frame): number {
  const deadline = frame.deadline;
  if (typeof deadline !== "number") throw new Error("the request frame carries no numeric deadline");
  return deadline;
}

/** Fires the session_shutdown handler the plugin registers with its first successful link. */
async function shutdown(host: Host): Promise<void> {
  const handler = host.events.get("session_shutdown");
  if (!handler) throw new Error("session_shutdown was never registered");
  await handler({ type: "session_shutdown" }, host.ctx);
}

const TAB_KEY = "1759000000000-aaaa";
const INVENTORY = [
  {
    activeSpace: "space-work",
    spaces: [{ uuid: "space-work", name: "Work", icon: null, containerTabId: 0, active: true }],
    tabs: [
      {
        tabKey: TAB_KEY,
        title: "Example Domain",
        url: "https://example.com/",
        space: "space-work",
        pinned: false,
        essential: false,
        lazy: false,
        selected: true,
      },
    ],
  },
];

const zenDir = fakeZenDir();
const profileDir = tempDir("hirozen-index-profile-");
process.env.HIROZEN_ZEN_DIR = zenDir;
process.env.HIROZEN_PROFILE = profileDir;
const host = makeHost(tempDir("hirozen-index-cwd-"));
hirozen(host.pi);

afterAll(async () => {
  if (host.events.has("session_shutdown")) await shutdown(host);
  for (const loader of loaders) loader.close();
  await Promise.allSettled(loaders.map(loader => loader.closed));
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  delete process.env.HIROZEN_ZEN_DIR;
  delete process.env.HIROZEN_PROFILE;
});

test("a superseded connect cannot release the live link (orphan guard)", async () => {
  // 1. Warm-up: one tool call connects and succeeds, which registers the teardown; then omp restarts.
  const warm = new FakeLoader(profileDir).on("zen.inventory", frame => warm.reply(frame, []));
  const warmStart = warm.start();
  const warmResult = await callTool(host, "zen_tabs");
  await warmStart;
  expect(warmResult.isError).not.toBe(true);
  expect(warm.requests.length).toBe(1);
  await shutdown(host);

  // 2. Tool call 1 starts connect A; the fake loader holds A's ready frame.
  const callA = callTool(host, "zen_tabs");
  const loaderA = new FakeLoader(profileDir, { holdReady: true });
  await loaderA.start();

  // 3. A second session_shutdown releases the module state while A is still connecting.
  await shutdown(host);

  // 4. Tool call 2 starts connect B, which completes and becomes the live link.
  const callB = callTool(host, "zen_tabs");
  const loaderB = new FakeLoader(profileDir).on("zen.inventory", frame => loaderB.reply(frame, INVENTORY));
  const loaderBStart = loaderB.start();
  const resultB = await callB;
  await loaderBStart;
  expect(resultB.isError).not.toBe(true);

  // 5. What the real loader keeps in the profile while B is connected: a live record naming this omp.
  writeFileSync(
    join(profileDir, "hirozen-status.json"),
    JSON.stringify({
      version: "1",
      state: "connected",
      zenPid: process.pid,
      lastHandoff: { pid: process.pid },
      updated: new Date().toISOString(),
    }),
  );

  // 6. Release A's ready with a stale sha: the abandoned attempt fails and closes its own link.
  loaderA.sendReady("0".repeat(64));
  const resultA = await callA;
  expect(textOf(resultA).startsWith("E_STALE_LOADER")).toBe(true);

  // The guard: the next call runs through the live link B. Without it A's close released B, the call
  // built a third connect, and the status record above refused it with E_IN_USE naming our own pid.
  const resultC = await callTool(host, "zen_tabs");
  expect(textOf(resultC)).not.toContain("E_IN_USE");
  expect(resultC.isError).not.toBe(true);
  expect(textOf(resultC)).toContain(TAB_KEY);
  expect(loaderB.requests.length).toBe(2);
}, 30_000);

test("a call in flight when a sticky stop closes the link gets that stop's text", async () => {
  // The previous test left its live link connected, and the status record it wrote still names a
  // session for this pid: release both before a fresh loader offers a handoff.
  await shutdown(host);
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });

  const loader = new FakeLoader(profileDir);
  const started = loader.start();
  const inFlight = callTool(host, "browser_read", { tabKey: TAB_KEY });

  // Hold the call open: the fake loader takes the request and never answers it.
  await loader.nextRequest();

  // Firefox's own stop ("Turn off remote control") closes the link with 4011 while that call is
  // still pending; the close is what the sticky text must describe, not a generic drop.
  loader.closeWith(4011, "external disconnect");
  const result = await inFlight;
  const text = textOf(result);
  expect(result.isError).toBe(true);
  expect(text.startsWith("E_STOPPED")).toBe(true);
  expect(text).toContain("turned off in Zen (Disconnect / Turn off remote control)");
  expect(text).toContain("run /hirozen-connect");
  // The generic gloss ("retry, or run /hirozen-connect") would advise a retry that the sticky gate
  // refuses; the in-flight failure and the later calls must use the same per-kind text.
  expect(text).not.toContain("fail-closed");
  expect(text).not.toContain("retry,");
  const later = await callTool(host, "zen_tabs");
  expect(textOf(later)).toBe(text);

  await started;
}, 30_000);

test("the act budget tracks the gate scope, the terminal hint mirrors consent, and the details name the ref", async () => {
  // The previous test left a sticky stop and a live link behind; /hirozen-connect is the documented
  // way out of the stop, and the status record it wrote must go before a fresh loader offers a handoff.
  await runCommand(host, "hirozen-connect");
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });

  // Bun's spyOn calls through by default, so the real call still sends the frame; the spy only
  // records what the plugin asked for (method + budget), which is what the loader's deadline is cut from.
  const callSpy = spyOn(ZenLink.prototype, "call");

  try {
    const loader = new FakeLoader(profileDir);
    const started = loader.start().catch(() => undefined); // reported by the assertions, not as an unhandled rejection

    // 1. Tracked scope is "none", so the first act call carries the extra 125 s the loader needs to
    //    wait for the user's answer in Zen (base 15 s + 125 s).
    const firstCall = callTool(host, "browser_act", { tabKey: TAB_KEY, action: "click", ref: "ab12.e1" });
    const firstRequest = await loader.nextRequest();
    expect(firstRequest.method).toBe("browser.act");
    expect(callSpy.mock.calls.map(call => ({ method: call[0], timeoutMs: call[2]?.timeoutMs }))).toEqual([
      { method: "browser.act", timeoutMs: 140_000 },
    ]);
    // The frame carries the absolute deadline the loader checks before it acts, not just the budget.
    expect(Math.abs(frameDeadline(firstRequest) - (Date.now() + 140_000))).toBeLessThan(5_000);

    // 2. The gate prompt reaches the terminal while the call is still pending.
    loader.send({ type: "event", name: "consent.pending", data: { scope: "act" } });
    await waitFor(() => host.notifications.some(message => message.includes("click Allow in Zen")));
    const hint = host.notifications.find(message => message.includes("click Allow in Zen")) ?? "";
    expect(hint).toContain("read and act on pages");

    // 3. Allow, then answer the pending call. The reply frame is queued behind the event frame, so
    //    awaiting the call proves the granted scope was applied before the next call is made.
    loader.send({ type: "event", name: "consent.granted", data: { scope: "act" } });
    loader.reply(firstRequest, { ok: true, url: "https://example.com/", title: "Example Domain" });
    expect(textOf(await firstCall)).toContain("https://example.com/");

    // 4. With act granted, the next act call needs no person-wait: base 15 s only.
    const secondCall = callTool(host, "browser_act", { tabKey: TAB_KEY, action: "click", ref: "ab12.e1" });
    const secondRequest = await loader.nextRequest();
    expect(callSpy.mock.calls[1]?.[2]?.timeoutMs).toBe(15_000);
    expect(frameDeadline(secondRequest) - Date.now()).toBeLessThanOrEqual(15_000);
    loader.reply(secondRequest, { ok: true, url: "https://example.com/", title: "Example Domain" });
    expect((await secondCall).isError).not.toBe(true);

    // 5. A snapshot names the elements the approval prompt has to describe.
    const snapshot = callTool(host, "browser_snapshot", { tabKey: TAB_KEY });
    const snapshotRequest = await loader.nextRequest();
    expect(snapshotRequest.method).toBe("browser.snapshot");
    loader.reply(snapshotRequest, {
      url: "https://example.com/form",
      title: "Fixture form",
      elements: [
        {
          ref: "ab12.e1",
          role: "button",
          name: "Save changes",
          tag: "button",
          rect: { x: 10, y: 20, width: 80, height: 30 },
        },
      ],
      truncated: false,
    });
    const snapshotResult = await snapshot;
    expect(snapshotResult.isError).not.toBe(true);
    expect(textOf(snapshotResult)).toContain("ab12.e1");

    // 6. The prompt details: the tab it acts on, the action, and the element behind the ref.
    const tool = host.tools.get("browser_act");
    if (!tool) throw new Error("browser_act is not registered");
    const args = { tabKey: TAB_KEY, action: "click", ref: "ab12.e1" };
    const details = tool.formatApprovalDetails?.(args);
    const lines = Array.isArray(details) ? details.join("\n") : String(details ?? "");
    expect(lines).toContain("Fixture form");
    expect(lines).toContain("https://example.com/form");
    expect(lines).toContain("click");
    expect(lines).toContain('button "Save changes"');
    // A ref the last snapshot did not name is echoed as-is instead of being called a role.
    const unknown = tool.formatApprovalDetails?.({ tabKey: TAB_KEY, action: "click", ref: "zz99.e7" });
    expect(Array.isArray(unknown) ? unknown.join("\n") : String(unknown)).toContain("ref zz99.e7");

    // 7. The approval itself is a per-call decision: exec tier, always prompting.
    const approval = tool.approval;
    const decision = typeof approval === "function" ? approval(args) : approval;
    expect(decision).toMatchObject({ tier: "exec", policy: "prompt" });
    if (!decision || typeof decision !== "object" || !("reason" in decision)) {
      throw new Error("the approval decision carries no reason");
    }
    expect(typeof decision.reason).toBe("string");
    expect(decision.reason).not.toBe("");

    await shutdown(host);
    await started;
  } finally {
    callSpy.mockRestore();
  }
}, 30_000);
