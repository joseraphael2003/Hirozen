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
import { install, sha256File, uninstall } from "../src/install";
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
  readonly cancels: Frame[] = [];
  readonly closed: Promise<{ code: number; reason: string }>;
  #ws: WebSocket | null = null;
  #handlers = new Map<string, (frame: Frame) => void>();
  #resolveClosed: (value: { code: number; reason: string }) => void;
  #stopped = false;
  #requestQueue: Frame[] = [];
  #requestWaiters: ((frame: Frame) => void)[] = [];

  constructor(
    readonly profileDir: string,
    readonly options: { holdReady?: boolean; readyZenDir?: string } = {},
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
  sendReady(loaderSha256 = LOADER_SHA, readyZenDir: string = zenDir): void {
    this.send({
      type: "ready",
      loaderVersion: "1.0.0-test",
      loaderSha256,
      childSha256: sha256File(CHILD_SOURCE),
      parentSha256: sha256File(PARENT_SOURCE),
      zenVersion: "1.22.3b",
      platformVersion: "156.0.1",
      zenDir: readyZenDir,
      capabilities: { gZenWorkspaces: true, "gZenViewSplitter.splitTabs": true, ReaderMode: true },
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
        if (!this.options.holdReady) this.sendReady(LOADER_SHA, this.options.readyZenDir ?? zenDir);
        return;
      }
      if (frame.type === "cancel") {
        this.cancels.push(frame);
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
}

type Host = {
  pi: ExtensionAPI;
  ctx: ExtensionContext;
  notifications: string[];
  tools: Map<string, StubTool>;
  events: Map<string, (event: unknown, ctx: ExtensionContext) => unknown>;
  commands: Map<string, (args: string, ctx: ExtensionContext) => unknown>;
};

/** What the stub keeps from a registered tool: the handler, the schema and the approval surface omp reads. */
type StubTool = {
  execute: (...args: unknown[]) => Promise<AgentToolResult<unknown>>;
  parameters?: unknown;
  approval?: unknown;
  formatApprovalDetails?: (args: unknown) => string | string[] | undefined;
};

/** A stub host: the real schema builder, captured registrations, recorded notifications. */
function makeHost(cwd: string): Host {
  const notifications: string[] = [];
  const tools = new Map<string, StubTool>();
  const events = new Map<string, (event: unknown, ctx: ExtensionContext) => unknown>();
  const commands = new Map<string, (args: string, ctx: ExtensionContext) => unknown>();

  const ctx = {
    hasUI: true,
    agent: { kind: "main", id: "Main", name: "main", depth: 0 },
    cwd,
    // `confirm` is what the reinstall offer and the setup flows read; every test that reaches one
    // answers yes (a test that needs a no overrides it for its own duration).
    ui: { notify: (message: string) => notifications.push(message), confirm: () => true },
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
    registerCommand: (name: string, command: { handler: (args: string, ctx: ExtensionContext) => unknown }) => {
      commands.set(name, command.handler);
    },
  } as unknown as ExtensionAPI;

  return { pi, ctx, notifications, tools, events, commands };
}

/** The schema surface omp validates a call against before the handler runs (the omptype builder). */
type ToolSchema = { safeParse: (value: unknown) => { success: boolean } };

/**
 * The registered tool's own `parameters`, narrowed to the one member these tests read: the builder's
 * object also carries parse/clone/…, and its shape is not worth modelling here.
 */
function toolSchema(tool: StubTool): ToolSchema {
  const parameters = tool.parameters;
  // The builder's schemas are callable objects, so both typeof answers are valid here.
  const usable =
    parameters !== undefined &&
    parameters !== null &&
    (typeof parameters === "object" || typeof parameters === "function");
  if (usable && "safeParse" in parameters && typeof parameters.safeParse === "function") {
    return parameters as ToolSchema;
  }
  throw new Error("the registered tool has no schema");
}

/** Runs a registered slash command the way omp does, with the root context. */
async function runCommand(host: Host, name: string, args = ""): Promise<void> {
  const handler = host.commands.get(name);
  if (!handler) throw new Error(`command ${name} is not registered`);
  await handler(args, host.ctx);
}

async function callTool(host: Host, name: string, params: unknown = {}): Promise<AgentToolResult<unknown>> {
  const tool = host.tools.get(name);
  if (!tool) throw new Error(`tool ${name} is not registered`);
  return tool.execute("call-1", params, undefined, undefined, host.ctx);
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

test("the act budget tracks the granted permissions, the terminal hint mirrors consent, and the details name the ref", async () => {
  // The orphan-guard test above left its live link connected; release it, and drop the status record
  // it wrote, before a fresh loader offers a handoff.
  await shutdown(host);
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
    loader.send({ type: "event", name: "consent.pending", data: { asked: ["act"] } });
    await waitFor(() => host.notifications.some(message => message.includes("click Allow in Zen")));
    const hint = host.notifications.find(message => message.includes("click Allow in Zen")) ?? "";
    expect(hint).toContain("read and act on pages");

    // 3. Allow, then answer the pending call. The reply frame is queued behind the event frame, so
    //    awaiting the call proves the granted permissions were applied before the next call is made.
    loader.send({ type: "event", name: "consent.granted", data: { granted: ["act"] } });
    loader.reply(firstRequest, { ok: true, url: "https://example.com/", title: "Example Domain" });
    expect(textOf(await firstCall)).toContain("https://example.com/");

    // 4. With act granted, the next act call needs no person-wait: base 15 s only.
    const secondCall = callTool(host, "browser_act", { tabKey: TAB_KEY, action: "click", ref: "ab12.e1" });
    const secondRequest = await loader.nextRequest();
    expect(callSpy.mock.calls[1]?.[2]?.timeoutMs).toBe(15_000);
    expect(frameDeadline(secondRequest) - Date.now()).toBeLessThanOrEqual(15_000);
    loader.reply(secondRequest, { ok: true, url: "https://example.com/", title: "Example Domain" });
    expect((await secondCall).isError).not.toBe(true);

    // 5. Upload has no person-wait of its own any more: no BiDi start and no four 10 s steps, so with
    //    the act scope granted it is sent with the same base 15 s as every other tool (V1.1 sent
    //    45 s + 125 s here).
    writeFileSync(join(host.ctx.cwd, "form.txt"), "upload me");
    const upload = callTool(host, "browser_upload", { tabKey: TAB_KEY, ref: "ab12.e3", paths: ["form.txt"] });
    const uploadRequest = await loader.nextRequest();
    expect(uploadRequest.method).toBe("browser.upload");
    expect(callSpy.mock.calls[2]?.[2]?.timeoutMs).toBe(15_000);
    loader.reply(uploadRequest, { ok: true, tabKey: TAB_KEY, count: 1 });
    expect((await upload).isError).not.toBe(true);

    // 6. A snapshot names the elements the approval prompt has to describe.
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

    // 7. The prompt details: the tab it acts on, the action, and the element behind the ref.
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

    // 8. The approval itself is a per-call decision: exec tier, always prompting.
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

test("a ready frame from another Zen install is refused with E_CONFIG", async () => {
  // The plan's wrong-path guard: the loader reports the install folder it runs from (GreD), so a
  // loader that belongs to an install Hirozen is not set up for is refused before it is published.
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  const otherZen = tempDir("hirozen-index-other-zen-");
  // The loader runs from an install Hirozen is not set up for: its ready frame says so.
  const loader = new FakeLoader(profileDir, { readyZenDir: otherZen });
  const started = loader.start().catch(() => undefined);
  const result = await callTool(host, "zen_tabs");
  await started;
  const text = textOf(result);
  expect(text.startsWith("E_CONFIG")).toBe(true);
  expect(text).toContain(otherZen);
  expect(text).toContain(zenDir);
  expect(text).toContain("run /hirozen-setup");
  await shutdown(host);
}, 30_000);

test("session_start warns with the real config problem, not a generic setup hint", async () => {
  // A half-set env pair is the case the generic hint hid: the saved pair is irrelevant because env
  // wins, so the user has to be told which variable is missing.
  const handler = host.events.get("session_start");
  if (!handler) throw new Error("session_start was never registered");
  const saved = process.env.HIROZEN_PROFILE;
  delete process.env.HIROZEN_PROFILE;
  try {
    const before = host.notifications.length;
    handler({ type: "session_start" }, host.ctx);
    await waitFor(() => host.notifications.length > before);
    expect(host.notifications.at(-1)).toContain("HIROZEN_PROFILE is not set");
  } finally {
    process.env.HIROZEN_PROFILE = saved;
  }
}, 10_000);

test("a failed connect is not cached: the next call retries after a reinstall", async () => {
  // A Zen update wipes the loader, so verify() fails before the connect's first await. That used to
  // cache the rejected promise (the catch cleared it, then the assignment put it back), and the
  // reinstall the user had just accepted never took effect until omp restarted.
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  uninstall(zenDir);
  const wiped = await callTool(host, "zen_tabs");
  expect(textOf(wiped).startsWith("E_STALE_LOADER")).toBe(true);
  expect(textOf(wiped)).toContain(zenDir);

  install(zenDir);
  const loader = new FakeLoader(profileDir).on("zen.inventory", frame => loader.reply(frame, []));
  const started = loader.start().catch(() => undefined);
  const result = await callTool(host, "zen_tabs");
  await started;
  expect(result.isError).not.toBe(true);
  expect(loader.requests.length).toBe(1);
  await shutdown(host);
}, 30_000);

test("/hirozen-status reports the granted permissions and the missing capabilities", async () => {
  writeFileSync(
    join(profileDir, "hirozen-status.json"),
    JSON.stringify({
      state: "dormant",
      capabilities: { gZenWorkspaces: true, "gZenGlanceManager.openGlance": false, ReaderMode: true },
      consent: ["read", "act"],
      consentPending: ["network"],
    }),
  );
  const before = host.notifications.length;
  await runCommand(host, "hirozen-status");
  expect(host.notifications.length).toBeGreaterThan(before);
  const report = host.notifications.at(-1) ?? "";
  expect(report).toContain("consent=read,act (asking: network)");
  expect(report).toContain("capabilities=missing gZenGlanceManager.openGlance");
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
});

test("a loader code renders its own gloss and keeps the loader's message", async () => {
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  const loader = new FakeLoader(profileDir).on("browser.read", frame =>
    loader.send({
      id: frame.id,
      error: { code: "E_UNSUPPORTED", message: "this Zen lacks gZenViewSplitter.splitTabs; Hirozen needs an update" },
    }),
  );
  const started = loader.start().catch(() => undefined);
  const result = await callTool(host, "browser_read", { tabKey: TAB_KEY });
  await started;
  const text = textOf(result);
  expect(result.isError).toBe(true);
  expect(text.startsWith("E_UNSUPPORTED")).toBe(true);
  expect(text).toContain("this Zen lacks gZenViewSplitter.splitTabs");
  expect(text).toContain("update Hirozen");
  expect((result.details as { code?: string } | undefined)?.code).toBe("E_UNSUPPORTED");

  // A tab whose requests cannot be scoped has its own code, and its gloss must not send the agent to
  // /hirozen-status (nothing is missing from this Zen) nor offer zen_load_tab (the tab is loaded).
  loader.on("network.start", frame =>
    loader.send({
      id: frame.id,
      error: {
        code: "E_TAB_UNSCOPED",
        message: `tab ${TAB_KEY} has no browsing context id; Hirozen cannot tell its requests apart from other tabs'`,
      },
    }),
  );
  const unscoped = await callTool(host, "browser_network_start", { tabKey: TAB_KEY });
  const unscopedText = textOf(unscoped);
  expect(unscoped.isError).toBe(true);
  expect(unscopedText.startsWith("E_TAB_UNSCOPED")).toBe(true);
  expect(unscopedText).toContain("cannot be told apart from other tabs'");
  expect(unscopedText).toContain("try another tab"); // the gloss, not just the loader's message
  expect(unscopedText).not.toContain("/hirozen-status");
  expect(unscopedText).not.toContain("zen_load_tab");
  expect((unscoped.details as { code?: string } | undefined)?.code).toBe("E_TAB_UNSCOPED");
  await shutdown(host);
}, 30_000);

test("an aborted call is E_CANCELLED and sends cancel; E_STOPPED no longer blames the loader", async () => {
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  const loader = new FakeLoader(profileDir); // browser.read stays unanswered: omp aborts it
  const started = loader.start().catch(() => undefined);
  const tool = host.tools.get("browser_read");
  if (!tool) throw new Error("browser_read is not registered");

  const controller = new AbortController();
  const pending = tool
    .execute("call-cancel", { tabKey: TAB_KEY }, controller.signal, undefined, host.ctx)
    .then(result => result);
  const request = await loader.nextRequest();
  expect(request.method).toBe("browser.read");
  controller.abort();
  const result = await pending;
  await started;
  await waitFor(() => loader.cancels.length > 0);

  const text = textOf(result);
  expect(result.isError).toBe(true);
  expect(text.startsWith("E_CANCELLED")).toBe(true);
  expect(text).toContain("cancelled in omp; nothing was done; retry");
  expect((result.details as { code?: string } | undefined)?.code).toBe("E_CANCELLED");
  // The frame goes out before the rejection, so the loader can drop the stale Allow/Deny gate.
  expect(loader.cancels).toEqual([{ type: "cancel", id: request.id }]);

  // E_STOPPED is a closed link, not every cancel; its gloss must not claim the loader dropped a
  // session over a call omp itself abandoned.
  loader.on("browser.read", frame =>
    loader.send({ id: frame.id, error: { code: "E_STOPPED", message: "the Hirozen link is closed" } }),
  );
  const stopped = await callTool(host, "browser_read", { tabKey: TAB_KEY });
  const stoppedText = textOf(stopped);
  expect(stopped.isError).toBe(true);
  expect(stoppedText.startsWith("E_STOPPED")).toBe(true);
  expect(stoppedText).not.toContain("loader dropped the session");
  // A close can hit an action already under way (#failAll rejects every pending call), so the gloss
  // must not promise that nothing was done.
  expect(stoppedText).not.toContain("nothing was done");
  expect(stoppedText).toContain("may or may not have run");
  expect(stoppedText).toContain("retry");
  await shutdown(host);
}, 30_000);

test("hover is an act action, and the prompt says what it hovers over", () => {
  const tool = host.tools.get("browser_act");
  if (!tool) throw new Error("browser_act is not registered");
  // omp validates a call against the tool's schema before the handler runs, so the enum is the gate.
  const schema = toolSchema(tool);
  expect(schema.safeParse({ tabKey: TAB_KEY, action: "hover", ref: "ab12.e9" }).success).toBe(true);
  expect(schema.safeParse({ tabKey: TAB_KEY, action: "dblclick", ref: "ab12.e9" }).success).toBe(false);

  const args = { tabKey: TAB_KEY, action: "hover", ref: "ab12.e9" };
  const details = tool.formatApprovalDetails?.(args);
  const lines = Array.isArray(details) ? details.join("\n") : String(details ?? "");
  expect(lines).toContain("hover over");
  expect(lines).toContain("ab12.e9");
  const decision = typeof tool.approval === "function" ? tool.approval(args) : tool.approval;
  expect(decision).toMatchObject({ tier: "exec", policy: "prompt" });
});

test('browser_read mode "article" sends the mode and renders the byline', async () => {
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  const tool = host.tools.get("browser_read");
  if (!tool) throw new Error("browser_read is not registered");
  const schema = toolSchema(tool);
  expect(schema.safeParse({ tabKey: TAB_KEY }).success).toBe(true);
  expect(schema.safeParse({ tabKey: TAB_KEY, mode: "article" }).success).toBe(true);
  expect(schema.safeParse({ tabKey: TAB_KEY, mode: "reader" }).success).toBe(false);

  const loader = new FakeLoader(profileDir).on("browser.read", frame => {
    const params = frame.params;
    if (params && typeof params === "object" && "mode" in params && params.mode === "article") {
      loader.reply(frame, {
        tabKey: TAB_KEY,
        url: "https://example.com/story",
        title: "A story",
        byline: "By A. Writer",
        text: "Once upon a time.",
        truncated: false,
      });
      return;
    }
    loader.reply(frame, {
      tabKey: TAB_KEY,
      url: "https://example.com/",
      title: "Example Domain",
      text: "Visible text",
      truncated: false,
    });
  });
  const started = loader.start().catch(() => undefined); // reported by the assertions, not as an unhandled rejection

  const articleCall = callTool(host, "browser_read", { tabKey: TAB_KEY, mode: "article" });
  const articleRequest = await loader.nextRequest();
  expect(articleRequest.method).toBe("browser.read");
  expect(articleRequest.params).toMatchObject({ tabKey: TAB_KEY, mode: "article" });
  const article = await articleCall;
  expect(article.isError).not.toBe(true);
  const articleText = textOf(article);
  expect(articleText).toContain("# A story");
  expect(articleText).toContain("https://example.com/story");
  expect(articleText).toContain("By A. Writer");
  expect(articleText).toContain("Once upon a time.");
  expect(article.details).toMatchObject({ mode: "article", byline: "By A. Writer", chars: 17 });

  // A plain read is the loader's default: it names no mode, and renders the visible text alone.
  const plainCall = callTool(host, "browser_read", { tabKey: TAB_KEY });
  const plainRequest = await loader.nextRequest();
  expect(plainRequest.params).toEqual({ tabKey: TAB_KEY });
  const plain = await plainCall;
  const plainText = textOf(plain);
  expect(plainText).toContain("Visible text");
  expect(plainText).not.toContain("By A. Writer");
  expect(plain.details).toMatchObject({ mode: "text" });

  await shutdown(host);
  await started;
}, 30_000);

test("zen_load_tab loads a lazy tab and names the restored page", async () => {
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  const tool = host.tools.get("zen_load_tab");
  if (!tool) throw new Error("zen_load_tab is not registered");
  const args = { tabKey: TAB_KEY };
  const details = tool.formatApprovalDetails?.(args);
  const lines = Array.isArray(details) ? details.join("\n") : String(details ?? "");
  expect(lines).toContain(TAB_KEY);
  expect(lines).toContain("without selecting it");
  const decision = typeof tool.approval === "function" ? tool.approval(args) : tool.approval;
  expect(decision).toMatchObject({ tier: "exec", policy: "prompt" });

  const loader = new FakeLoader(profileDir).on("zen.loadTab", frame =>
    loader.reply(frame, { tabKey: TAB_KEY, url: "https://example.com/restored", title: "Restored page" }),
  );
  const started = loader.start().catch(() => undefined);

  const call = callTool(host, "zen_load_tab", args);
  const request = await loader.nextRequest();
  expect(request.method).toBe("zen.loadTab");
  expect(request.params).toEqual({ tabKey: TAB_KEY });
  // Loading is an act: with nothing granted the call carries the person-wait, exactly like browser_act.
  const budget = frameDeadline(request) - Date.now();
  expect(budget).toBeGreaterThan(125_000);
  expect(budget).toBeLessThanOrEqual(140_000);

  const result = await call;
  expect(result.isError).not.toBe(true);
  const text = textOf(result);
  expect(text).toContain("Loaded tab");
  expect(text).toContain("selected tab are unchanged");
  expect(text).toContain("# Restored page");
  expect(text).toContain("https://example.com/restored");
  expect(result.details).toMatchObject({ tabKey: TAB_KEY, url: "https://example.com/restored", title: "Restored page" });

  await shutdown(host);
  await started;
}, 30_000);

test("/hirozen-grant covers the granted tab until the tab leaves the site", async () => {
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  const loader = new FakeLoader(profileDir).on("zen.inventory", frame => loader.reply(frame, INVENTORY));
  // The act reports where the page landed, which is what the plugin's tab cache learns from.
  let landed = "https://example.com/";
  loader.on("browser.act", frame => loader.reply(frame, { ok: true, url: landed, title: "Example Domain" }));
  const started = loader.start().catch(() => undefined);

  const act = host.tools.get("browser_act");
  if (!act) throw new Error("browser_act is not registered");
  const click = { tabKey: TAB_KEY, action: "click", ref: "ab12.e1" };

  // zen_tabs is the tab directory a grant is anchored to (tabKey -> its URL).
  expect((await callTool(host, "zen_tabs")).isError).not.toBe(true);
  expect((await loader.nextRequest()).method).toBe("zen.inventory"); // the frame that call leaves queued
  const beforeGrant = typeof act.approval === "function" ? act.approval(click) : act.approval;
  expect(beforeGrant).toMatchObject({ tier: "exec", policy: "prompt" });

  // The command confirms first, then says what it granted for how long.
  const before = host.notifications.length;
  await runCommand(host, "hirozen-grant", `${TAB_KEY} 5`);
  expect(host.notifications.length).toBeGreaterThan(before);
  const grantNotice = host.notifications.at(-1) ?? "";
  expect(grantNotice).toContain("https://example.com");
  expect(grantNotice).toContain("5 min");

  // While the grant covers the call, omp allows the act outright instead of prompting.
  const granted = typeof act.approval === "function" ? act.approval(click) : act.approval;
  expect(granted).toMatchObject({ tier: "write", policy: "allow" });
  const grantedReason = granted && typeof granted === "object" && "reason" in granted ? granted.reason : undefined;
  expect(typeof grantedReason).toBe("string");
  expect(String(grantedReason)).toContain("https://example.com");
  // Never covered by any grant: navigate (it can leave the site), and an act in another tab.
  const navigate =
    typeof act.approval === "function"
      ? act.approval({ tabKey: TAB_KEY, action: "navigate", url: "https://example.com/next" })
      : act.approval;
  expect(navigate).toMatchObject({ tier: "exec", policy: "prompt" });
  const otherTab =
    typeof act.approval === "function"
      ? act.approval({ tabKey: "1759000000000-cccc", action: "click", ref: "ab12.e2" })
      : act.approval;
  expect(otherTab).toMatchObject({ tier: "exec", policy: "prompt" });

  // The covered call also tells the loader which site the grant was for, so a stale cache cannot act.
  const call = callTool(host, "browser_act", click);
  const request = await loader.nextRequest();
  expect(request.method).toBe("browser.act");
  expect(request.params).toMatchObject({ tabKey: TAB_KEY, action: "click", grantOrigin: "https://example.com" });
  expect((await call).isError).not.toBe(true);

  // /hirozen-status lists the live grants.
  await runCommand(host, "hirozen-status");
  expect(host.notifications.at(-1) ?? "").toContain("grants: https://example.com");

  // A click that navigated the tab off the granted site: the reply is where the tab is now, so the
  // call after it prompts again (the grant is anchored to the origin it was given for). The approval
  // of that next call still sees the old cache - the reply above has not landed yet - so it is granted
  // and names the origin it was given for; the loader is what refuses it.
  landed = "https://elsewhere.example/page";
  expect(typeof act.approval === "function" ? act.approval(click) : act.approval).toMatchObject({ tier: "write", policy: "allow" });
  const moved = callTool(host, "browser_act", click);
  const movedRequest = await loader.nextRequest();
  expect(movedRequest.params).toMatchObject({ grantOrigin: "https://example.com" }); // the old cache
  expect((await moved).isError).not.toBe(true);
  const afterMove = typeof act.approval === "function" ? act.approval(click) : act.approval;
  expect(afterMove).toMatchObject({ tier: "exec", policy: "prompt" });
  const next = callTool(host, "browser_act", click);
  const nextRequest = await loader.nextRequest();
  expect(nextRequest.params).not.toHaveProperty("grantOrigin");
  expect((await next).isError).not.toBe(true);

  // Granting again covers the new site, a cancelled confirm grants nothing, and clear restores prompts.
  await runCommand(host, "hirozen-grant", `${TAB_KEY} 5`);
  expect(typeof act.approval === "function" ? act.approval(click) : act.approval).toMatchObject({ tier: "write", policy: "allow" });
  const cancelled = spyOn(host.ctx.ui, "confirm").mockResolvedValue(false);
  await runCommand(host, "hirozen-grant", `${TAB_KEY} 5`);
  cancelled.mockRestore();
  expect(host.notifications.at(-1) ?? "").toContain("no grant");
  // The earlier grant still stands: only clear removes it.
  expect(typeof act.approval === "function" ? act.approval(click) : act.approval).toMatchObject({ tier: "write", policy: "allow" });
  await runCommand(host, "hirozen-grant", "clear");
  expect(host.notifications.at(-1) ?? "").toContain("cleared");
  expect(typeof act.approval === "function" ? act.approval(click) : act.approval).toMatchObject({ tier: "exec", policy: "prompt" });

  // Minutes outside 1 to 60, and a target that is neither a known tab nor an origin, are refused.
  await runCommand(host, "hirozen-grant", `${TAB_KEY} 90`);
  expect(host.notifications.at(-1) ?? "").toContain("1 to 60");
  await runCommand(host, "hirozen-grant", "1759000000000-zzzz 5");
  expect(host.notifications.at(-1) ?? "").toContain("no such tab");

  await shutdown(host);
  await started;
}, 30_000);

test("E_GRANT_STALE corrects the tab cache, so the retry prompts instead of looping", async () => {
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  const loader = new FakeLoader(profileDir).on("zen.inventory", frame => loader.reply(frame, INVENTORY));
  loader.on("browser.act", frame =>
    loader.send({
      id: frame.id,
      error: { code: "E_GRANT_STALE", message: "the tab left the granted site; retry to be asked", url: "https://elsewhere.example/page" },
    }),
  );
  const started = loader.start().catch(() => undefined);

  const act = host.tools.get("browser_act");
  if (!act) throw new Error("browser_act is not registered");
  const click = { tabKey: TAB_KEY, action: "click", ref: "ab12.e1" };
  await callTool(host, "zen_tabs");
  expect((await loader.nextRequest()).method).toBe("zen.inventory"); // the frame that call leaves queued
  await runCommand(host, "hirozen-grant", `${TAB_KEY} 5`);
  expect(typeof act.approval === "function" ? act.approval(click) : act.approval).toMatchObject({ tier: "write", policy: "allow" });

  // The loader's cache check refuses the call: the tab is not on the granted site any more.
  const refused = await callTool(host, "browser_act", click);
  expect((await loader.nextRequest()).params).toMatchObject({ grantOrigin: "https://example.com" });
  const text = textOf(refused);
  expect(refused.isError).toBe(true);
  expect(text.startsWith("E_GRANT_STALE")).toBe(true);
  expect(text).toContain("the tab left the granted site"); // the loader's own message is kept
  expect(text).toContain("retry asks you"); // the plugin's gloss

  // The URL the error carried became the tab's known URL, so the retry is prompted, not granted.
  expect(typeof act.approval === "function" ? act.approval(click) : act.approval).toMatchObject({ tier: "exec", policy: "prompt" });
  const retry = callTool(host, "browser_act", click);
  const retryRequest = await loader.nextRequest();
  expect(retryRequest.params).not.toHaveProperty("grantOrigin");
  expect((await retry).isError).toBe(true);

  await runCommand(host, "hirozen-grant", "clear");
  await shutdown(host);
  await started;
}, 30_000);

test("a granted act carries the origin its approval decided, not one recomputed after the link await", async () => {
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  const loader = new FakeLoader(profileDir).on("zen.inventory", frame => loader.reply(frame, INVENTORY));
  loader.on("browser.act", frame => loader.reply(frame, { ok: true, url: "https://example.com/", title: "Example Domain" }));
  // The parallel read whose reply moves the plugin's tab cache off the granted origin.
  loader.on("browser.read", frame =>
    loader.reply(frame, { tabKey: TAB_KEY, url: "https://elsewhere.example/", title: "Elsewhere", text: "elsewhere", truncated: false }),
  );
  const started = loader.start().catch(() => undefined);

  const act = host.tools.get("browser_act");
  if (!act) throw new Error("browser_act is not registered");
  const click = { tabKey: TAB_KEY, action: "click", ref: "ab12.e1" };
  await callTool(host, "zen_tabs");
  expect((await loader.nextRequest()).method).toBe("zen.inventory"); // the frame that call leaves queued
  await runCommand(host, "hirozen-grant", `${TAB_KEY} 5`);
  // omp allows this exact call outright: the grant covers the tab's cached origin.
  expect(typeof act.approval === "function" ? act.approval(click) : act.approval).toMatchObject({ tier: "write", policy: "allow" });

  // A parallel tool reply moves the cache to another origin before the act runs. The approval already
  // happened, so the act must still name the origin it was allowed for: the loader's own check - not a
  // cache this plugin re-read after awaiting the link - is what decides whether that origin is live.
  const read = callTool(host, "browser_read", { tabKey: TAB_KEY });
  expect((await loader.nextRequest()).method).toBe("browser.read");
  expect((await read).isError).not.toBe(true);
  // omp asks the approval again when the tool starts (its render path). That answer is "prompt" now -
  // and it must not erase the decision the gate already made for this exact call.
  expect(typeof act.approval === "function" ? act.approval(click) : act.approval).toMatchObject({ tier: "exec", policy: "prompt" });
  const call = callTool(host, "browser_act", click);
  const request = await loader.nextRequest();
  expect(request.method).toBe("browser.act");
  expect(request.params).toMatchObject({ tabKey: TAB_KEY, action: "click", grantOrigin: "https://example.com" });
  expect((await call).isError).not.toBe(true);

  // A call the approval did not grant carries no origin at all: it is the person's own yes, and the
  // check exists for acts that ran without one.
  const prompted = { tabKey: "1759000000000-cccc", action: "click", ref: "ab12.e1" };
  expect(typeof act.approval === "function" ? act.approval(prompted) : act.approval).toMatchObject({ tier: "exec", policy: "prompt" });
  const plain = callTool(host, "browser_act", prompted);
  expect((await loader.nextRequest()).params).not.toHaveProperty("grantOrigin");
  expect((await plain).isError).not.toBe(true);

  await runCommand(host, "hirozen-grant", "clear");
  await shutdown(host);
  await started;
}, 30_000);

test("browser_cookies, browser_storage and browser_downloads send the agreed frames and render them", async () => {
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  const callSpy = spyOn(ZenLink.prototype, "call");
  try {
    const loader = new FakeLoader(profileDir).on("zen.inventory", frame => loader.reply(frame, INVENTORY));
    loader.on("network.cookies", frame =>
      loader.reply(frame, {
        tabKey: TAB_KEY,
        url: "https://example.com/",
        cookies: [
          {
            name: "sid",
            value: "<8 chars>",
            domain: "example.com",
            path: "/",
            expires: 1_800_000_000_000,
            secure: true,
            httpOnly: true,
            sameSite: "lax",
          },
          // `sameSite` is a name the loader maps from nsICookie's integer; "unset" is a cookie with no
          // sameSite attribute, "none" one that asks for SameSite=None.
          { name: "theme", value: "dark", domain: "example.com", path: "/", expires: null, secure: false, httpOnly: false, sameSite: "unset" },
          { name: "csrf", value: "<10 chars>", domain: "example.com", path: "/", expires: null, secure: true, httpOnly: false, sameSite: "none" },
        ],
        truncated: false,
      }),
    );
    loader.on("network.storage", frame =>
      loader.reply(frame, {
        tabKey: TAB_KEY,
        url: "https://example.com/",
        kind: "local",
        entries: [
          { key: "token", value: "<9 chars>" },
          { key: "theme", value: "dark" },
        ],
        truncated: false,
      }),
    );
    loader.on("network.downloads", frame =>
      loader.reply(frame, {
        downloads: [
          {
            source: "https://example.com/file.zip",
            target: "C:\\Users\\x\\Downloads\\file.zip",
            state: "succeeded",
            bytes: 12_345_678,
            totalBytes: 12_345_678,
            startedAt: 1_800_000_000_000,
          },
        ],
        truncated: false,
      }),
    );
    const started = loader.start().catch(() => undefined);

    // 1. Nothing granted yet: a network call carries the same person wait as an act (15 s + 125 s).
    expect((await callTool(host, "zen_tabs")).isError).not.toBe(true);
    expect((await loader.nextRequest()).method).toBe("zen.inventory"); // the frame that call leaves queued
    const cookiesCall = callTool(host, "browser_cookies", { tabKey: TAB_KEY });
    const cookiesRequest = await loader.nextRequest();
    expect(cookiesRequest.method).toBe("network.cookies");
    expect(cookiesRequest.params).toEqual({ tabKey: TAB_KEY }); // no reveal unless asked for
    expect(frameDeadline(cookiesRequest) - Date.now()).toBeGreaterThan(125_000);
    const cookiesText = textOf(await cookiesCall);
    expect(cookiesText).toContain("https://example.com/");
    expect(cookiesText).toContain("sid=<8 chars>");
    expect(cookiesText).toContain("expires=2027-01-15T08:00:00.000Z");
    expect(cookiesText).toContain("flags=secure,httpOnly,sameSite=lax");
    expect(cookiesText).toContain("theme=dark");
    expect(cookiesText).toContain("expires=session");
    // "unset" (no sameSite attribute) is not a flag; "none" is, spelled out.
    expect(cookiesText).toContain("- theme=dark domain=example.com path=/ expires=session\n");
    expect(cookiesText).toContain("flags=secure,sameSite=none");

    // 2. Reading a value itself is a different decision: it prompts, and the wire says so.
    const cookiesTool = host.tools.get("browser_cookies");
    if (!cookiesTool) throw new Error("browser_cookies is not registered");
    const plain = typeof cookiesTool.approval === "function" ? cookiesTool.approval({ tabKey: TAB_KEY }) : cookiesTool.approval;
    expect(plain).toBe("read");
    const reveal = typeof cookiesTool.approval === "function" ? cookiesTool.approval({ tabKey: TAB_KEY, reveal: true }) : cookiesTool.approval;
    expect(reveal).toMatchObject({ tier: "exec", policy: "prompt" });
    const revealDetails = cookiesTool.formatApprovalDetails?.({ tabKey: TAB_KEY, reveal: true });
    expect(Array.isArray(revealDetails) ? revealDetails.join("\n") : String(revealDetails ?? "")).toContain("WITH");

    // 3. The Allow for network has to reach the plugin before the next call, so that call is already
    //    on the base budget: a round trip after the event is what proves the event was handled.
    loader.send({ type: "event", name: "consent.granted", data: { granted: ["network"] } });
    expect((await callTool(host, "zen_tabs")).isError).not.toBe(true);
    expect((await loader.nextRequest()).method).toBe("zen.inventory");
    const storageCall = callTool(host, "browser_storage", { tabKey: TAB_KEY, kind: "local" });
    const storageRequest = await loader.nextRequest();
    expect(storageRequest.method).toBe("network.storage");
    expect(storageRequest.params).toEqual({ tabKey: TAB_KEY, kind: "local" });
    expect(callSpy.mock.calls.at(-1)?.[2]?.timeoutMs).toBe(15_000);
    const storageText = textOf(await storageCall);
    expect(storageText).toContain("token=<9 chars>");
    expect(storageText).toContain("theme=dark");

    const storageTool = host.tools.get("browser_storage");
    if (!storageTool) throw new Error("browser_storage is not registered");
    const storageSchema = toolSchema(storageTool);
    expect(storageSchema.safeParse({ tabKey: TAB_KEY, kind: "session" }).success).toBe(true);
    expect(storageSchema.safeParse({ tabKey: TAB_KEY, kind: "indexeddb" }).success).toBe(true);
    expect(storageSchema.safeParse({ tabKey: TAB_KEY, kind: "cookie" }).success).toBe(false);
    expect(storageSchema.safeParse({ tabKey: TAB_KEY, kind: "local", reveal: true }).success).toBe(true);
    expect(storageSchema.safeParse({ tabKey: TAB_KEY, kind: "local", reveal: "yes" }).success).toBe(false);

    // 4. Downloads take no tab and no parameters, and are a plain read.
    const downloadsTool = host.tools.get("browser_downloads");
    if (!downloadsTool) throw new Error("browser_downloads is not registered");
    expect(downloadsTool.approval).toBe("read");
    expect(toolSchema(downloadsTool).safeParse({}).success).toBe(true);
    const downloadsCall = callTool(host, "browser_downloads");
    const downloadsRequest = await loader.nextRequest();
    expect(downloadsRequest.method).toBe("network.downloads");
    expect(downloadsRequest.params).toEqual({});
    const downloadsText = textOf(await downloadsCall);
    expect(downloadsText).toContain("succeeded");
    expect(downloadsText).toContain("https://example.com/file.zip");
    expect(downloadsText).toContain("C:\\Users\\x\\Downloads\\file.zip");
    expect(downloadsText).toContain("2027-01-15T08:00:00.000Z");

    await runCommand(host, "hirozen-grant", "clear");
    await shutdown(host);
    await started;
  } finally {
    callSpy.mockRestore();
  }
}, 30_000);

test("the network recording tools start, read and stop a tab's request buffer", async () => {
  rmSync(join(profileDir, "hirozen-status.json"), { force: true });
  const loader = new FakeLoader(profileDir).on("zen.inventory", frame => loader.reply(frame, INVENTORY));
  loader.on("network.start", frame => loader.reply(frame, { tabKey: TAB_KEY, url: "https://example.com/", active: true }));
  loader.on("network.read", frame =>
    loader.reply(frame, {
      tabKey: TAB_KEY,
      url: "https://example.com/",
      active: true,
      entries: [
        {
          method: "GET",
          url: "https://example.com/api/data",
          status: 200,
          contentType: "application/json",
          startedAt: 1_800_000_000_000,
          ms: 42,
          requestHeaders: { accept: "*/*", cookie: "<redacted>" },
          responseHeaders: { "content-type": "application/json", "set-cookie": "<redacted>" },
        },
        {
          method: "POST",
          url: "https://example.com/api/save",
          status: null,
          contentType: null,
          startedAt: 1_800_000_001_000,
          ms: null,
          requestHeaders: { authorization: "<redacted>" },
          responseHeaders: {},
        },
      ],
      truncated: 3,
    }),
  );
  loader.on("network.stop", frame => loader.reply(frame, { tabKey: TAB_KEY, url: "https://example.com/", active: false, dropped: 2 }));
  const started = loader.start().catch(() => undefined);
  // A round trip first: the socket has to be up before the frames below are answered, and zen_tabs
  // leaves its own frame queued for the drain.
  expect((await callTool(host, "zen_tabs")).isError).not.toBe(true);
  expect((await loader.nextRequest()).method).toBe("zen.inventory");

  const startTool = host.tools.get("browser_network_start");
  if (!startTool) throw new Error("browser_network_start is not registered");
  // Starting a recording is an exec-tier action: it always prompts.
  expect(typeof startTool.approval === "function" ? startTool.approval({ tabKey: TAB_KEY }) : startTool.approval).toMatchObject({
    tier: "exec",
    policy: "prompt",
  });
  const startDetails = startTool.formatApprovalDetails?.({ tabKey: TAB_KEY });
  expect(Array.isArray(startDetails) ? startDetails.join("\n") : String(startDetails ?? "")).toContain("redacted");

  const startCall = callTool(host, "browser_network_start", { tabKey: TAB_KEY });
  const startRequest = await loader.nextRequest();
  expect(startRequest.method).toBe("network.start");
  expect(startRequest.params).toEqual({ tabKey: TAB_KEY });
  expect(textOf(await startCall)).toContain("Watching tab");

  for (const name of ["browser_network_read", "browser_network_stop"]) {
    const tool = host.tools.get(name);
    if (!tool) throw new Error(`${name} is not registered`);
    expect(tool.approval).toBe("read");
  }
  const readCall = callTool(host, "browser_network_read", { tabKey: TAB_KEY });
  expect((await loader.nextRequest()).method).toBe("network.read");
  const readText = textOf(await readCall);
  expect(readText).toContain("GET 200 https://example.com/api/data");
  expect(readText).toContain("application/json, 42 ms");
  expect(readText).toContain("cookie=<redacted>");
  expect(readText).toContain("set-cookie=<redacted>");
  expect(readText).toContain("POST (no response) https://example.com/api/save");
  expect(readText).toContain("authorization=<redacted>");
  expect(readText).toContain("3 more request(s)");

  const stopCall = callTool(host, "browser_network_stop", { tabKey: TAB_KEY });
  expect((await loader.nextRequest()).method).toBe("network.stop");
  const stopText = textOf(await stopCall);
  expect(stopText).toContain("Stopped watching tab");
  expect(stopText).toContain("2 buffered request(s) were dropped");

  await runCommand(host, "hirozen-grant", "clear");
  await shutdown(host);
  await started;
}, 30_000);

test("the reinstall offer names /hirozen-attach only when that Zen is running", async () => {
  // A Zen update wipes the loader while zen.exe is still there: the offer fires on session_start. The
  // attach hint needs a live process, and this install folder (a temp dir) has none, so the notice
  // must not offer it (the restart advice always applies).
  uninstall(zenDir);
  const handler = host.events.get("session_start");
  if (!handler) throw new Error("session_start was never registered");
  const before = host.notifications.length;
  handler({ type: "session_start" }, host.ctx);
  await waitFor(() => host.notifications.length > before, 20_000);
  const notice = host.notifications.at(-1) ?? "";
  expect(notice).toContain("reinstalled into");
  expect(notice).toContain("Restart Zen to load it.");
  expect(notice).not.toContain("/hirozen-attach");
}, 30_000);
