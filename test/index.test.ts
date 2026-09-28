// Plugin-level regression test for the orphaned-link guard in src/index.ts (doc §15.1 B, V1.1).
//
// The bug: `session_shutdown` nulls `connectPromise` while a connect is in flight, so a second call
// runs a second connect; when the abandoned attempt later fails its stale-sha check it closes its own
// link, and that late close used to release the *live* module state. A tool call after it then built a
// third connect, which `findOwner` refused with E_IN_USE naming omp's own pid.
//
// The host is a stub `pi`/`ctx` (pattern: temp/t6-smoke.ts); a real WebSocket client plays the loader.
import { afterAll, expect, test } from "bun:test";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { zod } from "@oh-my-pi/pi-coding-agent";
import type { AgentToolResult, ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

import hirozen from "../src/index";
import { install, sha256File } from "../src/install";

/** `loader/loader.sys.mjs` as this checkout hashes it: the sha the plugin accepts in `ready`. */
const LOADER_SHA = sha256File(fileURLToPath(new URL("../loader/loader.sys.mjs", import.meta.url)));

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

  /** The `ready` frame, sent by `start()` unless `holdReady` left it for the test to release. */
  sendReady(loaderSha256 = LOADER_SHA): void {
    this.send({
      type: "ready",
      loaderVersion: "1.0.0-test",
      loaderSha256,
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
  tools: Map<string, { execute: (...args: unknown[]) => Promise<AgentToolResult<unknown>> }>;
  events: Map<string, (event: unknown, ctx: ExtensionContext) => unknown>;
};

/** A stub host: the real schema builder, captured registrations, recorded notifications. */
function makeHost(cwd: string): Host {
  const notifications: string[] = [];
  const tools = new Map<string, { execute: (...args: unknown[]) => Promise<AgentToolResult<unknown>> }>();
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
    registerTool: (tool: { name: string; execute: (...args: unknown[]) => Promise<AgentToolResult<unknown>> }) => {
      tools.set(tool.name, tool);
    },
    registerCommand: () => undefined,
  } as unknown as ExtensionAPI;

  return { pi, ctx, notifications, tools, events };
}

async function callTool(host: Host, name: string, params: unknown = {}): Promise<AgentToolResult<unknown>> {
  const tool = host.tools.get(name);
  if (!tool) throw new Error(`tool ${name} is not registered`);
  return tool.execute("call-1", params, undefined, undefined, host.ctx);
}

function textOf(result: AgentToolResult<unknown>): string {
  return result.content.map(item => (item.type === "text" ? item.text : `<${item.type}>`)).join("\n");
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
