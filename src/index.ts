// Hirozen omp extension: read-only Zen browser tools over the Hirozen loader link (blob: src/link.ts).
//
// The factory body registers only (tools, commands, lifecycle handlers): omp also loads extensions
// during `omp plugin install` validation and re-runs the factory inside every subagent, so load time
// must have no side effects. The link is created lazily by the first tool call of the root session,
// which is also the only instance that registers the session_shutdown teardown.
//
// Every tool checks in the plan's fixed order: root/UI -> sticky stop -> config -> connect.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import type { AgentToolResult, ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

import { attachNow } from "./attach";
import { type VerifyResult, install, sha256File, verify } from "./install";
import { HirozenError, type LinkCloseInfo, type LoaderEvent, type StopKind, ZenLink, readStatusFile } from "./link";

/** `loader/loader.sys.mjs` in this checkout: the hash install() pins and the running loader must report. */
const LOADER_SOURCE = fileURLToPath(new URL("../loader/loader.sys.mjs", import.meta.url));

// BiDi is started by the loader on the first browser.* call; the Zen "Allow remote control?" prompt
// has no timeout of its own, so consent deserves a long budget and every command after it a short one.
const CONSENT_TIMEOUT_MS = 150_000;
const RUNNING_TIMEOUT_MS = 15_000;
/** Repeat the "click Allow" notice while the dialog is still unanswered. */
const CONSENT_REPEAT_MS = 60_000;

const CONSENT_NOTICE =
  'Zen is showing the "Allow remote control?" dialog — click Allow so omp can read this Zen session.';

/** Per-kind wording of a sticky stop; the tool refusal, the notice and /hirozen-status all use it. */
const STOP_TEXT: Record<StopKind, string> = {
  "zen-stop": "the Hirozen session was stopped in Zen — run /hirozen-connect (or /hirozen-attach) to start a new one.",
  "zen-disconnect":
    "remote control was turned off in Zen (Disconnect) — run /hirozen-connect (or /hirozen-attach) to allow it again.",
  "zen-disabled":
    "remote control was disabled permanently in Zen; re-enable remote.experimental.dynamicstart.enabled in about:config, then run /hirozen-connect.",
};

/** Loader error codes the plugin owns; their message is already written for the user. */
const PLUGIN_CODES: Record<string, true> = {
  E_AUTH: true,
  E_CONFIG: true,
  E_IN_USE: true,
  E_NO_UI: true,
  E_STALE_LOADER: true,
  E_TIMEOUT: true,
  E_UNKNOWN: true,
};

/** Plain-English gloss per loader code, followed by the loader's own message. */
const CODE_TEXT: Record<string, string> = {
  E_BIDI_LOST: "the remote-control (BiDi) session was lost mid-call — the socket or the browser session went away",
  E_COMPROMISE: "another debugger had already started remote control in Zen; Hirozen stopped it and refused to continue",
  E_DENIED: "the remote-control prompt was denied in Zen",
  E_DISABLED_IN_ZEN:
    "remote control was disabled permanently in Zen; re-enable remote.experimental.dynamicstart.enabled in about:config to use browser_* again",
  E_INTERNAL: "the Zen loader hit an unexpected internal error",
  E_PORT_BUSY: "127.0.0.1:9222 cannot be bound - the port is in use by another program or reserved by Windows (check `netsh int ipv4 show excludedportrange protocol=tcp`); Zen was left untouched",
  E_PRIVATE: "that tab is in a private window, which Hirozen never touches",
  E_PRIVILEGED_PAGE: "that tab is a privileged page, which Hirozen refuses to read",
  E_READ_FAILED: "the loader returned no usable page data (the page may still be loading, crashed or reloading)",
  E_STOP_FAILED: "Hirozen's own remote-control stop failed; the session may still be up in Zen",
  E_STOPPED: "the loader dropped the session (fail-closed); retry, or run /hirozen-connect",
  E_SYSTEM_ACCESS: "MOZ_REMOTE_ALLOW_SYSTEM_ACCESS is set; Hirozen refuses to start remote control with system access",
  E_TAB_INACTIVE_SPACE: "that tab is in an inactive space, and Hirozen never switches spaces",
  E_TAB_UNKNOWN: "no such tab; list the tabs with zen_tabs",
  E_TAB_UNLOADED: "that tab is not loaded; open it in Zen first (Hirozen never loads tabs)",
  E_UNKNOWN_METHOD: "the installed loader does not support that method; run /hirozen-install, restart Zen",
  E_UNSAFE_START: "the remote-control start failed Hirozen's safety assertions after the fact",
};

/** Per-window tab inventory, exactly as `zen.inventory` sends it. */
type ZenSpace = { uuid: string; name: string; icon: string | null; containerTabId: number; active: boolean };
type ZenTab = {
  tabKey: string;
  title: string;
  url: string;
  space: string | null;
  pinned: boolean;
  essential: boolean;
  lazy: boolean;
  selected: boolean;
};
type ZenWindow = { activeSpace: string | null; spaces: ZenSpace[]; tabs: ZenTab[] };
/** `zen.spaces` answers with the same windows, minus the tabs. */
type ZenSpaceWindow = { activeSpace: string | null; spaces: ZenSpace[] };
type ZenRead = { tabKey: string; url: string; title: string; text: string; truncated: boolean };
type ZenScreenshot = { tabKey: string; mimeType: string; data: string };

/** A tool-visible failure: the contract's code plus text the model can read. */
type Failure = { code: string; text: string; details?: Record<string, unknown> };

// ---------------------------------------------------------------------------------------------
// Link lifecycle (module state is per process, which is where the root session lives)
// ---------------------------------------------------------------------------------------------

let link: ZenLink | null = null;
/** Root context that owns the live link; it supplies the managed timers for the consent notice. */
let linkCtx: ExtensionContext | null = null;
let connectPromise: Promise<ZenLink> | null = null;
/**
 * Bumped by every connect attempt and by releaseLink(). An attempt publishes its link, and clears
 * connectPromise in its catch, only while its generation is still the current one: an attempt that
 * session_shutdown superseded must not touch the state a newer attempt owns (doc §15.1 B).
 */
let connectGen = 0;
let bidiPhase: "off" | "starting" | "running" = "off";
let consentRepeat: (() => void) | null = null;
/** Set by an in-Zen stop (close 4010/4011); only /hirozen-connect and /hirozen-attach clear it. */
let stopKind: StopKind | null = null;
let teardownHooked = false;
let warnedAboutBrowserMcp = false;

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** The readable half of an error: plugin codes keep their message, loader codes get a gloss first. */
function describeError(error: unknown): Failure {
  if (!(error instanceof HirozenError)) return { code: "E_UNKNOWN", text: messageOf(error) };
  const { code, message } = error;
  const details = error.pid === undefined ? undefined : { pid: error.pid };
  if (PLUGIN_CODES[code] === true) {
    if (code === "E_AUTH") {
      return { code, text: `another program answered the handoff; not the Hirozen loader — ${message}`, details };
    }
    return { code, text: message, details };
  }
  const gloss = CODE_TEXT[code];
  return { code, text: gloss ? `${gloss} — ${message}` : messageOf(error), details };
}

/** Failures render as `<code>[: pid <pid>]: <text>` so the code and its owner are always visible. */
function fail(failure: Failure): AgentToolResult<unknown> {
  const pid = typeof failure.details?.pid === "number" ? ` pid ${failure.details.pid}` : "";
  return {
    content: [{ type: "text", text: `${failure.code}${pid}: ${failure.text}` }],
    details: { code: failure.code, ...(failure.details ?? {}) },
    isError: true,
  };
}

/** Config is explicit by design: there is no default Zen directory anywhere in this plugin. */
type HirozenConfig = { zenDir: string; profileDir: string };

function readConfig(): { ok: true; config: HirozenConfig } | { ok: false; problem: string } {
  const zenDir = (process.env.HIROZEN_ZEN_DIR ?? "").trim();
  if (zenDir === "") {
    return {
      ok: false,
      problem: "HIROZEN_ZEN_DIR is not set; set it to the Zen install directory (there is no default).",
    };
  }
  const profileDir = (process.env.HIROZEN_PROFILE ?? "").trim();
  if (profileDir === "") {
    return {
      ok: false,
      problem: "HIROZEN_PROFILE is not set; set it to the Zen profile directory (there is no default).",
    };
  }
  return { ok: true, config: { zenDir, profileDir } };
}

/** One managed (or plain) timer, cancelable through the returned function. */
function scheduleOnce(ctx: ExtensionContext, ms: number, run: () => void): () => void {
  if (typeof ctx.setTimeout === "function") {
    const timer = ctx.setTimeout(() => run(), ms);
    return () => ctx.clearTimer?.(timer);
  }
  const timer = setTimeout(run, ms);
  return () => clearTimeout(timer);
}

function clearConsentNotice(): void {
  consentRepeat?.();
  consentRepeat = null;
}

function notifyConsent(ctx: ExtensionContext, repeated: boolean): void {
  ctx.ui.notify(`Hirozen: ${repeated ? "still waiting — " : ""}${CONSENT_NOTICE}`, "warning");
}

/** BiDi left "off": the consent dialog is being shown for the first time, so tell the user. */
function announceConsent(): void {
  const ctx = linkCtx;
  if (!ctx) return;
  notifyConsent(ctx, false);
  armConsentRepeat(ctx);
}

/**
 * Remind again every CONSENT_REPEAT_MS for as long as the dialog is unanswered. A start that failed
 * (E_DENIED and friends) reaches the extension as `bidi.off`, and `bidi.running` means consent was
 * granted: either one clears the reminder.
 */
function armConsentRepeat(ctx: ExtensionContext): void {
  clearConsentNotice();
  consentRepeat = scheduleOnce(ctx, CONSENT_REPEAT_MS, () => {
    consentRepeat = null;
    if (bidiPhase !== "starting") return;
    notifyConsent(ctx, true);
    armConsentRepeat(ctx);
  });
}

/** The loader emits `bidi.starting` again for every call that joins the pending start: notify once. */
function handleLoaderEvent(event: LoaderEvent): void {
  if (event.name === "bidi.starting") {
    if (bidiPhase !== "starting") {
      bidiPhase = "starting";
      announceConsent();
    }
    return;
  }
  if (event.name === "bidi.running") {
    bidiPhase = "running";
    clearConsentNotice();
    return;
  }
  if (event.name === "bidi.off") {
    bidiPhase = "off";
    clearConsentNotice();
  }
}

function releaseLink(): void {
  connectGen += 1; // any attempt still in flight is stale now; its link must never be published
  link = null;
  linkCtx = null;
  connectPromise = null;
  bidiPhase = "off";
  clearConsentNotice();
}

/**
 * The close handler of one ZenLink instance. Only the live link may release module state: an orphan
 * (a stale-sha attempt closing itself, or one session_shutdown superseded) must be a no-op, or it
 * would drop the link a newer attempt just published — the false E_IN_USE of doc §15.1 B.
 */
function handleLinkClose(closed: ZenLink, info: LinkCloseInfo): void {
  if (link !== closed) return;
  const ctx = linkCtx;
  releaseLink();
  if (info.stopKind === null) return;
  stopKind = info.stopKind;
  if (ctx) ctx.ui.notify(`Hirozen: ${STOP_TEXT[info.stopKind]}`, "warning");
}

function shutdownLink(): void {
  const current = link;
  releaseLink();
  current?.close();
}

/** Verify the installed copy, connect single-flight, then check the identity the loader reported. */
function ensureLink(pi: ExtensionAPI, ctx: ExtensionContext, config: HirozenConfig): Promise<ZenLink> {
  if (link) return Promise.resolve(link);
  if (connectPromise) return connectPromise;
  const generation = ++connectGen;
  const attempt = (async () => {
    try {
      const checked = verify(config.zenDir);
      if (!checked.ok) {
        const hint = checked.reason.includes("/hirozen-install") ? "" : "; run /hirozen-install, restart Zen";
        throw new HirozenError("E_STALE_LOADER", `${checked.reason}${hint}`);
      }
      // The onClose is bound to this instance: a close of a link that is not (or no longer) the live
      // one releases nothing.
      const fresh = new ZenLink({ onEvent: handleLoaderEvent, onClose: info => handleLinkClose(fresh, info) });
      const ready = await fresh.connect(config.profileDir);
      let sourceSha: string;
      try {
        sourceSha = sha256File(LOADER_SOURCE);
      } catch (error) {
        fresh.close();
        throw new HirozenError(
          "E_STALE_LOADER",
          `cannot hash the plugin loader at ${LOADER_SOURCE} (${messageOf(error)}); run /hirozen-install, restart Zen`,
        );
      }
      if (ready.loaderSha256 !== sourceSha) {
        fresh.close();
        throw new HirozenError(
          "E_STALE_LOADER",
          `the running loader reports sha256 ${ready.loaderSha256}, this plugin ships ${sourceSha}; run /hirozen-install, restart Zen`,
        );
      }
      if (generation !== connectGen) {
        // session_shutdown, or a newer attempt, ran while this one was connecting: this link was never
        // published, so it owns nothing and is closed here (a no-op close, per the instance handler).
        fresh.close();
        throw new HirozenError("E_STOPPED", "the omp session ended while the Zen loader was connecting; retry the call");
      }
      link = fresh;
      linkCtx = ctx;
      if (!teardownHooked) {
        teardownHooked = true;
        pi.on("session_shutdown", () => shutdownLink());
      }
      if (!warnedAboutBrowserMcp) {
        warnedAboutBrowserMcp = true;
        warnAboutBrowserMcpServers(pi, ctx);
      }
      return fresh;
    } catch (error) {
      // Only while this attempt is current: a superseded attempt must not clear the promise a newer
      // one installed (that is what let two connects run at once).
      if (generation === connectGen) connectPromise = null;
      throw error;
    }
  })();
  connectPromise = attempt;
  return attempt;
}

/** The tool check order fixed by the plan: root/UI, sticky stop, config, connect. */
async function requireLink(pi: ExtensionAPI, ctx: ExtensionContext): Promise<{ link: ZenLink } | { failure: Failure }> {
  if (!(ctx.hasUI && ctx.agent?.kind === "main")) {
    return {
      failure: {
        code: "E_NO_UI",
        text: "Hirozen tools need the interactive omp session: this context has no UI, or it is a subagent.",
      },
    };
  }
  if (stopKind) return { failure: { code: "E_STOPPED", text: STOP_TEXT[stopKind] } };
  const config = readConfig();
  if (!config.ok) return { failure: { code: "E_CONFIG", text: config.problem } };
  try {
    return { link: await ensureLink(pi, ctx, config.config) };
  } catch (error) {
    return { failure: describeError(error) };
  }
}

// ---------------------------------------------------------------------------------------------
// Chromium browser-automation MCP warning (doc §7)
// ---------------------------------------------------------------------------------------------

/** MCP servers that drive a Chromium browser: a second automation client in the same session. */
const BROWSER_MCP_PATTERN =
  /playwright|puppeteer|chrome[-_ ]?devtools|browser[-_ ]?mcp|mcp[-_ ]?browser|browser[-_ ]?tools|selenium|webdriver|chromium/i;

function userAgentDir(pi: ExtensionAPI): string | null {
  try {
    const dir = pi.pi.getAgentDir();
    return typeof dir === "string" && dir !== "" ? dir : null;
  } catch {
    return null;
  }
}

/** `mcpServers` of one config file as name -> searchable text; a missing or corrupt file is skipped. */
function readMcpServers(file: string): [string, string][] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return [];
  }
  if (typeof parsed !== "object" || parsed === null) return [];
  const servers = (parsed as { mcpServers?: unknown }).mcpServers;
  if (typeof servers !== "object" || servers === null) return [];
  return Object.entries(servers as Record<string, unknown>).map(([name, config]) => [
    name,
    `${name} ${JSON.stringify(config ?? null)}`,
  ]);
}

/**
 * Names of configured browser-automation MCP servers. omp exposes no extension API for MCP config, so
 * this reads the native and fallback config files it documents (mcp-config.md) read-only. Servers that
 * reach omp through another tool's config are not covered; omp's own browser layer filters those.
 */
function browserMcpServers(pi: ExtensionAPI, cwd: string): string[] {
  const files = [
    join(cwd, ".omp", "mcp.json"),
    join(cwd, ".omp", ".mcp.json"),
    join(cwd, "mcp.json"),
    join(cwd, ".mcp.json"),
  ];
  const agentDir = userAgentDir(pi);
  if (agentDir) files.push(join(agentDir, "mcp.json"), join(agentDir, ".mcp.json"));
  const found = new Set<string>();
  for (const file of files) {
    for (const [name, haystack] of readMcpServers(file)) {
      if (BROWSER_MCP_PATTERN.test(haystack)) found.add(name);
    }
  }
  return [...found];
}

function warnAboutBrowserMcpServers(pi: ExtensionAPI, ctx: ExtensionContext): void {
  const servers = browserMcpServers(pi, ctx.cwd);
  if (servers.length === 0) return;
  ctx.ui.notify(
    `Hirozen: omp has browser-automation MCP server(s) configured (${servers.join(", ")}). They drive Chromium, not Zen; consider disabling them for Hirozen sessions.`,
    "warning",
  );
}

// ---------------------------------------------------------------------------------------------
// Tool rendering
// ---------------------------------------------------------------------------------------------

function spaceName(window: ZenSpaceWindow, uuid: string | null): string | null {
  if (!uuid) return null;
  return window.spaces.find(space => space.uuid === uuid)?.name ?? null;
}

function renderInventory(windows: ZenWindow[]): string {
  const tabs = windows.reduce((count, window) => count + window.tabs.length, 0);
  const lines = [`Zen: ${windows.length} window(s), ${tabs} tab(s).`];
  windows.forEach((window, index) => {
    const active = spaceName(window, window.activeSpace) ?? "none";
    lines.push(
      `window ${index + 1}: active space "${active}", ${window.spaces.length} space(s), ${window.tabs.length} tab(s)`,
    );
    for (const tab of window.tabs) {
      const space = spaceName(window, tab.space) ?? (tab.pinned || tab.essential ? "all spaces" : "-");
      const flags = [tab.selected ? "selected" : "", tab.pinned ? "pinned" : "", tab.essential ? "essential" : "", tab.lazy ? "lazy" : ""]
        .filter(flag => flag !== "")
        .join(", ");
      lines.push(`  - ${tab.tabKey} — ${tab.title || tab.url} — ${tab.url} [space: ${space}${flags ? `; ${flags}` : ""}]`);
    }
  });
  lines.push(
    'Pass a tabKey to browser_read / browser_screenshot. "lazy" tabs have no document yet and tabs in a non-active space are unreachable: Hirozen never loads, activates or switches anything.',
  );
  return lines.join("\n");
}

function renderSpaces(windows: ZenSpaceWindow[]): string {
  const lines = [`Zen: ${windows.length} window(s).`];
  windows.forEach((window, index) => {
    const active = spaceName(window, window.activeSpace) ?? "none";
    lines.push(`window ${index + 1}: active space "${active}", ${window.spaces.length} space(s)`);
    for (const space of window.spaces) {
      const container = space.containerTabId > 0 ? `; container ${space.containerTabId}` : "";
      lines.push(`  - ${space.name}${space.active ? " [active]" : ""}${container}`);
    }
  });
  return lines.join("\n");
}

// ---------------------------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------------------------

async function runZenTabs(pi: ExtensionAPI, ctx: ExtensionContext, signal?: AbortSignal): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const windows = await access.link.call<ZenWindow[]>("zen.inventory", {}, { signal });
    const tabCount = windows.reduce((count, window) => count + window.tabs.length, 0);
    return {
      content: [{ type: "text", text: renderInventory(windows) }],
      details: { windowCount: windows.length, tabCount, windows },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runZenSpaces(pi: ExtensionAPI, ctx: ExtensionContext, signal?: AbortSignal): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const windows = await access.link.call<ZenSpaceWindow[]>("zen.spaces", {}, { signal });
    return {
      content: [{ type: "text", text: renderSpaces(windows) }],
      details: { windowCount: windows.length, windows },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

/** A timeout while BiDi was off/starting is the consent dialog still being open, not a failure. */
function failCall(error: unknown, consentBudget: boolean): AgentToolResult<unknown> {
  const described = describeError(error);
  if (described.code === "E_TIMEOUT" && consentBudget) {
    return fail({
      code: "E_TIMEOUT",
      text: 'the Zen "Allow remote control?" dialog is still open; answer it, then retry',
    });
  }
  return fail(described);
}

/** How much of a URL the header echoes: a `data:` URL can be tens of thousands of characters long. */
const URL_HEADER_CAP = 300;

/** `# <title>\n<url>\n\n<text>` with the URL capped, so one page cannot flood the terminal. */
function renderRead(page: ZenRead): string {
  const url = page.url.length > URL_HEADER_CAP ? `${page.url.slice(0, URL_HEADER_CAP)}…` : page.url;
  return `# ${page.title}\n${url}\n\n${page.text}`;
}

async function runBrowserRead(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  tabKey: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  const consentBudget = bidiPhase !== "running";
  const timeoutMs = consentBudget ? CONSENT_TIMEOUT_MS : RUNNING_TIMEOUT_MS;
  try {
    const page = await access.link.call<ZenRead>("browser.read", { tabKey }, { timeoutMs, signal });
    return {
      content: [{ type: "text", text: renderRead(page) }],
      details: { tabKey: page.tabKey, url: page.url, title: page.title, truncated: page.truncated, chars: page.text.length },
    };
  } catch (error) {
    return failCall(error, consentBudget);
  }
}

async function runBrowserScreenshot(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  tabKey: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  const consentBudget = bidiPhase !== "running";
  const timeoutMs = consentBudget ? CONSENT_TIMEOUT_MS : RUNNING_TIMEOUT_MS;
  try {
    const shot = await access.link.call<ZenScreenshot>("browser.screenshot", { tabKey }, { timeoutMs, signal });
    if (typeof shot.data !== "string" || shot.data === "") {
      return fail({ code: "E_UNKNOWN", text: "the loader returned no image data for that tab" });
    }
    return {
      content: [
        { type: "image", data: shot.data, mimeType: "image/png" },
        { type: "text", text: `Screenshot of tab ${shot.tabKey} (viewport, image/png, ${shot.data.length} base64 bytes).` },
      ],
      details: { tabKey: shot.tabKey, mimeType: "image/png", bytes: shot.data.length },
    };
  } catch (error) {
    return failCall(error, consentBudget);
  }
}

// ---------------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------------

async function runInstallCommand(ctx: ExtensionContext): Promise<void> {
  const zenDir = (process.env.HIROZEN_ZEN_DIR ?? "").trim();
  if (zenDir === "") {
    ctx.ui.notify("Hirozen: HIROZEN_ZEN_DIR is not set; set it to the Zen install directory (there is no default).", "error");
    return;
  }
  try {
    const { loaderSha256 } = install(zenDir);
    ctx.ui.notify(
      `Hirozen: loader installed into ${zenDir} (sha256 ${loaderSha256.slice(0, 12)}…). Restart Zen to load it; the Hirozen tools stay unavailable until then.`,
      "info",
    );
  } catch (error) {
    const described = describeError(error);
    ctx.ui.notify(`Hirozen: ${described.code}: ${described.text}`, "error");
  }
}

async function runAttachCommand(ctx: ExtensionContext): Promise<void> {
  const config = readConfig();
  if (!config.ok) {
    ctx.ui.notify(`Hirozen: ${config.problem}`, "error");
    return;
  }
  try {
    // attachNow notifies right before it forwards the command line: the "Incoming Connection" prompt
    // only appears once the prefs, lock and loader-hash checks have passed, so a refusal stays silent.
    const attached = await attachNow({
      zenDir: config.config.zenDir,
      profileDir: config.config.profileDir,
      notify: message => ctx.ui.notify(`Hirozen: ${message}`, "info"),
    });
    stopKind = null;
    ctx.ui.notify(
      `Hirozen: attached through local devtools port ${attached.port} (loader sha256 ${attached.loaderSha256.slice(0, 12)}…); the DevTools settings are off again. Tool calls can connect now.`,
      "info",
    );
  } catch (error) {
    const described = describeError(error);
    ctx.ui.notify(`Hirozen: ${described.code}: ${described.text}`, "error");
  }
}

async function runConnectCommand(ctx: ExtensionContext): Promise<void> {
  const wasStopped = stopKind !== null;
  stopKind = null;
  ctx.ui.notify(
    wasStopped
      ? "Hirozen: cleared the stop; the next zen_tabs / browser_* call starts a new link (Zen will ask for consent again)."
      : "Hirozen: nothing to clear; the next tool call connects as usual.",
    "info",
  );
}

/** Read-only install check shared by the session_start warning and /hirozen-status. */
function checkInstalled(zenDir: string): { ok: boolean; text: string } {
  let checked: VerifyResult;
  try {
    checked = verify(zenDir);
  } catch (error) {
    return { ok: false, text: messageOf(error) };
  }
  if (!checked.ok) return { ok: false, text: checked.reason };
  return { ok: true, text: `installed loader == plugin loader, sha256 ${checked.installedSha?.slice(0, 12)}…` };
}

/** `user_pref("name", value);` lines of a profile's prefs.js, or null when it cannot be read. */
function readUserPrefs(profileDir: string): Map<string, string> | null {
  let source: string;
  try {
    source = readFileSync(join(profileDir, "prefs.js"), "utf8");
  } catch {
    return null;
  }
  const prefs = new Map<string, string>();
  for (const line of source.split("\n")) {
    const match = /^user_pref\("([^"]+)",\s*(.*)\);\s*$/.exec(line.trim());
    if (match) prefs.set(match[1], match[2]);
  }
  return prefs;
}

function renderStatusFile(profileDir: string): string {
  const status = readStatusFile(profileDir);
  if (!status) return `absent (${join(profileDir, "hirozen-status.json")})`;
  const parts = [
    `state=${status.state ?? "?"}`,
    `mode=${status.mode ?? "?"}`,
    `zenPid=${status.zenPid ?? "?"}`,
    `bidi=${status.bidi?.state ?? "?"}${status.bidi?.port ? `:${status.bidi.port}` : ""}`,
    `updated=${status.updated ?? "?"}`,
  ];
  if (status.lastClose) parts.push(`lastClose=${status.lastClose}`);
  if (status.lastStopError) parts.push(`lastStopError=${status.lastStopError}`);
  if (status.lastStartError) {
    const { code, message, at } = status.lastStartError;
    parts.push(`lastStartError=${code ?? "?"}${at ? ` @ ${at}` : ""}${message ? `: ${message}` : ""}`);
  }
  return parts.join(" ");
}

const DEVTOOLS_PREFS = ["devtools.chrome.enabled", "devtools.debugger.remote-enabled", "devtools.debugger.prompt-connection"];

function renderDevtoolsPrefs(profileDir: string): string {
  const prefs = readUserPrefs(profileDir);
  if (!prefs) return `${join(profileDir, "prefs.js")} is not readable`;
  return DEVTOOLS_PREFS.map(name => `${name}=${prefs.get(name) ?? "(unset)"}`).join(" ");
}

async function runStatusCommand(ctx: ExtensionContext): Promise<void> {
  const zenDir = (process.env.HIROZEN_ZEN_DIR ?? "").trim();
  const profileDir = (process.env.HIROZEN_PROFILE ?? "").trim();
  const installed = zenDir === "" ? null : checkInstalled(zenDir);
  const session = stopKind
    ? `stopped (${stopKind}) — run /hirozen-connect`
    : link
      ? "connected"
      : "not connected (the first tool call connects)";
  const lines = [
    "Hirozen status",
    `config: HIROZEN_ZEN_DIR=${zenDir || "(unset)"} HIROZEN_PROFILE=${profileDir || "(unset)"}`,
    `loader: ${installed ? `${installed.ok ? "ok" : "NOT ok"} (${installed.text})` : "not checked (HIROZEN_ZEN_DIR is unset)"}`,
    `session: ${session}`,
    `status file: ${profileDir === "" ? "not read (HIROZEN_PROFILE is unset)" : renderStatusFile(profileDir)}`,
    `devtools prefs: ${profileDir === "" ? "not read (HIROZEN_PROFILE is unset)" : renderDevtoolsPrefs(profileDir)}`,
  ];
  ctx.ui.notify(lines.join("\n"), stopKind !== null || (installed !== null && !installed.ok) ? "warning" : "info");
}

// ---------------------------------------------------------------------------------------------
// Extension factory: registration only
// ---------------------------------------------------------------------------------------------

/**
 * Parameter schemas, built from the injected omptype builder. They go through a named helper because
 * omp's `registerTool` infers `TParams` from the `parameters` property: an inline `pi.zod.object({…})`
 * does not feed that inference and the handler's `params` silently widens to `unknown`.
 */
function toolParameters(builder: ExtensionAPI["zod"]) {
  return {
    none: builder.object({}),
    tabKey: builder.object({ tabKey: builder.string().describe("tabKey reported by zen_tabs") }),
  };
}

export default function hirozen(pi: ExtensionAPI): void {
  const parameters = toolParameters(pi.zod);

  pi.on("session_start", (_event, ctx) => {
    // Root session only, and silent while the plugin is unconfigured: this is the doc §6.3
    // "verify on every omp start" check, read-only so it is not a factory side effect.
    if (!(ctx.hasUI && ctx.agent?.kind === "main")) return;
    const config = readConfig();
    if (!config.ok) return;
    const checked = checkInstalled(config.config.zenDir);
    if (checked.ok) return;
    const fix = checked.text.includes("/hirozen-install") ? "" : " — run /hirozen-install, restart Zen.";
    ctx.ui.notify(`Hirozen: ${checked.text}${fix}`, "warning");
  });

  pi.registerTool({
    name: "zen_tabs",
    label: "Zen tabs",
    description:
      "List the Zen browser's windows, spaces and tabs (read-only: nothing is loaded, activated or closed).",
    parameters: parameters.none,
    approval: "read",
    loadMode: "essential",
    execute: (_toolCallId, _params, signal, _onUpdate, ctx) => runZenTabs(pi, ctx, signal),
  });

  pi.registerTool({
    name: "zen_spaces",
    label: "Zen spaces",
    description: "List the Zen browser's windows and their spaces (read-only).",
    parameters: parameters.none,
    approval: "read",
    loadMode: "essential",
    execute: (_toolCallId, _params, signal, _onUpdate, ctx) => runZenSpaces(pi, ctx, signal),
  });

  pi.registerTool({
    name: "browser_read",
    label: "Read tab",
    description:
      "Read the visible text of one Zen tab by its tabKey from zen_tabs (read-only; the tab is never loaded or activated).",
    parameters: parameters.tabKey,
    approval: "read",
    loadMode: "essential",
    execute: (_toolCallId, params, signal, _onUpdate, ctx) => runBrowserRead(pi, ctx, params.tabKey, signal),
  });

  pi.registerTool({
    name: "browser_screenshot",
    label: "Screenshot tab",
    description: "Capture a PNG screenshot of one Zen tab's viewport by its tabKey from zen_tabs (read-only).",
    parameters: parameters.tabKey,
    approval: "read",
    loadMode: "essential",
    execute: (_toolCallId, params, signal, _onUpdate, ctx) => runBrowserScreenshot(pi, ctx, params.tabKey, signal),
  });

  pi.registerCommand("hirozen-install", {
    description: "Install the Hirozen loader into the Zen install directory (HIROZEN_ZEN_DIR)",
    handler: (_args, ctx) => runInstallCommand(ctx),
  });

  pi.registerCommand("hirozen-attach", {
    description: "Attach Hirozen to a running Zen through its developer-tools port, then clear the stop",
    handler: (_args, ctx) => runAttachCommand(ctx),
  });

  pi.registerCommand("hirozen-connect", {
    description: "Clear the Hirozen stop (Zen's Stop button, or remote control turned off in Zen)",
    handler: (_args, ctx) => runConnectCommand(ctx),
  });

  pi.registerCommand("hirozen-status", {
    description: "Report the loader install, the loader status file and the Zen DevTools prefs",
    handler: (_args, ctx) => runStatusCommand(ctx),
  });
}
