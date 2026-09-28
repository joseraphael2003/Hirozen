// Hirozen omp extension: Zen browser tools over the Hirozen loader link (blob: src/link.ts).
//
// V2 is loader-first: reads, screenshots, snapshots, page input, uploads, page dialogs and Zen layout
// all run through the loader's own JSWindowActor and gZen* code, so nothing here starts WebDriver
// BiDi. Consent comes from the loader's in-Zen Allow/Deny gate; this plugin mirrors the scope it
// reports into each call's budget and into a terminal hint ("click Allow in Zen"), which is the only
// sign in omp while a person still has to answer in Zen.
//
// The factory body registers only (tools, commands, lifecycle handlers): omp also loads extensions
// during `omp plugin install` validation and re-runs the factory inside every subagent, so load time
// must have no side effects. The link is created lazily by the first tool call of the root session,
// which is also the only instance that registers the session_shutdown teardown.
//
// Every tool checks in the plan's fixed order: root/UI -> sticky stop -> config -> connect.
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { AgentToolResult, ExtensionAPI, ExtensionContext, ToolDefinition } from "@oh-my-pi/pi-coding-agent";

import { attachNow } from "./attach";
import { type VerifyResult, install, sha256File, verify } from "./install";
import {
  HirozenError,
  type LinkCloseInfo,
  type LoaderEvent,
  type ReadyFrame,
  type StopKind,
  ZenLink,
  readStatusFile,
} from "./link";

/** The three loader modules in this checkout: the hashes install() pins and the running loader reports. */
const LOADER_SOURCE = fileURLToPath(new URL("../loader/loader.sys.mjs", import.meta.url));
const CHILD_SOURCE = fileURLToPath(new URL("../loader/HirozenChild.sys.mjs", import.meta.url));
const PARENT_SOURCE = fileURLToPath(new URL("../loader/HirozenParent.sys.mjs", import.meta.url));

// A call's budget is 15 s of base work plus 125 s while the loader's in-Zen Allow/Deny notice may
// still be waiting for an answer (the loader gives it 120 s). The same instant travels to the loader
// as an absolute deadline, so an answer that arrives too late never turns into an action omp has
// already given up on.
const BASE_BUDGET_MS = 15_000;
const PERSON_WAIT_MS = 125_000;
/** Repeat a "a person still has to answer in Zen" notice while they have not. */
const CONSENT_REPEAT_MS = 60_000;

/** Per-kind wording of a sticky stop; the tool refusal, the notice and /hirozen-status all use it. */
const STOP_TEXT: Record<StopKind, string> = {
  "zen-stop": "the Hirozen session was stopped in Zen — run /hirozen-connect (or /hirozen-attach) to start a new one.",
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
  E_ACTOR:
    "the Hirozen actor is not registered in Zen, so no page action can run; restart Zen after /hirozen-install",
  E_BAD_PARAMS: "the call's parameters were not usable (see the message)",
  E_DEADLINE:
    "omp gave up before Zen answered, so nothing was done; retry when the person at Zen is ready (this is not a page failure)",
  E_DENIED: "the Hirozen Allow/Deny notice in Zen was denied (or left unanswered)",
  E_INTERNAL: "the Zen loader hit an unexpected internal error",
  E_LAYOUT_REFUSED:
    "Zen refused that layout change; splits never include the selected tab or a pinned/essential/hidden tab, and the space must exist",
  E_NO_DIALOG: "that tab has no page dialog open, so there is nothing to answer",
  E_NOT_INTERACTABLE:
    "that element cannot take this action (disabled, zero-size, not a file input, or a file input that takes fewer files)",
  E_PRIVATE: "that tab is in a private window, which Hirozen never touches",
  E_PRIVILEGED_PAGE: "that tab is a privileged page, which Hirozen never reads or acts on",
  E_READ_FAILED: "the loader returned no usable page data (the page may still be loading, crashed or reloading)",
  E_REF_STALE:
    "that element reference is from an older page (or the element is gone); take a fresh browser_snapshot and retry",
  E_STOPPED: "the loader dropped the session (fail-closed); retry, or run /hirozen-connect",
  E_TAB_INACTIVE_SPACE: "that tab is in an inactive space, and Hirozen never switches spaces",
  E_TAB_UNKNOWN: "no such tab; list the tabs with zen_tabs",
  E_TAB_UNLOADED: "that tab is not loaded; open it in Zen first (Hirozen never loads tabs)",
  E_UNKNOWN_METHOD: "the installed loader does not support that method; run /hirozen-install, restart Zen",
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
/** One element of a `browser.snapshot`; `ref` is the handle `browser_act` takes. */
type ZenElement = {
  ref: string;
  role: string;
  name: string;
  tag: string;
  rect: { x: number; y: number; width: number; height: number };
};
type ZenSnapshot = { url: string; title: string; elements: ZenElement[]; truncated: boolean };
/**
 * What an act/upload/dialog call reports: the page it ended on, a page dialog it ran into (the agent
 * then uses browser_dialog), and any tab a popup opened that the loader re-homed into the agent space.
 */
type ZenActResult = {
  ok?: boolean;
  url?: string;
  title?: string;
  dialog?: { type?: string; message?: string };
  opened?: string[];
};
type ZenOpen = { tabKey: string; spaceId: string };
type ZenSplit = { groupId?: string };
type ZenGlance = { tabKey: string };

/**
 * The parsed arguments of the V2 tools. omp validates every call against the tool's `parameters`
 * before it runs, so these are the schemas' output shapes, named here for the approval plumbing.
 */
type TabParams = { tabKey: string };
type UrlParams = { url: string };
type ActParams = {
  tabKey: string;
  action: string;
  ref?: string;
  text?: string;
  key?: string;
  dy?: number;
  url?: string;
};
type UploadParams = { tabKey: string; ref: string; paths: string[] };
type DialogParams = { tabKey: string; accept: boolean; text?: string };
type MoveParams = { tabKey: string; spaceId: string };
type SplitParams = { tabKeys: string[]; layout: string };

/** A tool-visible failure: the contract's code plus text the model can read. */
type Failure = { code: string; text: string; details?: Record<string, unknown> };

/** The gate scope the loader reported for this link, and what a pending notice is asking for. */
type GateScope = "none" | "read" | "act";

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
/** Cancels the armed repeat of the gate notice while it is showing. */
let consentRepeat: (() => void) | null = null;
/** The scope the loader granted this link; the budget for a call depends on it. Reset with the link. */
let consentScope: GateScope = "none";
/** What the pending Allow/Deny notice asks for, or null when nothing waits on a person. */
let consentPending: "read" | "act" | null = null;
/** Per-tabKey title/URL the plugin last saw, so an approval prompt can name the tab it acts on. */
const knownTabs = new Map<string, { title: string; url: string }>();
/** Per-tabKey elements of the last browser_snapshot, so a prompt can name the ref it acts on. */
const snapshotRefs = new Map<string, Map<string, { role: string; name: string }>>();
/** Set by Zen's Stop button (close 4010); only /hirozen-connect and /hirozen-attach clear it. */
let stopKind: StopKind | null = null;
let teardownHooked = false;
let warnedAboutBrowserMcp = false;

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * The readable half of an error: plugin codes keep their message, loader codes get a gloss first.
 */
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
  // A call that was in flight when Zen ended the session must read like the calls that follow it: the
  // close that killed it (link.ts fails pending calls before onClose, and onClose runs before any
  // rejection is observed) is the very event that set stopKind, and for a sticky stop the generic
  // "retry" gloss is wrong advice - the retry cannot pass the gate. Non-sticky closes leave stopKind
  // null and keep the generic gloss, where retrying is exactly what works.
  if (code === "E_STOPPED" && stopKind !== null) return { code, text: STOP_TEXT[stopKind], details };
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

/** The gate notice: the only thing in omp while a person still has to answer in Zen. */
function notifyGateWait(ctx: ExtensionContext, repeated: boolean): void {
  const prefix = `Hirozen: ${repeated ? "still waiting — " : ""}`;
  const scope = consentPending ?? "read";
  ctx.ui.notify(
    `${prefix}click Allow in Zen to let omp ${scope === "act" ? "read and act on pages" : "read pages"} (Deny refuses).`,
    "warning",
  );
}

/**
 * Remind again every CONSENT_REPEAT_MS for as long as the person has not answered. The predicate is
 * re-checked when the timer fires, so `consent.granted`/`consent.denied` end the repeat without
 * racing this timer.
 */
function armGateNotice(ctx: ExtensionContext): void {
  consentRepeat?.();
  consentRepeat = scheduleOnce(ctx, CONSENT_REPEAT_MS, () => {
    consentRepeat = null;
    if (consentPending === null) return;
    notifyGateWait(ctx, true);
    armGateNotice(ctx);
  });
}

/** A person has to answer the Hirozen gate in Zen before a call can proceed: say what, then remind. */
function announceGateWait(): void {
  const ctx = linkCtx;
  if (!ctx) return;
  notifyGateWait(ctx, false);
  armGateNotice(ctx);
}

/** The `scope` of a `consent.*` event, or null when the loader sent something this plugin cannot use. */
function eventScope(data: unknown): "read" | "act" | null {
  if (!data || typeof data !== "object" || !("scope" in data)) return null;
  const scope = data.scope;
  return scope === "read" || scope === "act" ? scope : null;
}

/** Loader events: the consent gate, whose scope drives every call's budget. */
function handleLoaderEvent(event: LoaderEvent): void {
  if (event.name === "consent.pending") {
    // The loader upgrades a pending read prompt in place, so this also fires for an act upgrade.
    consentPending = eventScope(event.data) ?? "read";
    announceGateWait();
    return;
  }
  if (event.name === "consent.granted") {
    const scope = eventScope(event.data);
    if (scope === null) return;
    consentScope = scope;
    consentPending = null;
    clearConsentNotice();
    return;
  }
  if (event.name === "consent.denied") {
    consentPending = null;
    clearConsentNotice();
    if (linkCtx) linkCtx.ui.notify("Hirozen: denied in Zen.", "warning");
  }
}

function releaseLink(): void {
  connectGen += 1; // any attempt still in flight is stale now; its link must never be published
  link = null;
  linkCtx = null;
  connectPromise = null;
  // The gate belongs to the loader, which clears it with the link: a new link starts at "none" and
  // must ask again. The caches describe what that link last saw, so they go with it.
  consentScope = "none";
  consentPending = null;
  knownTabs.clear();
  snapshotRefs.clear();
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

/**
 * The `ready` frame names the three modules the loader is running. Every one of them has to be this
 * checkout's copy: a loader newer than its actor (or the reverse) is the V1 stale-loader failure, one
 * module at a time. Returns the problem, or null when all three match.
 */
function staleLoader(ready: ReadyFrame): string | null {
  const modules: [name: string, source: string, reported: string | undefined][] = [
    ["loader.sys.mjs", LOADER_SOURCE, ready.loaderSha256],
    ["HirozenChild.sys.mjs", CHILD_SOURCE, ready.childSha256],
    ["HirozenParent.sys.mjs", PARENT_SOURCE, ready.parentSha256],
  ];
  for (const [name, source, reported] of modules) {
    let sha: string;
    try {
      sha = sha256File(source);
    } catch (error) {
      return `cannot hash the plugin ${name} at ${source} (${messageOf(error)})`;
    }
    if (reported !== sha) {
      return `the running ${name} reports sha256 ${reported ?? "(nothing)"}, this plugin ships ${sha}`;
    }
  }
  return null;
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
      const stale = staleLoader(ready);
      if (stale !== null) {
        fresh.close();
        throw new HirozenError("E_STALE_LOADER", `${stale}; run /hirozen-install, restart Zen`);
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
    'Pass a tabKey to browser_read, browser_screenshot, browser_snapshot, browser_act, browser_upload and the zen_* layout tools. "lazy" tabs have no document yet and tabs in a non-active space are unreachable except the Hirozen Agent space: Hirozen never loads or activates anything.',
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

/** How much of a URL the header echoes: a `data:` URL can be tens of thousands of characters long. */
const URL_HEADER_CAP = 300;

/** `# <title>\n<url>` with the URL capped, so one page cannot flood the terminal. */
function pageHeader(url: string, title: string): string {
  const shown = url.length > URL_HEADER_CAP ? `${url.slice(0, URL_HEADER_CAP)}…` : url;
  return `# ${title}\n${shown}`;
}

/** How strong a granted scope is; a call waits for a person while its own requirement is above it. */
const SCOPE_RANK: Record<GateScope, number> = { none: 0, read: 1, act: 2 };

/**
 * The omp-side budget for one call: 15 s of base work plus 125 s while the Hirozen Allow/Deny notice
 * may still be waiting for an answer, which is whenever the granted scope is below what the call
 * needs. The loader receives the same instant as an absolute deadline and refuses to act once it
 * passed, so a late answer never turns into an action omp has already given up on.
 */
function callBudget(needs: "read" | "act"): number {
  return SCOPE_RANK[consentScope] < SCOPE_RANK[needs] ? BASE_BUDGET_MS + PERSON_WAIT_MS : BASE_BUDGET_MS;
}

/** Remember what a page call just reported, so a later approval prompt can name that tab. */
function rememberTab(tabKey: string, page: { title?: string; url?: string }): void {
  if (typeof page.title !== "string" && typeof page.url !== "string") return;
  const known = knownTabs.get(tabKey);
  knownTabs.set(tabKey, { title: page.title ?? known?.title ?? "", url: page.url ?? known?.url ?? "" });
}

/** The tab an approval prompt acts on: `<title> — <url>`, or `unknown tab` before zen_tabs saw it. */
function describeTab(tabKey: string): string {
  const known = knownTabs.get(tabKey);
  if (!known) return `unknown tab (${tabKey})`;
  return `${known.title} — ${known.url}`;
}

/** `role "name"` for a ref the tab's last snapshot named, or `ref <ref>` when it did not. */
function describeRef(tabKey: string, ref: string | undefined): string | null {
  if (!ref) return null;
  const element = snapshotRefs.get(tabKey)?.get(ref);
  if (!element) return `ref ${ref}`;
  return `${element.role} "${element.name}"`;
}

async function runZenTabs(pi: ExtensionAPI, ctx: ExtensionContext, signal?: AbortSignal): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const windows = await access.link.call<ZenWindow[]>("zen.inventory", {}, { signal });
    const tabCount = windows.reduce((count, window) => count + window.tabs.length, 0);
    // The inventory is the plugin's tab directory: an approval prompt for a tabKey it named can show
    // the tab's title and URL even before any page tool ran on it.
    for (const window of windows) {
      for (const tab of window.tabs) rememberTab(tab.tabKey, { title: tab.title, url: tab.url });
    }
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

/** `# <title>\n<url>\n\n<text>`; the header is capped so one page cannot flood the terminal. */
function renderRead(page: ZenRead): string {
  return `${pageHeader(page.url, page.title)}\n\n${page.text}`;
}

async function runBrowserRead(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  tabKey: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const page = await access.link.call<ZenRead>("browser.read", { tabKey }, { timeoutMs: callBudget("read"), signal });
    rememberTab(tabKey, page);
    return {
      content: [{ type: "text", text: renderRead(page) }],
      details: { tabKey: page.tabKey, url: page.url, title: page.title, truncated: page.truncated, chars: page.text.length },
    };
  } catch (error) {
    return fail(describeError(error));
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
  try {
    const shot = await access.link.call<ZenScreenshot>("browser.screenshot", { tabKey }, { timeoutMs: callBudget("read"), signal });
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
    return fail(describeError(error));
  }
}

/** One element per line: the ref the agent acts with, then the role and name a person would see. */
function renderSnapshot(snapshot: ZenSnapshot, elements: ZenElement[]): string {
  const lines = [pageHeader(snapshot.url, snapshot.title), "", `${elements.length} element(s):`];
  for (const element of elements) {
    lines.push(`- ${element.ref} ${element.role} ${element.name === "" ? "(no name)" : `"${element.name}"`} [${element.tag}]`);
  }
  if (snapshot.truncated) {
    lines.push("", "The list stops at 400 elements; scroll the page or narrow it, then snapshot again.");
  }
  lines.push("", "A ref belongs to the document it came from: after a navigation or reload, snapshot again.");
  return lines.join("\n");
}

async function runBrowserSnapshot(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  tabKey: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const snapshot = await access.link.call<ZenSnapshot>("browser.snapshot", { tabKey }, { timeoutMs: callBudget("read"), signal });
    const elements = Array.isArray(snapshot.elements) ? snapshot.elements : [];
    rememberTab(tabKey, snapshot);
    // The last snapshot per tab is what an approval prompt reads to turn a ref into `role "name"`.
    snapshotRefs.set(tabKey, new Map(elements.map(element => [element.ref, { role: element.role, name: element.name }])));
    return {
      content: [{ type: "text", text: renderSnapshot(snapshot, elements) }],
      details: {
        tabKey,
        url: snapshot.url,
        title: snapshot.title,
        elementCount: elements.length,
        truncated: snapshot.truncated === true,
      },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

/** What an act/upload/dialog call reports, plus anything the agent has to follow up on. */
function renderActOutcome(verb: string, tabKey: string, result: ZenActResult): string {
  const lines = [`${verb} in tab ${tabKey}.`];
  if (typeof result.url === "string" || typeof result.title === "string") {
    lines.push(pageHeader(result.url ?? "", result.title ?? ""));
  }
  if (result.dialog) {
    lines.push(`A page dialog is open (${result.dialog.type ?? "dialog"}): ${result.dialog.message ?? ""}`.trimEnd());
    lines.push("Answer it with browser_dialog.");
  }
  if (Array.isArray(result.opened) && result.opened.length > 0) {
    lines.push(`Opened tab(s), moved to the Hirozen Agent space: ${result.opened.join(", ")}`);
  }
  return lines.join("\n");
}

async function runBrowserAct(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  params: ActParams,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const result = await access.link.call<ZenActResult>(
      "browser.act",
      {
        tabKey: params.tabKey,
        action: params.action,
        ref: params.ref,
        text: params.text,
        key: params.key,
        dy: params.dy,
        url: params.url,
      },
      { timeoutMs: callBudget("act"), signal },
    );
    rememberTab(params.tabKey, result);
    return {
      content: [{ type: "text", text: renderActOutcome(params.action, params.tabKey, result) }],
      details: {
        tabKey: params.tabKey,
        action: params.action,
        url: result.url,
        title: result.title,
        dialog: result.dialog ?? null,
        opened: result.opened ?? [],
      },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

/** Files are read by Zen, not by omp: every path must be absolute and must exist here first. */
function absoluteUploadPaths(cwd: string, paths: string[]): { ok: true; paths: string[] } | { ok: false; missing: string } {
  const resolved: string[] = [];
  for (const given of paths) {
    const full = resolve(cwd, given);
    if (!existsSync(full)) return { ok: false, missing: full };
    resolved.push(full);
  }
  return { ok: true, paths: resolved };
}

async function runBrowserUpload(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  params: UploadParams,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  const resolved = absoluteUploadPaths(ctx.cwd, params.paths);
  if (!resolved.ok) {
    return fail({ code: "E_BAD_PARAMS", text: `no such file to upload: ${resolved.missing}` });
  }
  try {
    const result = await access.link.call<ZenActResult>(
      "browser.upload",
      { tabKey: params.tabKey, ref: params.ref, paths: resolved.paths },
      { timeoutMs: callBudget("act"), signal },
    );
    rememberTab(params.tabKey, result);
    return {
      content: [{ type: "text", text: renderActOutcome(`Uploaded ${resolved.paths.length} file(s)`, params.tabKey, result) }],
      details: { tabKey: params.tabKey, ref: params.ref, paths: resolved.paths, url: result.url, title: result.title },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runBrowserDialog(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  params: DialogParams,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const result = await access.link.call<ZenActResult>(
      "browser.dialog",
      { tabKey: params.tabKey, accept: params.accept, text: params.text },
      { timeoutMs: callBudget("act"), signal },
    );
    rememberTab(params.tabKey, result);
    return {
      content: [
        {
          type: "text",
          text: renderActOutcome(params.accept ? "Accepted the page dialog" : "Dismissed the page dialog", params.tabKey, result),
        },
      ],
      details: { tabKey: params.tabKey, accept: params.accept, url: result.url, title: result.title },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runZenOpen(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  url: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const opened = await access.link.call<ZenOpen>("zen.open", { url }, { timeoutMs: callBudget("act"), signal });
    rememberTab(opened.tabKey, { url });
    return {
      content: [
        {
          type: "text",
          text: `Opened ${url} in tab ${opened.tabKey}, in the "Hirozen Agent" space (space ${opened.spaceId}); the tab is in the background.`,
        },
      ],
      details: { tabKey: opened.tabKey, spaceId: opened.spaceId, url },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runZenMove(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  params: MoveParams,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const moved = await access.link.call<ZenOpen>("zen.move", { tabKey: params.tabKey, spaceId: params.spaceId }, { timeoutMs: callBudget("act"), signal });
    return {
      content: [{ type: "text", text: `Moved tab ${moved.tabKey} to space ${moved.spaceId}.` }],
      details: { tabKey: moved.tabKey, spaceId: moved.spaceId },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runZenSplit(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  params: SplitParams,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const group = await access.link.call<ZenSplit>(
      "zen.split",
      { tabKeys: params.tabKeys, layout: params.layout },
      { timeoutMs: callBudget("act"), signal },
    );
    const tabs = params.tabKeys.join(", ");
    const id = group.groupId === undefined ? "" : ` (group ${group.groupId})`;
    return {
      content: [{ type: "text", text: `Split tabs ${tabs} as ${params.layout}${id}; the selected tab was left alone.` }],
      details: { tabKeys: params.tabKeys, layout: params.layout, groupId: group.groupId ?? null },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runZenUnsplit(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  tabKey: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    await access.link.call<ZenActResult>("zen.unsplit", { tabKey }, { timeoutMs: callBudget("act"), signal });
    return {
      content: [{ type: "text", text: `Removed tab ${tabKey} from its split.` }],
      details: { tabKey },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runZenGlance(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  url: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const glance = await access.link.call<ZenGlance>("zen.glance", { url }, { timeoutMs: callBudget("act"), signal });
    return {
      content: [
        {
          type: "text",
          text: `Opened ${url} in a glance (tab ${glance.tabKey}); a glance selects itself, which is the one case Hirozen takes the selected tab.`,
        },
      ],
      details: { tabKey: glance.tabKey, url },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}
// ---------------------------------------------------------------------------------------------
// Approval prompts (S3: omp renders these lines under "Allow tool: <name>", even in yolo mode)
// ---------------------------------------------------------------------------------------------

/** The per-action approval omp enforces before an act-tier tool runs. */
type ExecApproval = { tier: "exec"; policy: "prompt"; reason: string };

/** The details half of the prompt, as omp reads it (`AgentTool.formatApprovalDetails`). */
type ApprovalDetails = (args: unknown) => string[];

/** Cap what a prompt echoes: typed text can be 2000 characters, and a URL can be a `data:` URL. */
const PROMPT_TEXT_CAP = 200;

function clipForPrompt(text: string): string {
  return text.length > PROMPT_TEXT_CAP ? `${text.slice(0, PROMPT_TEXT_CAP)}… (${text.length} chars)` : text;
}

/** Every act-tier tool prompts on every call, even in omp's default yolo mode (S3). */
function execApproval(reason: string): () => ExecApproval {
  return () => ({ tier: "exec", policy: "prompt", reason });
}

/** The parsed arguments of a tool, recovered at the approval boundary: omp validated them against the
 *  tool's `parameters` before the gate, and TypeScript cannot carry that type through `unknown`. */
function approvalArgs<T>(args: unknown): T {
  return args as T;
}

/** browser_act: the tab, the action, and the element a person would see behind the ref. */
function actApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<ActParams>(args);
  const target = describeRef(params.tabKey, params.ref);
  const lines = [`tab: ${describeTab(params.tabKey)}`];
  switch (params.action) {
    case "click":
      lines.push(`action: click ${target ?? "the page"}`);
      break;
    case "type":
      lines.push(`action: type into ${target ?? "the page"}`, `text: ${clipForPrompt(params.text ?? "")}`);
      break;
    case "press":
      lines.push(`action: press ${params.key ?? "?"}${target ? ` on ${target}` : ""}`);
      break;
    case "scroll":
      lines.push(`action: ${target ? `scroll ${target} into view` : `scroll by ${params.dy ?? 0} px`}`);
      break;
    case "navigate":
      lines.push(`action: navigate to ${params.url ?? "?"}`);
      break;
    default:
      lines.push(`action: ${params.action}`);
  }
  return lines;
}

/** browser_upload: which file input, and every path Zen is about to read. */
function uploadApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<UploadParams>(args);
  const target = describeRef(params.tabKey, params.ref) ?? `ref ${params.ref}`;
  return [
    `tab: ${describeTab(params.tabKey)}`,
    `action: set ${params.paths.length} file(s) on ${target}`,
    ...params.paths.map(path => `file: ${path}`),
  ];
}

/** browser_dialog: accept or dismiss, and the text a prompt dialog would receive. */
function dialogApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<DialogParams>(args);
  const lines = [`tab: ${describeTab(params.tabKey)}`, `action: ${params.accept ? "accept" : "dismiss"} the page dialog`];
  if (params.text !== undefined && params.text !== "") lines.push(`text: ${clipForPrompt(params.text)}`);
  return lines;
}

/** zen_open: the URL that lands in the agent space. */
function openApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<UrlParams>(args);
  return ['action: open a background tab in the "Hirozen Agent" space', `url: ${params.url}`];
}

/** zen_move: which tab, which space. */
function moveApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<MoveParams>(args);
  return [`tab: ${describeTab(params.tabKey)}`, `action: move to space ${params.spaceId}`];
}

/** zen_split: every tab that would end up in the layout. */
function splitApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<SplitParams>(args);
  const lines = [`action: split ${params.tabKeys.length} tabs as ${params.layout}`];
  for (const tabKey of params.tabKeys) lines.push(`tab: ${describeTab(tabKey)}`);
  return lines;
}

/** zen_unsplit: the tab leaving its split. */
function unsplitApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<TabParams>(args);
  return [`tab: ${describeTab(params.tabKey)}`, "action: remove from its split"];
}

/** zen_glance: the URL, and the fact that a glance takes the selected tab (the one exception). */
function glanceApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<UrlParams>(args);
  return ["action: open a glance over the current tab (a glance takes the selected tab)", `url: ${params.url}`];
}

/**
 * `registerTool`'s ToolDefinition does not declare `formatApprovalDetails`, but the SDK adapts a
 * definition into an AgentTool by forwarding every own property (`extensibility/tool-proxy.ts`), and
 * the approval prompt reads it from there (`tools/approval.ts`; S3 verified the lines render).
 * Spreading it in here states that in one place, and keeps the definition above it contextually typed.
 */
function withApprovalDetails(
  tool: ToolDefinition,
  formatApprovalDetails: ApprovalDetails,
): ToolDefinition & { formatApprovalDetails: ApprovalDetails } {
  return { ...tool, formatApprovalDetails };
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
  const hashes = checked.installed;
  const shown = hashes
    ? `loader ${hashes.loader.slice(0, 12)}…, child ${hashes.child.slice(0, 12)}…, parent ${hashes.parent.slice(0, 12)}…`
    : `sha256 ${checked.installedSha?.slice(0, 12)}…`;
  return { ok: true, text: `installed modules == plugin modules (${shown})` };
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
    `consent=${status.consent ?? "?"}${status.consentPending ? ` (asking: ${status.consentPending})` : ""}`,
    `updated=${status.updated ?? "?"}`,
  ];
  if (status.lastClose) parts.push(`lastClose=${status.lastClose}`);
  if (status.actorError) parts.push(formatStatusError("actorError", status.actorError));
  return parts.join(" ");
}

/** One `name=code @ at: message` field, used for the actor error. */
function formatStatusError(name: string, error: { code?: string; message?: string; at?: string }): string {
  const { code, message, at } = error;
  return `${name}=${code ?? "?"}${at ? ` @ ${at}` : ""}${message ? `: ${message}` : ""}`;
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
  const tabKey = () => builder.string().describe("tabKey reported by zen_tabs");
  return {
    none: builder.object({}),
    tabKey: builder.object({ tabKey: tabKey() }),
    act: builder.object({
      tabKey: tabKey(),
      action: builder.enum(["click", "type", "press", "scroll", "navigate"]).describe("what to do on the tab"),
      ref: builder.string().optional().describe("element ref from browser_snapshot (click/type/press/scroll target)"),
      text: builder.string().optional().describe("text to type (action=type)"),
      key: builder
        .string()
        .optional()
        .describe("key name for action=press: Enter, Tab, Escape, Backspace, arrows, PageUp, PageDown, Home, End"),
      dy: builder.number().optional().describe("pixels to scroll down (negative up; action=scroll without a ref)"),
      url: builder.string().optional().describe("http(s) URL to open (action=navigate)"),
    }),
    upload: builder.object({
      tabKey: tabKey(),
      ref: builder.string().describe("ref of an <input type=file> from browser_snapshot"),
      paths: builder.array(builder.string()).describe("files to set on the input; relative paths resolve against the omp cwd"),
    }),
    dialog: builder.object({
      tabKey: tabKey(),
      accept: builder.boolean().describe("true accepts the dialog, false dismisses it"),
      text: builder.string().optional().describe("text for a prompt() dialog"),
    }),
    url: builder.object({ url: builder.string().describe("http(s) URL") }),
    move: builder.object({
      tabKey: tabKey(),
      spaceId: builder.string().describe("space uuid from zen_spaces"),
    }),
    split: builder.object({
      tabKeys: builder.array(tabKey()).describe("2 to 4 tabKeys of the same window; never the selected tab"),
      layout: builder.enum(["vsep", "hsep", "grid"]).describe("split layout"),
    }),
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

  pi.registerTool({
    name: "browser_snapshot",
    label: "Snapshot tab",
    description:
      "List the interactive elements of one Zen tab by its tabKey (links, buttons, inputs, selects, labelled controls) with a ref for each; browser_act and browser_upload take those refs (read-only; the tab is never loaded or activated).",
    parameters: parameters.tabKey,
    approval: "read",
    loadMode: "essential",
    execute: (_toolCallId, params, signal, _onUpdate, ctx) => runBrowserSnapshot(pi, ctx, params.tabKey, signal),
  });

  pi.registerTool(
    withApprovalDetails(
      {
        name: "browser_act",
        label: "Act in tab",
        description:
          "Act on one Zen tab by its tabKey: click, type, press, scroll or navigate (navigate needs an http(s) url). Refs come from browser_snapshot. The loader's in-Zen Allow/Deny gate must have granted the act scope; every call needs your approval. Refused on privileged pages, in private windows and on tabs in an inactive space that is not the Hirozen Agent space.",
        parameters: parameters.act,
        approval: execApproval("browser_act changes a page in Zen (click, type, press, scroll or navigate)."),
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: ActParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runBrowserAct(pi, ctx, params, signal),
      },
      actApprovalDetails,
    ),
  );

  pi.registerTool(
    withApprovalDetails(
      {
        name: "browser_upload",
        label: "Upload files",
        description:
          "Set files on an <input type=file> in one Zen tab (ref from browser_snapshot). The loader's in-Zen Allow/Deny gate must have granted the act scope; every call needs your approval. Paths must exist locally (relative paths resolve against this omp session's cwd).",
        parameters: parameters.upload,
        approval: execApproval("browser_upload sets files on a page's file input in Zen."),
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: UploadParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runBrowserUpload(pi, ctx, params, signal),
      },
      uploadApprovalDetails,
    ),
  );

  pi.registerTool(
    withApprovalDetails(
      {
        name: "browser_dialog",
        label: "Answer page dialog",
        description:
          "Answer the page dialog (alert/confirm/prompt, including beforeunload) that is open in one Zen tab - the one a browser_act reported. accept=true answers it, accept=false dismisses it, and text fills a prompt() before accepting. E_NO_DIALOG means the tab has none open.",
        parameters: parameters.dialog,
        approval: execApproval("browser_dialog answers a page dialog in Zen."),
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: DialogParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runBrowserDialog(pi, ctx, params, signal),
      },
      dialogApprovalDetails,
    ),
  );

  pi.registerTool(
    withApprovalDetails(
      {
        name: "zen_open",
        label: "Open in agent space",
        description:
          'Open an http(s) URL in a new background tab in the "Hirozen Agent" space of Zen\'s most recent normal window. The user\'s space and selected tab are left alone; the returned tabKey can be read, snapshotted and acted on while that space is inactive.',
        parameters: parameters.url,
        approval: execApproval('zen_open opens a tab in Zen\'s "Hirozen Agent" space.'),
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: UrlParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runZenOpen(pi, ctx, params.url, signal),
      },
      openApprovalDetails,
    ),
  );

  pi.registerTool(
    withApprovalDetails(
      {
        name: "zen_move",
        label: "Move tab",
        description:
          "Move a tab to another Zen space (spaceId from zen_spaces). Pinned and essential tabs are refused, and Hirozen never switches the user's space.",
        parameters: parameters.move,
        approval: execApproval("zen_move moves a tab between Zen spaces."),
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: MoveParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runZenMove(pi, ctx, params, signal),
      },
      moveApprovalDetails,
    ),
  );

  pi.registerTool(
    withApprovalDetails(
      {
        name: "zen_split",
        label: "Split tabs",
        description:
          "Split 2 to 4 tabs of one Zen window into a vsep/hsep/grid layout. The selected tab is never included and stays selected, and pinned, essential or hidden tabs are refused.",
        parameters: parameters.split,
        approval: execApproval("zen_split changes Zen's tab layout."),
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: SplitParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runZenSplit(pi, ctx, params, signal),
      },
      splitApprovalDetails,
    ),
  );

  pi.registerTool(
    withApprovalDetails(
      {
        name: "zen_unsplit",
        label: "Unsplit tab",
        description:
          "Remove one tab from its Zen split. Zen dissolves the whole split when fewer than three tabs remain in it.",
        parameters: parameters.tabKey,
        approval: execApproval("zen_unsplit removes a tab from its Zen split."),
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: TabParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runZenUnsplit(pi, ctx, params.tabKey, signal),
      },
      unsplitApprovalDetails,
    ),
  );

  pi.registerTool(
    withApprovalDetails(
      {
        name: "zen_glance",
        label: "Glance",
        description:
          "Open an http(s) URL in a Zen glance over the current tab (needs a window without a glance already open). Unlike every other Hirozen tool, a glance selects itself in Zen.",
        parameters: parameters.url,
        approval: execApproval("zen_glance opens a Zen glance over the current tab."),
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: UrlParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runZenGlance(pi, ctx, params.url, signal),
      },
      glanceApprovalDetails,
    ),
  );

  pi.registerCommand("hirozen-install", {
    description: "Install the Hirozen loader into the Zen install directory (HIROZEN_ZEN_DIR)",
    handler: (_args, ctx) => runInstallCommand(ctx),
  });

  pi.registerCommand("hirozen-attach", {
    description: "Attach Hirozen to a running Zen through its developer-tools port, then clear the stop",
    handler: (_args, ctx) => runAttachCommand(ctx),
  });

  pi.registerCommand("hirozen-connect", {
    description: "Clear the Hirozen stop (Zen's Stop button)",
    handler: (_args, ctx) => runConnectCommand(ctx),
  });

  pi.registerCommand("hirozen-status", {
    description: "Report the loader install, the loader status file and the Zen DevTools prefs",
    handler: (_args, ctx) => runStatusCommand(ctx),
  });
}
