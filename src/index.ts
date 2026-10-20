// Hirozen omp extension: Zen browser tools over the Hirozen loader link (blob: src/link.ts).
//
// V2 is loader-first: reads, screenshots, snapshots, page input, uploads, page dialogs and Zen layout
// all run through the loader's own JSWindowActor and gZen* code, so nothing here starts WebDriver
// BiDi. Consent comes from the loader's in-Zen Allow/Deny gate; this plugin mirrors the permissions it
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
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { AgentToolResult, ExtensionAPI, ExtensionContext, ToolDefinition } from "@oh-my-pi/pi-coding-agent";

import { attachNow, listZenProcesses, normalizePath, profileLocked } from "./attach";
import { type HirozenConfig, type ResolveConfigResult, clearConfig, resolveConfig, saveConfig } from "./config";
import { type Candidate, discoverZen, normalizeManualPath, readCompatibility } from "./discover";
import { GRANT_MINUTES_MAX, GRANT_MINUTES_MIN, GrantStore, originOf, parseGrantMinutes } from "./grant";
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
  E_CANCELLED: true,
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
  E_DENIED: "nothing was done; ask the person at Zen to click Allow, then retry",
  E_GRANT_STALE:
    "the grant did not cover this call: the tab had left the site it was granted for, so nothing was done; the retry asks you (navigate and everything outside the act actions always ask)",
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
  E_STOPPED: "the Hirozen link is not connected or closed before the call could run (nothing was done); retry",
  E_TAB_INACTIVE_SPACE:
    "that tab is in a non-active space: Hirozen reads, snapshots and screenshots there, but never switches spaces to act, upload or answer a dialog",
  E_TAB_UNKNOWN: "no such tab; list the tabs with zen_tabs",
  E_TAB_UNLOADED: "that tab is not loaded; open it in Zen first, or load it with zen_load_tab (which never selects it)",
  E_TAB_UNSCOPED:
    "that tab's requests cannot be told apart from other tabs' (Zen gives its browsing context no id), so nothing is being watched; try another tab",
  E_UNSUPPORTED:
    "the running Zen does not expose an internal Hirozen needs (a Zen update, or an older Zen); update Hirozen, or read /hirozen-status for the missing names",
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
/** `browser.read` with `mode: "article"` adds the reader-mode byline ("" when the reader found none). */
type ZenRead = { tabKey: string; url: string; title: string; text: string; truncated: boolean; byline?: string };
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
/**
 * zen.open's reply: the loader waits for the load, so `url`/`title` are where the page landed - a
 * redirect or a normalization means they differ from the URL that was asked for. zen.move shares the
 * shape and reports neither.
 */
type ZenOpen = { tabKey: string; spaceId: string; url?: string; title?: string };
type ZenSplit = { groupId?: string };
type ZenGlance = { tabKey: string };
/** zen_load_tab's reply: the page the lazy tab restored to (its real URL, never about:blank). */
type ZenLoadTab = { tabKey: string; url: string; title: string };
/**
 * The network replies (`network.*`). Values the loader considers sensitive arrive redacted as
 * `"<n chars>"` unless the call asked for `reveal`, and the headers of a recorded request have
 * `cookie`, `set-cookie`, `authorization` and `proxy-authorization` replaced by `"<redacted>"`.
 */
type ZenCookie = {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number | null;
  secure: boolean;
  httpOnly: boolean;
  /** The loader's name for nsICookie's integer: `none` | `lax` | `strict` | `unset` (no attribute) |
   *  `unknown` (a value no Gecko constant covers). Never a raw number. */
  sameSite: string | null;
};
type ZenCookies = { tabKey: string; url: string; cookies: ZenCookie[]; truncated: boolean };
type ZenStorageEntry = { key: string; value: string | null };
type ZenStorage = { tabKey: string; url: string; kind: string; entries: ZenStorageEntry[]; truncated: boolean };
type ZenDownload = {
  source: string;
  target: string;
  state: string;
  bytes: number | null;
  totalBytes: number | null;
  startedAt: number | null;
};
type ZenDownloads = { downloads: ZenDownload[]; truncated: boolean };
type ZenNetworkEntry = {
  method: string;
  url: string;
  status: number | null;
  contentType: string | null;
  startedAt: number;
  ms: number | null;
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
};
type ZenNetworkWatch = { tabKey: string; url: string; active: boolean };
type ZenNetworkRead = ZenNetworkWatch & { entries: ZenNetworkEntry[]; truncated: number };
type ZenNetworkStop = ZenNetworkWatch & { dropped: number };

/**
 * The parsed arguments of the V2 tools. omp validates every call against the tool's `parameters`
 * before it runs, so these are the schemas' output shapes, named here for the approval plumbing.
 */
type TabParams = { tabKey: string };
/** browser_read: `mode` selects the reader-mode article instead of the visible text. */
type ReadParams = { tabKey: string; mode?: string };
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
/** browser_cookies/browser_storage: `reveal` asks for the values themselves instead of `<n chars>`. */
type CookiesParams = { tabKey: string; reveal?: boolean };
type StorageParams = { tabKey: string; kind: string; reveal?: boolean };
type MoveParams = { tabKey: string; spaceId: string };
type SplitParams = { tabKeys: string[]; layout: string };

/** A tool-visible failure: the contract's code plus text the model can read. */
type Failure = { code: string; text: string; details?: Record<string, unknown> };

/** The gate permissions the loader grants independently; `act` implies `read` (loader: #scopeCovers). */
type Permission = "read" | "act" | "network";
/** The order a notice or a budget check names them in (weakest first). */
const PERMISSIONS: Permission[] = ["read", "act", "network"];
/** What each permission lets the loader do, for the terminal hint. */
const PERMISSION_VERBS: Record<Permission, string> = {
  read: "read pages",
  act: "read and act on pages",
  network: "read network data: cookies, downloads, storage, request headers",
};

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
/** The permissions the loader granted this link; the budget for a call depends on them. Reset with
 *  the link. */
let consentGranted = new Set<Permission>();
/** What the pending Allow/Deny notice asks for, or null when nothing waits on a person. */
let consentPending: Permission[] | null = null;
/** Per-tabKey title/URL the plugin last saw, so an approval prompt can name the tab it acts on. */
const knownTabs = new Map<string, { title: string; url: string }>();
/** Per-tabKey elements of the last browser_snapshot, so a prompt can name the ref it acts on. */
const snapshotRefs = new Map<string, Map<string, { role: string; name: string }>>();
/**
 * The /hirozen-grant grants: they are what lets a browser_act on the granted tab or site run without
 * an omp prompt. Process-local, and dropped with the link (teardown, Zen Stop).
 */
const grants = new GrantStore();
/**
 * The origin a pending browser_act's approval was allowed for, keyed by the very args object omp
 * hands to both the approval and execute. The decision has to be taken once: `execute` awaits the
 * link before it sends anything, and a tab cache a parallel reply moved in the meantime - or a grant
 * that expired in it - would otherwise turn an act omp already allowed into one with no origin on the
 * wire, which is the one check that catches a stale cache.
 *
 * Only a grant writes, and `execute` is what takes the entry away: omp evaluates the same approval
 * again when the tool starts (its render path), so an approval that answers "prompt" - a grant that
 * expired, a cache that moved - must leave the decision the gate already made alone. A call that is
 * prompted is the person's own yes and owes no origin check; a call that is covered by a grant and
 * then replaced (a tool_call handler) is a new object with its own entry.
 */
const grantedActOrigins = new WeakMap<object, string>();
/**
 * Set by Zen's Stop button (close 4010); only /hirozen-connect, /hirozen-attach and a /hirozen-setup
 * that changes or clears the pair clear it.
 */
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

/** Config comes from `resolveConfig` alone: env (both vars) beats the pair saved by /hirozen-setup. */

/** The refusal every command and tool gives when it is not the interactive root session. */
const NO_UI_TEXT = "Hirozen needs the interactive omp session: this context has no UI, or it is a subagent.";

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
  const asked = consentPending ?? ["read"];
  ctx.ui.notify(`${prefix}click Allow in Zen to let omp ${permissionVerbs(asked)} (Deny refuses).`, "warning");
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

/** `"read and act on pages"` for a set of permissions; `act` covers `read`, so they never both show. */
function permissionVerbs(permissions: readonly Permission[]): string {
  const has = (need: Permission) => permissions.includes(need);
  return PERMISSIONS.filter(need => has(need) && !(need === "read" && has("act")))
    .map(need => PERMISSION_VERBS[need])
    .join(" and ");
}

/** The permissions a `consent.*` event carries under `key`, or null when the loader sent something
 *  this plugin cannot use. An empty list is a usable answer (nothing granted / nothing asked). */
function eventPermissions(data: unknown, key: "asked" | "granted"): Permission[] | null {
  if (!data || typeof data !== "object" || !(key in data)) return null;
  const value = (data as Record<string, unknown>)[key];
  if (!Array.isArray(value)) return null;
  return value.every(need => PERMISSIONS.includes(need as Permission)) ? (value as Permission[]) : null;
}

/** Loader events: the consent gate, whose granted set drives every call's budget. */
function handleLoaderEvent(event: LoaderEvent): void {
  if (event.name === "consent.pending") {
    // A call joining the notice adds its own permission, so this also fires for an upgrade.
    consentPending = eventPermissions(event.data, "asked") ?? ["read"];
    announceGateWait();
    return;
  }
  if (event.name === "consent.granted") {
    const granted = eventPermissions(event.data, "granted");
    if (granted === null) return;
    consentGranted = new Set(granted);
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
  // The gate belongs to the loader, which clears it with the link: a new link starts with nothing
  // granted and must ask again. The caches describe what that link last saw, so they go with it.
  consentGranted = new Set();
  consentPending = null;
  knownTabs.clear();
  snapshotRefs.clear();
  // A grant is anchored to a tab's last known URL, which dies with the cache: it goes too.
  grants.clear();
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
  // One microtask of delay before the body runs, because the body can fail before its first await (a
  // failed verify) and `connectPromise = attempt` below has to run before the catch clears it: run
  // inline, the catch's clear is clobbered by that assignment, and the rejected promise stays cached
  // so every later call replays the same error.
  const attempt = Promise.resolve().then(async () => {
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
      // The loader reports the install folder it runs from (GreD). A loader left behind in another
      // install would drive the wrong Zen while looking perfectly healthy: refuse it here, where the
      // loader is not published yet. An older loader sends no field, and its sha already failed above.
      if (ready.zenDir !== undefined && normalizePath(ready.zenDir) !== normalizePath(config.zenDir)) {
        fresh.close();
        throw new HirozenError(
          "E_CONFIG",
          `the running Hirozen loader belongs to ${ready.zenDir}, but Hirozen is set up for ` +
            `${config.zenDir}; run /hirozen-setup`,
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
  });
  connectPromise = attempt;
  return attempt;
}

/** The tool check order fixed by the plan: root/UI, sticky stop, config, connect. */
async function requireLink(pi: ExtensionAPI, ctx: ExtensionContext): Promise<{ link: ZenLink } | { failure: Failure }> {
  if (!(ctx.hasUI && ctx.agent?.kind === "main")) {
    return { failure: { code: "E_NO_UI", text: NO_UI_TEXT } };
  }
  if (stopKind) return { failure: { code: "E_STOPPED", text: STOP_TEXT[stopKind] } };
  const config = await resolveConfig(ctx.cwd);
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
    'Pass a tabKey to browser_read, browser_screenshot, browser_snapshot, browser_act, browser_upload, browser_dialog and the zen_* layout tools. "lazy" tabs have no document yet: the read tools refuse them and zen_load_tab loads one without selecting it. Loaded tabs in a non-active space can be read, snapshotted and screenshotted; acts, uploads and dialogs there are refused, because Hirozen never switches spaces. zen_tabs and the read tools never load or activate a tab; zen_load_tab loads (but never selects) a tab, browser_act navigate and zen_open load pages, and zen_glance selects its glance tab.',
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

/**
 * The omp-side budget for one call: 15 s of base work plus 125 s while the Hirozen Allow/Deny notice
 * may still be waiting for an answer, which is whenever the granted set does not cover what the call
 * needs (mirroring the loader's `#scopeCovers`: a granted `act` covers `read`, nothing else covers
 * anything). The loader receives the same instant as an absolute deadline and refuses to act once it
 * passed, so a late answer never turns into an action omp has already given up on.
 */
function callBudget(needs: Permission): number {
  const covered = consentGranted.has(needs) || (needs === "read" && consentGranted.has("act"));
  return covered ? BASE_BUDGET_MS : BASE_BUDGET_MS + PERSON_WAIT_MS;
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
    // Ungated, so no person wait: the base budget, never link.ts's 150 s default (Rev 2: every tool
    // base 15 s, +125 s only while the Hirozen gate may prompt).
    const windows = await access.link.call<ZenWindow[]>("zen.inventory", {}, { timeoutMs: BASE_BUDGET_MS, signal });
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
    const windows = await access.link.call<ZenSpaceWindow[]>("zen.spaces", {}, { timeoutMs: BASE_BUDGET_MS, signal });
    return {
      content: [{ type: "text", text: renderSpaces(windows) }],
      details: { windowCount: windows.length, windows },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

/**
 * `# <title>\n<url>` and, when the reader found one, its byline, then the text; the header is capped
 * so one page cannot flood the terminal. A text read has no byline and renders as it always did.
 */
function renderRead(page: ZenRead): string {
  return `${pageHeader(page.url, page.title)}\n${page.byline ?? ""}\n${page.text}`;
}

async function runBrowserRead(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  params: ReadParams,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  // mode "text" is the loader's default, so only an article read names a mode on the wire.
  const article = params.mode === "article";
  try {
    const page = await access.link.call<ZenRead>(
      "browser.read",
      article ? { tabKey: params.tabKey, mode: "article" } : { tabKey: params.tabKey },
      { timeoutMs: callBudget("read"), signal },
    );
    rememberTab(params.tabKey, page);
    return {
      content: [{ type: "text", text: renderRead(page) }],
      details: {
        tabKey: page.tabKey,
        url: page.url,
        title: page.title,
        mode: article ? "article" : "text",
        truncated: page.truncated,
        chars: page.text.length,
        ...(article ? { byline: typeof page.byline === "string" ? page.byline : "" } : {}),
      },
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
  // The origin the approval let this call through for, decided there and consumed here (see
  // grantedActOrigins): naming it on the wire lets the loader check the tab's live URL, so a stale tab
  // cache here cannot act on a site nobody granted. Reading it after the await above is what keeps the
  // act omp allowed from losing that check - nothing recomputes it once the link is up - and taking it
  // (rather than reading it) is what keeps a later approval from seeing an answer of its own.
  const grantOrigin = grantedActOrigins.get(params);
  grantedActOrigins.delete(params);
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
        ...(grantOrigin ? { grantOrigin } : {}),
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
    // The loader refused because the tab is not on the granted site any more: that URL is where the
    // tab is now, so the next call is prompted (with the grant no longer covering it) instead of
    // looping through the same stale cache entry.
    if (error instanceof HirozenError && error.code === "E_GRANT_STALE" && typeof error.url === "string") {
      rememberTab(params.tabKey, { url: error.url });
    }
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

// ---------------------------------------------------------------------------------------------
// Network (T9-T11): the tab's cookies, its page storage, Zen's downloads, and its request headers
// ---------------------------------------------------------------------------------------------
//
// Every call here runs under the loader's `network` permission and its own in-Zen Allow/Deny prompt,
// so a call that still has to ask carries the person wait (`callBudget("network")`, exactly like act).
// The loader has already redacted what matters: cookie and storage values are `"<n chars>"` unless the
// call asked for `reveal`, and a recorded request's headers never carry a live cookie or authorization
// value. This side only renders what came back.

/** `flags=secure,httpOnly,sameSite=lax` for the cookie attributes that are set, or "" for none.
 *  `sameSite` is the name the loader maps nsICookie's integer to; "unset" means the cookie has no
 *  sameSite attribute at all, which is not a flag. */
function cookieFlags(cookie: ZenCookie): string {
  const flags = [
    cookie.secure ? "secure" : "",
    cookie.httpOnly ? "httpOnly" : "",
    cookie.sameSite && cookie.sameSite !== "unset" ? `sameSite=${cookie.sameSite}` : "",
  ].filter(flag => flag !== "");
  return flags.length === 0 ? "" : ` flags=${flags.join(",")}`;
}

function renderCookies(reply: ZenCookies): string {
  const lines = [pageHeader(reply.url, `${reply.cookies.length} cookie(s) for tab ${reply.tabKey}`)];
  for (const cookie of reply.cookies) {
    const expires = cookie.expires === null ? "session" : new Date(cookie.expires).toISOString();
    lines.push(
      `- ${cookie.name}=${cookie.value} domain=${cookie.domain} path=${cookie.path} expires=${expires}${cookieFlags(cookie)}`,
    );
  }
  if (reply.truncated) lines.push("", "The list stops at 64 KB of cookie data.");
  return lines.join("\n");
}

function renderStorage(reply: ZenStorage): string {
  const lines = [pageHeader(reply.url, `${reply.entries.length} ${reply.kind} entry(s) for tab ${reply.tabKey}`)];
  // IndexedDB answers database names only, which the loader sends with a null value.
  for (const entry of reply.entries) lines.push(entry.value === null ? `- ${entry.key}` : `- ${entry.key}=${entry.value}`);
  if (reply.truncated) lines.push("", "The list stops at 64 KB of storage data.");
  return lines.join("\n");
}

/** `<n>/<total> bytes, started <ISO>`: as much as Zen knows about one download. */
function downloadNote(download: ZenDownload): string {
  const started = download.startedAt === null ? "unknown" : new Date(download.startedAt).toISOString();
  return `${download.bytes ?? "?"}/${download.totalBytes ?? "?"} bytes, started ${started}`;
}

function renderDownloads(reply: ZenDownloads): string {
  const lines = [`# ${reply.downloads.length} download(s), newest first`];
  for (const download of reply.downloads) {
    lines.push(`- ${download.state} ${download.source} -> ${download.target} (${downloadNote(download)})`);
  }
  if (reply.truncated) lines.push("", "Only the newest 50 downloads are listed.");
  return lines.join("\n");
}

/** One `name=value` header line, or null when that side of the exchange carried no header. */
function headerLine(side: string, headers: Record<string, string>): string | null {
  const pairs = Object.entries(headers);
  return pairs.length === 0 ? null : `  ${side}: ${pairs.map(([name, value]) => `${name}=${value}`).join(" ")}`;
}

function renderNetworkRead(reply: ZenNetworkRead): string {
  const lines = [pageHeader(reply.url, `${reply.entries.length} request(s) in tab ${reply.tabKey}`)];
  if (!reply.active) lines.push("", "This tab is not being recorded any more; start it again with browser_network_start.");
  for (const entry of reply.entries) {
    const status = entry.status === null ? "(no response)" : String(entry.status);
    const timing = entry.ms === null ? "" : `, ${entry.ms} ms`;
    lines.push(`- ${entry.method} ${status} ${entry.url} (${entry.contentType ?? "no content type"}${timing})`);
    for (const line of [headerLine("request", entry.requestHeaders), headerLine("response", entry.responseHeaders)]) {
      if (line !== null) lines.push(line);
    }
  }
  if (reply.truncated > 0) {
    lines.push("", `${reply.truncated} more request(s) did not fit in this reply (64 KB) and are gone; record again for more.`);
  }
  return lines.join("\n");
}

function renderNetworkStart(reply: ZenNetworkWatch): string {
  return `${pageHeader(reply.url, `Watching tab ${reply.tabKey}`)}\nRequests are recorded until browser_network_stop; read them with browser_network_read.`;
}

function renderNetworkStop(reply: ZenNetworkStop): string {
  return `${pageHeader(reply.url, `Stopped watching tab ${reply.tabKey}`)}\n${reply.dropped} buffered request(s) were dropped.`;
}

async function runBrowserCookies(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  params: CookiesParams,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  // `reveal` is only ever sent when asked for: the loader answers "<n chars>" otherwise, and its own
  // prompt (and this plugin's approval) is what a reveal costs.
  const wire = params.reveal === true ? { tabKey: params.tabKey, reveal: true } : { tabKey: params.tabKey };
  try {
    const reply = await access.link.call<ZenCookies>("network.cookies", wire, {
      timeoutMs: callBudget("network"),
      signal,
    });
    rememberTab(params.tabKey, reply);
    return {
      content: [{ type: "text", text: renderCookies(reply) }],
      details: {
        tabKey: reply.tabKey,
        url: reply.url,
        cookies: reply.cookies.length,
        revealed: params.reveal === true,
        truncated: reply.truncated,
      },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runBrowserStorage(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  params: StorageParams,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  const wire =
    params.reveal === true
      ? { tabKey: params.tabKey, kind: params.kind, reveal: true }
      : { tabKey: params.tabKey, kind: params.kind };
  try {
    const reply = await access.link.call<ZenStorage>("network.storage", wire, {
      timeoutMs: callBudget("network"),
      signal,
    });
    rememberTab(params.tabKey, reply);
    return {
      content: [{ type: "text", text: renderStorage(reply) }],
      details: {
        tabKey: reply.tabKey,
        url: reply.url,
        kind: reply.kind,
        entries: reply.entries.length,
        revealed: params.reveal === true,
        truncated: reply.truncated,
      },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runBrowserDownloads(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const reply = await access.link.call<ZenDownloads>("network.downloads", {}, {
      timeoutMs: callBudget("network"),
      signal,
    });
    return {
      content: [{ type: "text", text: renderDownloads(reply) }],
      details: { downloads: reply.downloads.length, truncated: reply.truncated },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runBrowserNetworkStart(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  tabKey: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const reply = await access.link.call<ZenNetworkWatch>("network.start", { tabKey }, {
      timeoutMs: callBudget("network"),
      signal,
    });
    rememberTab(tabKey, reply);
    return {
      content: [{ type: "text", text: renderNetworkStart(reply) }],
      details: { tabKey: reply.tabKey, url: reply.url, active: reply.active },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runBrowserNetworkRead(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  tabKey: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    // Reading clears what was buffered, so this is the one look at those requests.
    const reply = await access.link.call<ZenNetworkRead>("network.read", { tabKey }, {
      timeoutMs: callBudget("network"),
      signal,
    });
    rememberTab(tabKey, reply);
    return {
      content: [{ type: "text", text: renderNetworkRead(reply) }],
      details: {
        tabKey: reply.tabKey,
        url: reply.url,
        active: reply.active,
        requests: reply.entries.length,
        truncated: reply.truncated,
      },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

async function runBrowserNetworkStop(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  tabKey: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const reply = await access.link.call<ZenNetworkStop>("network.stop", { tabKey }, {
      timeoutMs: callBudget("network"),
      signal,
    });
    rememberTab(tabKey, reply);
    return {
      content: [{ type: "text", text: renderNetworkStop(reply) }],
      details: { tabKey: reply.tabKey, url: reply.url, dropped: reply.dropped },
    };
  } catch (error) {
    return fail(describeError(error));
  }
}

/**
 * `zen.loadTab` answers with the page the lazy tab restored to; the loader has already put the user's
 * selected tab and space back, so the reply only has to name what loaded.
 */
async function runZenLoadTab(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  tabKey: string,
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const access = await requireLink(pi, ctx);
  if ("failure" in access) return fail(access.failure);
  try {
    const loaded = await access.link.call<ZenLoadTab>("zen.loadTab", { tabKey }, { timeoutMs: callBudget("act"), signal });
    rememberTab(tabKey, loaded);
    return {
      content: [
        {
          type: "text",
          text: [
            `Loaded tab ${loaded.tabKey} in the background; the user's space and selected tab are unchanged.`,
            pageHeader(loaded.url, loaded.title),
          ].join("\n"),
        },
      ],
      details: { tabKey: loaded.tabKey, url: loaded.url, title: loaded.title },
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
    // The page may redirect: the loader reports where the load landed, and both the reply and the tab
    // cache (which feeds the approval details of later calls on this tab) must name the page the tab
    // actually shows, not the URL that was asked for.
    const landed = opened.url || url;
    rememberTab(opened.tabKey, { url: landed, title: opened.title });
    return {
      content: [
        {
          type: "text",
          text: [
            `Opened a tab in the "Hirozen Agent" space (space ${opened.spaceId}), tab ${opened.tabKey}; it is in the background.`,
            pageHeader(landed, opened.title ?? ""),
          ].join("\n"),
        },
      ],
      details: { tabKey: opened.tabKey, spaceId: opened.spaceId, url: landed, title: opened.title },
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
/** A granted browser_act: omp allows it outright in every mode (a user deny rule still wins). */
type GrantedApproval = { tier: "write"; policy: "allow"; reason: string };
/** What a tool's `approval` may answer: a bare tier (a plain read), or a tier with its own policy. */
type ApprovalDecision = "read" | ExecApproval | GrantedApproval;

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

/**
 * browser_act's approval: while a /hirozen-grant covers this tab and this action, omp allows the call
 * outright (write tier, allow policy — honoured in every approval mode, though a user deny rule still
 * wins) instead of prompting. Everything else prompts, navigate always: it can leave the site the
 * grant was given for.
 *
 * A grant records the origin for this exact args object as it is taken; `execute` reads it back and
 * sends `grantOrigin`, so the grant check the loader does cannot be lost between the approval and the
 * call (grantedActOrigins). Only a grant writes: omp asks this same question again when the tool
 * starts (its render path), and a "no" there — the grant expired, or a parallel reply moved the tab
 * cache in between — must not erase the decision the gate already made.
 */
function actApproval(args: unknown): ApprovalDecision {
  const params = approvalArgs<ActParams>(args);
  const grant = grants.coveringAct(params.tabKey, knownTabs.get(params.tabKey)?.url, params.action);
  if (grant) rememberGrantedAct(args, grant.origin);
  if (!grant) {
    return {
      tier: "exec",
      policy: "prompt",
      reason: "browser_act changes a page in Zen (click, type, press, scroll, hover or navigate).",
    };
  }
  const minutes = Math.max(1, Math.ceil((grant.until - Date.now()) / 60_000));
  return {
    tier: "write",
    policy: "allow",
    reason: `granted by /hirozen-grant: ${grant.origin} for ${minutes} more min`,
  };
}

/** What `actApproval` decided about one browser_act call, for `execute` to read and consume. */
function rememberGrantedAct(args: unknown, origin: string): void {
  if (typeof args !== "object" || args === null) return;
  grantedActOrigins.set(args, origin);
}

/** browser_cookies: a read, unless the call asks for the cookie values themselves. */
function cookiesApproval(args: unknown): ApprovalDecision {
  if (approvalArgs<CookiesParams>(args).reveal !== true) return "read";
  return {
    tier: "exec",
    policy: "prompt",
    reason: "browser_cookies with reveal:true returns the cookie values themselves.",
  };
}

/** browser_storage: a read, unless the call asks for the stored values themselves (IndexedDB answers
 *  database names only, so reveal changes nothing there). */
function storageApproval(args: unknown): ApprovalDecision {
  const params = approvalArgs<StorageParams>(args);
  if (params.reveal !== true || params.kind === "indexeddb") return "read";
  return {
    tier: "exec",
    policy: "prompt",
    reason: "browser_storage with reveal:true returns the stored values themselves.",
  };
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
    case "hover":
      lines.push(`action: hover over ${target ?? "the page"}`);
      break;
    case "navigate":
      lines.push(`action: navigate to ${params.url ?? "?"}`);
      break;
    default:
      lines.push(`action: ${params.action}`);
  }
  return lines;
}

/** browser_cookies: the tab, and whether the cookie values themselves are shown. */
function cookiesApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<CookiesParams>(args);
  return [
    `tab: ${describeTab(params.tabKey)}`,
    params.reveal === true
      ? "action: read this tab's cookies WITH their values"
      : "action: read this tab's cookies (values redacted)",
  ];
}

/** browser_storage: the tab, the store, and whether the stored values themselves are shown. */
function storageApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<StorageParams>(args);
  return [
    `tab: ${describeTab(params.tabKey)}`,
    `action: read this tab's ${params.kind} storage${params.reveal === true ? " WITH its values" : " (values redacted)"}`,
  ];
}

/** browser_network_start: which tab starts being recorded, and what stays redacted. */
function networkStartApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<TabParams>(args);
  return [
    `tab: ${describeTab(params.tabKey)}`,
    "action: record this tab's requests (URLs, statuses and headers; cookie and authorization values are redacted)",
  ];
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

/** zen_load_tab: which tab starts loading, and that the view is left alone. */
function loadTabApprovalDetails(args: unknown): string[] {
  const params = approvalArgs<TabParams>(args);
  return [`tab: ${describeTab(params.tabKey)}`, "action: load the tab in the background without selecting it"];
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

/** A config problem as a notice: "Hirozen: " unless the problem already starts with "Hirozen". */
function configNotice(problem: string): string {
  return problem.startsWith("Hirozen") ? problem : `Hirozen: ${problem}`;
}

async function runInstallCommand(ctx: ExtensionContext): Promise<void> {
  const resolved = await resolveConfig(ctx.cwd);
  if (!resolved.ok) {
    ctx.ui.notify(configNotice(resolved.problem), "error");
    return;
  }
  const { zenDir } = resolved.config;
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
  const resolved = await resolveConfig(ctx.cwd);
  if (!resolved.ok) {
    ctx.ui.notify(configNotice(resolved.problem), "error");
    return;
  }
  try {
    // attachNow notifies right before it forwards the command line: the "Incoming Connection" prompt
    // only appears once the prefs, lock and loader-hash checks have passed, so a refusal stays silent.
    const attached = await attachNow({
      zenDir: resolved.config.zenDir,
      profileDir: resolved.config.profileDir,
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

/** `verify()` and the read errors it can throw, in the one shape its callers classify. */
function verifyQuietly(zenDir: string): { checked: VerifyResult } | { problem: string } {
  try {
    return { checked: verify(zenDir) };
  } catch (error) {
    return { problem: messageOf(error) };
  }
}

/** Read-only install check shared by the session_start warning and /hirozen-status. */
function checkInstalled(zenDir: string): { ok: boolean; text: string } {
  const outcome = verifyQuietly(zenDir);
  if ("problem" in outcome) return { ok: false, text: outcome.problem };
  const checked = outcome.checked;
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
  const granted = status.consent ?? [];
  const asking = status.consentPending ?? [];
  const parts = [
    `state=${status.state ?? "?"}`,
    `mode=${status.mode ?? "?"}`,
    `zenPid=${status.zenPid ?? "?"}`,
    `consent=${granted.length === 0 ? "none" : granted.join(",")}${asking.length > 0 ? ` (asking: ${asking.join(",")})` : ""}`,
    `capabilities=${renderCapabilities(status.capabilities)}`,
    `updated=${status.updated ?? "?"}`,
  ];
  if (status.lastClose) parts.push(`lastClose=${status.lastClose}`);
  if (status.actorError) parts.push(formatStatusError("actorError", status.actorError));
  return parts.join(" ");
}

/** Every capability the running Zen reported as missing, or a note that there is nothing to report. */
function renderCapabilities(capabilities: Record<string, boolean> | undefined): string {
  if (!capabilities) return "not reported";
  const missing = Object.keys(capabilities).filter(name => capabilities[name] !== true);
  return missing.length === 0 ? "all present" : `missing ${missing.join(", ")}`;
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
  const resolved = await resolveConfig(ctx.cwd);
  const zenDir = resolved.ok ? resolved.config.zenDir : "";
  const profileDir = resolved.ok ? resolved.config.profileDir : "";
  const installed = resolved.ok ? checkInstalled(zenDir) : null;
  const where = resolved.ok
    ? resolved.source === "env"
      ? "from env"
      : `from settings${resolved.overridePath === undefined ? "" : `; project override ${resolved.overridePath}`}`
    : "";
  const session = stopKind
    ? `stopped (${stopKind}) — run /hirozen-connect`
    : link
      ? "connected"
      : "not connected (the first tool call connects)";
  const unset = "not read (Hirozen is not set up)";
  const lines = [
    "Hirozen status",
    `config: ${resolved.ok ? `${zenDir} | ${profileDir} (${where})` : resolved.problem}`,
    `loader: ${installed ? `${installed.ok ? "ok" : "NOT ok"} (${installed.text})` : "not checked (Hirozen is not set up)"}`,
    `session: ${session}`,
    `grants: ${renderGrants()}`,
    `status file: ${profileDir === "" ? unset : renderStatusFile(profileDir)}`,
    `devtools prefs: ${profileDir === "" ? unset : renderDevtoolsPrefs(profileDir)}`,
  ];
  ctx.ui.notify(lines.join("\n"), stopKind !== null || (installed !== null && !installed.ok) ? "warning" : "info");
}

/** The live grants for /hirozen-status: `<origin> (<tab|every tab>) until <time>`, or "none". */
function renderGrants(): string {
  const live = grants.list();
  if (live.length === 0) return "none";
  return live
    .map(grant => {
      const what = grant.kind === "tab" ? `tab ${grant.key}` : "every tab";
      return `${grant.origin} (${what}) until ${new Date(grant.until).toLocaleTimeString()}`;
    })
    .join("; ");
}

/** What a `/hirozen-grant` target means: an http(s) origin, or a tab the plugin has seen. */
type GrantTarget = { kind: "tab" | "origin"; key: string; origin: string; what: string };

/**
 * Resolve one `/hirozen-grant` target, or say why it cannot be granted. A target that parses as an
 * http(s) URL is the site itself; anything else has to be a tabKey from zen_tabs, and the grant is then
 * anchored to the origin that tab is on now (so a tab that navigates away stops being covered).
 */
function resolveGrantTarget(target: string): GrantTarget | { problem: string } {
  const origin = originOf(target);
  if (origin !== null) return { kind: "origin", key: origin, origin, what: `every tab on ${origin}` };
  const known = knownTabs.get(target);
  if (known === undefined) {
    return {
      problem: `no such tab ${target}; list the tabs with zen_tabs, or give an http(s) origin like https://example.com`,
    };
  }
  const tabOrigin = originOf(known.url);
  if (tabOrigin === null) {
    const where = known.url === "" ? "a page with no URL" : known.url;
    return { problem: `tab ${target} is on ${where}, which no grant can cover (an http(s) page is needed)` };
  }
  return { kind: "tab", key: target, origin: tabOrigin, what: `tab ${describeTab(target)}` };
}

/**
 * `/hirozen-grant <tabKey|origin> <minutes>` and `/hirozen-grant clear` (T12). Slash command only: the
 * agent can never grant itself anything.
 *
 * A grant is the one thing that makes a browser_act run without an omp approval prompt, and only for
 * the act actions: navigate (it can leave the site), uploads, page dialogs, the zen_* tools, the
 * network tools and a reveal always ask. The in-Zen permissions are unchanged by a grant, and the
 * grant is anchored to the origin the target was on when it was given.
 */
async function runGrantCommand(ctx: ExtensionContext, args: string): Promise<void> {
  if (!(ctx.hasUI && ctx.agent?.kind === "main")) {
    ctx.ui.notify(`Hirozen: ${NO_UI_TEXT}`, "error");
    return;
  }
  const [target = "", minutesText = ""] = args.trim().split(/\s+/);
  if (target === "clear") {
    const dropped = grants.clear();
    ctx.ui.notify(
      dropped === 0 ? "Hirozen: no grants to clear." : `Hirozen: cleared ${dropped} grant(s); browser_act asks again.`,
      "info",
    );
    return;
  }
  if (target === "") {
    ctx.ui.notify(
      `Hirozen: give a tabKey from zen_tabs or an http(s) origin, then the minutes (${GRANT_MINUTES_MIN} to ${GRANT_MINUTES_MAX}).`,
      "error",
    );
    return;
  }
  const minutes = parseGrantMinutes(minutesText);
  if (minutes === null) {
    ctx.ui.notify(`Hirozen: the minutes must be a whole number from ${GRANT_MINUTES_MIN} to ${GRANT_MINUTES_MAX}.`, "error");
    return;
  }
  const resolved = resolveGrantTarget(target);
  if ("problem" in resolved) {
    ctx.ui.notify(`Hirozen: ${resolved.problem}.`, "error");
    return;
  }
  const confirmed = await ctx.ui.confirm(
    "Grant omp permission to act in Zen?",
    `For the next ${minutes} minute(s), browser_act clicks, typing, key presses, scrolling and hovers in ${resolved.what} run without an omp approval prompt (the in-Zen Allow/Deny prompt is unchanged).\n\nNavigate, uploads, page dialogs, the zen_* tools, the network tools and a reveal always ask. Remove it early with /hirozen-grant clear.`,
  );
  if (!confirmed) {
    ctx.ui.notify("Hirozen: no grant was added.", "info");
    return;
  }
  const grant = grants.grant(resolved.kind, resolved.key, resolved.origin, minutes);
  ctx.ui.notify(
    `Hirozen: granted ${resolved.origin} for ${minutes} min (until ${new Date(grant.until).toLocaleTimeString()}); ${resolved.what} runs without an approval prompt. Navigate and everything else still ask.`,
    "warning",
  );
}

// ---------------------------------------------------------------------------------------------
// /hirozen-setup: propose the pairs this machine has, let the user confirm one, save it
// ---------------------------------------------------------------------------------------------

/** The label that opens manual entry; always last, so `indexOf` keeps mapping labels to candidates. */
const MANUAL_LABEL = "Enter paths manually…";

/** `<profileName> — <zenDir> (Zen <version>[, running])`, the label setup offers for one candidate. */
function candidateLabel(candidate: Candidate): string {
  const flags = [candidate.zenVersion ? `Zen ${candidate.zenVersion}` : "", candidate.running ? "running" : ""].filter(
    part => part !== "",
  );
  return `${candidate.profileName} — ${candidate.zenDir}${flags.length > 0 ? ` (${flags.join(", ")})` : ""}`;
}

/**
 * One label per candidate, plus the manual entry. Two candidates whose labels would read the same
 * (same profile name and install folder) get their profile folder's basename appended, so a label
 * `ctx.ui.select` returns maps back to exactly one candidate.
 */
function candidateLabels(candidates: Candidate[]): string[] {
  const base = candidates.map(candidateLabel);
  const counts = new Map<string, number>();
  for (const label of base) counts.set(label, (counts.get(label) ?? 0) + 1);
  const labels = base.map((label, index) =>
    (counts.get(label) ?? 0) > 1 ? `${label} [${basename(candidates[index].profileDir)}]` : label,
  );
  return [...labels, MANUAL_LABEL];
}

/** One typed path, normalized and required to be absolute; null when the user cancelled or it was not. */
async function askPath(ctx: ExtensionContext, title: string, what: string): Promise<string | null> {
  const typed = await ctx.ui.input(title);
  if (typed === undefined) return null;
  const path = normalizeManualPath(typed);
  if (path === null) {
    ctx.ui.notify(`Hirozen: that is not an absolute ${what} (for example D:\\PROGRAMS). Nothing was saved.`, "error");
    return null;
  }
  return path;
}

/** Two `ctx.ui.input`s; null when the user cancelled either one. */
async function manualPair(ctx: ExtensionContext): Promise<HirozenConfig | null> {
  const zenDir = await askPath(ctx, "Zen install folder (the folder holding zen.exe)", "Zen install folder");
  if (zenDir === null) return null;
  const profileDir = await askPath(ctx, "Zen profile folder (the folder holding prefs.js)", "Zen profile folder");
  if (profileDir === null) return null;
  return { zenDir, profileDir };
}

/** Discovery only proposes; the user always confirms, even when there is exactly one candidate. */
async function choosePair(ctx: ExtensionContext): Promise<HirozenConfig | null> {
  const candidates = await discoverZen({
    appData: process.env.APPDATA ?? "",
    processes: await listZenProcesses(),
    isLocked: profileLocked,
  });
  if (candidates.length === 0) {
    ctx.ui.notify("Hirozen: no Zen install with a profile was found; enter the paths manually.", "info");
    return manualPair(ctx);
  }
  const labels = candidateLabels(candidates);
  const picked = await ctx.ui.select("Which Zen should Hirozen use?", labels);
  if (picked === undefined) return null;
  const index = labels.indexOf(picked);
  if (index === labels.length - 1) return manualPair(ctx);
  const candidate = candidates[index];
  return candidate === undefined ? null : { zenDir: candidate.zenDir, profileDir: candidate.profileDir };
}

/**
 * What the session still overrides after the pair was saved, so the notify never promises too much.
 * Both notes come from `resolveConfig`'s own answer: a successful save leaves only the env pair (or
 * nothing) able to outrank the settings, and an incomplete env pair is exactly the problem it reports.
 */
function envOverrideNote(after: ResolveConfigResult): string {
  if (after.ok && after.source === "env") {
    return " HIROZEN_ZEN_DIR and HIROZEN_PROFILE are set: they still win in this session.";
  }
  if (!after.ok) return ` The env override is incomplete and still wins in this session: ${after.problem}`;
  return "";
}

/** Offer the loader install after setup when verify() says this install has none (or an old one). */
async function offerInstall(ctx: ExtensionContext, zenDir: string, problem: string): Promise<void> {
  const wanted = await ctx.ui.confirm("Install the Hirozen loader into this Zen?", `${problem}\n\nInstall it now?`);
  if (!wanted) return;
  try {
    install(zenDir);
    ctx.ui.notify(
      `Hirozen: loader installed into ${zenDir}. Restart Zen to load it, or run /hirozen-attach if it is already running.`,
      "info",
    );
  } catch (error) {
    const described = describeError(error);
    ctx.ui.notify(`Hirozen: ${described.code}: ${described.text}`, "error");
  }
}

/** The interactive half of /hirozen-setup: choose, validate, confirm, save, then offer the install. */
async function setupPair(ctx: ExtensionContext): Promise<void> {
  const pair = await choosePair(ctx);
  if (pair === null) return;
  const missing = [
    ...(existsSync(join(pair.zenDir, "zen.exe")) ? [] : [`${join(pair.zenDir, "zen.exe")} does not exist`]),
    ...(existsSync(join(pair.profileDir, "prefs.js")) ? [] : [`${join(pair.profileDir, "prefs.js")} does not exist`]),
  ];
  if (missing.length > 0) {
    ctx.ui.notify(`Hirozen: that is not a usable Zen pair (${missing.join("; ")}). Nothing was saved.`, "error");
    return;
  }
  // The profile remembers the install it last ran from. The pair is still the user's call, but the
  // confirm has to say so before they make it.
  const compatibility = readCompatibility(pair.profileDir);
  const note =
    compatibility && normalizePath(compatibility.lastPlatformDir) !== normalizePath(pair.zenDir)
      ? `\n(this profile last ran from ${compatibility.lastPlatformDir})`
      : "";
  const confirmed = await ctx.ui.confirm("Use this Zen for Hirozen?", `${pair.zenDir}\n${pair.profileDir}${note}`);
  if (!confirmed) return;

  const previous = await resolveConfig(ctx.cwd);
  try {
    await saveConfig(ctx.cwd, pair);
  } catch (error) {
    ctx.ui.notify(`Hirozen: ${messageOf(error)}`, "error");
    return;
  }
  const after = await resolveConfig(ctx.cwd);
  // A live link and a sticky stop belong to the Zen the session is actually using, so compare the pair
  // in effect before the save with the one in effect after it: a save that leaves the effective pair
  // alone (env or a project override still pins the same Zen) must tear nothing down. Exactly one of
  // the two being usable is a change by definition; both unusable is not.
  const changed =
    previous.ok !== after.ok ||
    (previous.ok &&
      after.ok &&
      (normalizePath(previous.config.zenDir) !== normalizePath(after.config.zenDir) ||
        normalizePath(previous.config.profileDir) !== normalizePath(after.config.profileDir)));
  if (changed) {
    shutdownLink();
    stopKind = null;
  }

  const shadowed =
    after.ok && after.overridePath !== undefined
      ? ` A project override at ${after.overridePath} shadows the saved setting(s); edit it to change what Hirozen uses here.`
      : "";
  ctx.ui.notify(
    `Hirozen: using ${pair.zenDir} with profile ${pair.profileDir}.${envOverrideNote(after)}${shadowed}`,
    "info",
  );

  const outcome = verifyQuietly(pair.zenDir);
  const problem = "problem" in outcome ? outcome.problem : outcome.checked.ok ? null : outcome.checked.reason;
  if (problem !== null) await offerInstall(ctx, pair.zenDir, problem);
}

/** `/hirozen-setup clear`: forget the pair and drop the link and stop that belonged to it. */
async function clearPair(ctx: ExtensionContext): Promise<void> {
  try {
    await clearConfig(ctx.cwd);
  } catch (error) {
    ctx.ui.notify(`Hirozen: ${messageOf(error)}`, "error");
    return;
  }
  shutdownLink();
  stopKind = null;
  ctx.ui.notify("Hirozen: forgot the saved Zen and profile; run /hirozen-setup to choose them again.", "info");
}

async function runSetupCommand(ctx: ExtensionContext, args: string): Promise<void> {
  if (!(ctx.hasUI && ctx.agent?.kind === "main")) {
    ctx.ui.notify(`Hirozen: ${NO_UI_TEXT}`, "error");
    return;
  }
  if (args.trim() === "clear") {
    await clearPair(ctx);
    return;
  }
  await setupPair(ctx);
}

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
    read: builder.object({
      tabKey: tabKey(),
      mode: builder
        .enum(["text", "article"])
        .optional()
        .describe('"article" reads the page in reader mode (title, byline, article text) instead of the visible text'),
    }),
    act: builder.object({
      tabKey: tabKey(),
      action: builder
        .enum(["click", "type", "press", "scroll", "hover", "navigate"])
        .describe("what to do on the tab"),
      ref: builder
        .string()
        .optional()
        .describe("element ref from browser_snapshot (click/type/press/scroll/hover target)"),
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
    cookies: builder.object({
      tabKey: tabKey(),
      reveal: builder
        .boolean()
        .optional()
        .describe('return the cookie values themselves instead of "<n chars>" (needs its own approval)'),
    }),
    storage: builder.object({
      tabKey: tabKey(),
      kind: builder
        .enum(["local", "session", "indexeddb"])
        .describe("which storage to read; indexeddb lists database names only"),
      reveal: builder
        .boolean()
        .optional()
        .describe('return the stored values themselves instead of "<n chars>" (needs its own approval)'),
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

/** Zen's name for the reinstall confirm: `Zen <version>` from application.ini's `[App] Version`, else "Zen". */
function zenName(zenDir: string): string {
  try {
    const lines = readFileSync(join(zenDir, "application.ini"), "utf8").replace(/^\uFEFF/, "").split(/\r?\n/);
    let inApp = false;
    for (const line of lines) {
      const section = /^\s*\[([^\]]+)\]\s*$/.exec(line);
      if (section) {
        inApp = section[1].toLowerCase() === "app";
        continue;
      }
      const version = inApp ? /^Version=(.+)$/.exec(line.trim())?.[1]?.trim() : undefined;
      if (version) return `Zen ${version}`;
    }
    return "Zen";
  } catch {
    return "Zen";
  }
}

/**
 * A Zen update replaces the install folder, which wipes the loader. `verify` reports that as "every
 * module is missing" (nothing installed, nothing mismatched) while zen.exe is still there; anything
 * else keeps the ordinary warning. Never installs without the confirm.
 *
 * `/hirozen-attach` is only named when that Zen is still running: attaching needs a live process, and
 * a hint nobody can follow is worse than none (the restart advice always applies).
 */
async function offerReinstall(ctx: ExtensionContext, zenDir: string): Promise<void> {
  const confirmed = await ctx.ui.confirm(
    "Hirozen was removed from Zen",
    `${zenName(zenDir)} no longer has the Hirozen loader (a Zen update replaces the install folder). Reinstall now?`,
  );
  if (!confirmed) return;
  install(zenDir);
  const wanted = normalizePath(zenDir);
  const running = (await listZenProcesses()).some(process => normalizePath(dirname(process.executablePath)) === wanted);
  const attach = running ? ", or run /hirozen-attach while it is still running" : "";
  ctx.ui.notify(`Hirozen: loader reinstalled into ${zenDir}. Restart Zen to load it${attach}.`, "info");
}

/**
 * The doc §6.3 "verify on every omp start" check. Read-only, so it is not a factory side effect, and
 * the caller never awaits a dialog in it: the reinstall offer runs on its own.
 */
async function checkOnStart(ctx: ExtensionContext): Promise<void> {
  const resolved = await resolveConfig(ctx.cwd);
  if (!resolved.ok) {
    // "warning", not "info": omp renders info as a 2.4 s toast that is gone before the startup screen settles.
    ctx.ui.notify(configNotice(resolved.problem), "warning");
    return;
  }
  const zenDir = resolved.config.zenDir;
  const outcome = verifyQuietly(zenDir);
  if ("problem" in outcome) {
    ctx.ui.notify(`Hirozen: ${outcome.problem}`, "warning");
    return;
  }
  const checked = outcome.checked;
  if (checked.ok) return;
  if (checked.installed === null && checked.mismatch === null) {
    if (!existsSync(join(zenDir, "zen.exe"))) {
      ctx.ui.notify(`Hirozen: the saved Zen install is gone (${zenDir}); run /hirozen-setup.`, "warning");
      return;
    }
    void offerReinstall(ctx, zenDir).catch(error => ctx.ui.notify(`Hirozen: ${messageOf(error)}`, "error"));
    return;
  }
  const fix = checked.reason.includes("/hirozen-install") ? "" : " — run /hirozen-install, restart Zen.";
  ctx.ui.notify(`Hirozen: ${checked.reason}${fix}`, "warning");
}

export default function hirozen(pi: ExtensionAPI): void {
  const parameters = toolParameters(pi.zod);

  pi.on("session_start", (_event, ctx) => {
    // Root session only. Nothing here is awaited, so a dialog can never hold up omp's startup.
    if (!(ctx.hasUI && ctx.agent?.kind === "main")) return;
    void checkOnStart(ctx).catch(error => ctx.ui.notify(`Hirozen: ${messageOf(error)}`, "error"));
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
      'Read the visible text of one Zen tab by its tabKey from zen_tabs, or the reader-mode article with mode:"article" (read-only; the tab is never loaded, activated or navigated). Loaded tabs in any space can be read.',
    parameters: parameters.read,
    approval: "read",
    loadMode: "essential",
    execute: (_toolCallId, params, signal, _onUpdate, ctx) => runBrowserRead(pi, ctx, params, signal),
  });

  pi.registerTool({
    name: "browser_screenshot",
    label: "Screenshot tab",
    description:
      "Capture a PNG screenshot of one Zen tab's viewport by its tabKey from zen_tabs (read-only; loaded tabs in any space can be screenshotted).",
    parameters: parameters.tabKey,
    approval: "read",
    loadMode: "essential",
    execute: (_toolCallId, params, signal, _onUpdate, ctx) => runBrowserScreenshot(pi, ctx, params.tabKey, signal),
  });

  pi.registerTool({
    name: "browser_snapshot",
    label: "Snapshot tab",
    description:
      "List the interactive elements of one Zen tab by its tabKey (links, buttons, inputs, selects, labelled controls) with a ref for each; browser_act and browser_upload take those refs (read-only; the tab is never loaded or activated, and loaded tabs in any space can be snapshotted).",
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
          'Act on one Zen tab by its tabKey: click, type, press, scroll, hover or navigate (navigate needs an http(s) url). Refs come from browser_snapshot. The loader\'s in-Zen Allow/Deny gate must have granted the act permission; every call needs your approval, unless a /hirozen-grant you gave covers that tab or site (navigate is never covered). Refused on privileged pages, in private windows and on tabs in a non-active space that is not the Hirozen Agent space (reads, snapshots and screenshots are allowed there; acts, uploads and dialogs are not).',
        parameters: parameters.act,
        approval: actApproval,
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
          "Set files on an <input type=file> in one Zen tab (ref from browser_snapshot). The loader's in-Zen Allow/Deny gate must have granted the act permission; every call needs your approval. Paths must exist locally (relative paths resolve against this omp session's cwd).",
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
        name: "zen_load_tab",
        label: "Load tab",
        description:
          'Load an unloaded ("lazy") Zen tab by its tabKey from zen_tabs, without selecting it: the user\'s space and selected tab are left alone. Refuses pinned and essential tabs, private windows, privileged (about:/chrome:/resource:) pages and tabs that are already loaded.',
        parameters: parameters.tabKey,
        approval: execApproval("zen_load_tab loads an unloaded tab in Zen (its page starts loading in the background)."),
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: TabParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runZenLoadTab(pi, ctx, params.tabKey, signal),
      },
      loadTabApprovalDetails,
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

  pi.registerTool(
    withApprovalDetails(
      {
        name: "browser_cookies",
        label: "Read cookies",
        description:
          'Read the cookies Zen would send to one tab\'s top-level site (name, domain, path, expiry, flags) under the loader\'s network permission. Values come back as "<n chars>" unless reveal:true, which needs its own approval. Read-only: the tab is never loaded, activated or navigated.',
        parameters: parameters.cookies,
        approval: cookiesApproval,
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: CookiesParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runBrowserCookies(pi, ctx, params, signal),
      },
      cookiesApprovalDetails,
    ),
  );

  pi.registerTool(
    withApprovalDetails(
      {
        name: "browser_storage",
        label: "Read page storage",
        description:
          'Read one tab\'s page storage (localStorage, sessionStorage, or IndexedDB database names) under the loader\'s network permission. Values come back as "<n chars>" unless reveal:true, which needs its own approval. Read-only: nothing is written.',
        parameters: parameters.storage,
        approval: storageApproval,
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: StorageParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runBrowserStorage(pi, ctx, params, signal),
      },
      storageApprovalDetails,
    ),
  );

  pi.registerTool({
    name: "browser_downloads",
    label: "List downloads",
    description:
      "List Zen's most recent downloads, newest first (source URL, target path, state, bytes, start time), under the loader's network permission. Read-only: Hirozen cannot start, cancel or delete a download.",
    parameters: parameters.none,
    approval: "read",
    loadMode: "essential",
    execute: (_toolCallId, _params, signal, _onUpdate, ctx) => runBrowserDownloads(pi, ctx, signal),
  });

  pi.registerTool(
    withApprovalDetails(
      {
        name: "browser_network_start",
        label: "Record requests",
        description:
          'Start recording one Zen tab\'s requests (URLs, statuses, timings and headers) under the loader\'s network permission; cookie, set-cookie, authorization and proxy-authorization values are redacted. Read them with browser_network_read, stop with browser_network_stop. Read-only: nothing is modified, blocked or replayed.',
        parameters: parameters.tabKey,
        approval: execApproval(
          "browser_network_start records a tab's requests in Zen (URLs, statuses and headers, with the sensitive values redacted).",
        ),
        loadMode: "essential",
        execute: (
          _toolCallId: string,
          params: TabParams,
          signal: AbortSignal | undefined,
          _onUpdate: unknown,
          ctx: ExtensionContext,
        ) => runBrowserNetworkStart(pi, ctx, params.tabKey, signal),
      },
      networkStartApprovalDetails,
    ),
  );

  pi.registerTool({
    name: "browser_network_read",
    label: "Read recorded requests",
    description:
      "Read what browser_network_start recorded for one Zen tab (oldest first, newest 200 within 64 KB) and clear the buffer. Reading a tab that is not being recorded is not an error: it answers with no requests.",
    parameters: parameters.tabKey,
    approval: "read",
    loadMode: "essential",
    execute: (_toolCallId, params, signal, _onUpdate, ctx) => runBrowserNetworkRead(pi, ctx, params.tabKey, signal),
  });

  pi.registerTool({
    name: "browser_network_stop",
    label: "Stop recording requests",
    description: "Stop recording one Zen tab's requests and drop what was buffered.",
    parameters: parameters.tabKey,
    approval: "read",
    loadMode: "essential",
    execute: (_toolCallId, params, signal, _onUpdate, ctx) => runBrowserNetworkStop(pi, ctx, params.tabKey, signal),
  });

  pi.registerCommand("hirozen-grant", {
    description: `Let browser_act click/type/press/scroll/hover in one tab or site for ${GRANT_MINUTES_MIN}-${GRANT_MINUTES_MAX} minutes without an approval prompt (\`clear\` removes every grant)`,
    handler: (args, ctx) => runGrantCommand(ctx, args),
  });

  pi.registerCommand("hirozen-setup", {
    description: "Choose the Zen install and profile Hirozen uses (saved in omp's plugin settings; `clear` forgets them)",
    handler: (args, ctx) => runSetupCommand(ctx, args),
  });

  pi.registerCommand("hirozen-install", {
    description: "Install the Hirozen loader into the configured Zen install directory (see /hirozen-setup)",
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
    description: "Report the configured Zen and profile, the loader install, the loader status file and the DevTools prefs",
    handler: (_args, ctx) => runStatusCommand(ctx),
  });
}
