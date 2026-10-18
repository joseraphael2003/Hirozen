// Hirozen loader: dormant chrome-scope module inside Zen's parent process.
//
// It never listens on a port. It polls the profile for a one-shot omp handoff file, connects OUT to
// omp, proves a shared nonce with HMAC, and from then on serves one omp session: inventory/spaces come
// from chrome scope, reads, snapshots, screenshots, page input and file uploads run through the Hirozen
// JSWindowActor this module registers, page dialogs are answered through the tab's own dialog box, and
// Zen layout runs through the window's gZen* - see .sisyphus/plans/hirozen-v2.md (Rev 2: WebDriver
// BiDi is gone entirely - this module never starts a remote-control agent or opens a DevTools port,
// and a read, a snapshot or a screenshot never shows a prompt: consent is the in-Zen notice below).
//
// V3 (plan hirozen-v3.md): reads, snapshots and screenshots reach a loaded tab in any space without
// switching it (only writes keep E_TAB_INACTIVE_SPACE), `browser.read` can answer the reader view's
// parse of the page (`mode: "article"`, still no navigation), `browser.act` can hover, and
// `zen.loadTab` gives one unloaded tab its docshell through Zen's own restore path without selecting
// it or moving the user's space. Consent stays the permission set below.
//
// Consent gate (§8.2): no method shows a Firefox prompt any more, so this loader owns an in-Zen
// Allow/Deny notice per link (state `#consent`, default Deny, persistent while connected) before any
// gated method runs, and omp keeps its per-action approval on top. V3: consent is a *set* of
// independent permissions {read, act, network} rather than one ladder - `act` still implies `read`,
// `network` is independent - and a call joins a pending notice by adding its own permission to the
// asked set, so one Allow settles every waiter.
//
// V3 capabilities: the Zen internals Hirozen calls are probed (most recent window) at init and at
// ready into `capabilities` (status file + ready frame), and every call site guards per call with
// #need() so a Zen that lacks one gets E_UNSUPPORTED naming it instead of a TypeError.
//
// Wire & status contract (.sisyphus/plans/hirozen-v1.md, hirozen-v1.1.md, hirozen-v2.md, shared with
// the omp side in src/link.ts):
//   request {id, method, params, deadline?}; success {id, result}; error {id, error: {code, message}};
//   loader events {type: "event", name, data}. Status file: hirozen-status.json. `deadline` is omp's
//   absolute epoch-ms budget for the request: the loader refuses with E_DEADLINE before it acts once
//   that moment has passed (a missing/non-finite deadline means no check).
//   loader->omp heartbeat {type: "ping", t}; omp->loader {type: "pong", t}, dropped before #handle.
//   Close codes: 1000 done, 4002 pre-auth message, 4003 auth failed, 4010 stopped by user,
//   4012 heartbeat timeout (not sticky).
//
// Every Gecko/Zen API used here was checked against the shipped Zen 1.22.3b (Gecko 156.0.1) sources:
//  - File.createFromFileName (ChromeOnly; chrome code uses it, modules/profiles/
//    SelectableProfile.sys.mjs): the parent builds the File objects an upload sets, and they cross
//    sendQuery to the actor by structured clone.
//  - moz-src/browser/components/tabbrowser/Tabbrowser.sys.mjs getTabDialogBox(browser) L1507-1517:
//    creates `browser.tabDialogBox` on demand, so its presence is exactly "a prompt was opened for
//    this browser". chrome/browser/content/browser/browser.js L4447-4730 (TabDialogBox) and
//    modules/SubDialog.sys.mjs L933-1104 (SubDialogManager) hold the live prompts: a SubDialog's
//    frameContentWindow is the commonDialog's window, where commonDialog.js (DOMContentLoaded)
//    assigns `Dialog = new CommonDialog(args, ui)` - `ui.button0` = accept, `ui.button1` = cancel,
//    `ui.loginTextbox` = the text box, `ui.infoBody` = the message. shared/Prompt.sys.mjs
//    L34-196 finds and drives the same fields.
//  - chrome/toolkit/content/global/elements/notificationbox.js appendNotification(type, notification,
//    buttons, disableClickJackingDelay=false, dismissable=true): the 5th argument reaches
//    moz-message-bar.mjs, which renders its dismiss button only when dismissable is true (L196).
//  - chrome/browser/content/browser/browser-init.js L739 notifies "browser-delayed-startup-finished"
//    once per top-level window (DevToolsStartup.sys.mjs L372-375 relies on the same topic), which is
//    how a notice reaches a window opened after it was shown.
//  - modules/Timer.sys.mjs exports both setTimeout and setInterval (used by the heartbeat).
//  - modules/zen/ZenSpaceManager.mjs: allStoredTabs / getWorkspaces / activeWorkspace; a tab's
//    zen-workspace-id is absent on pinned/essential tabs; modules/zen/ZenWindowSync.sys.mjs sets
//    tab.id on every tab, private windows included.
import { setTimeout, clearTimeout, setInterval, clearInterval } from "resource://gre/modules/Timer.sys.mjs";

const lazy = {};
ChromeUtils.defineESModuleGetters(lazy, {
  PrivateBrowsingUtils: "resource://gre/modules/PrivateBrowsingUtils.sys.mjs",
  // Probed by the capability report; the reader view (child) and the downloads tool import the same
  // modules (browser.js L80 defines ReaderMode on this URI, webdriver-bidi's browsingContext.sys.mjs
  // L17 defines Downloads on this one).
  ReaderMode: "moz-src:///toolkit/components/reader/ReaderMode.sys.mjs",
  Downloads: "resource://gre/modules/Downloads.sys.mjs",
});

const LOADER_VERSION = "1";
const STATUS_VERSION = 1;
const HANDOFF_FILE = "hirozen-handoff.json";
const STATUS_FILE = "hirozen-status.json";
const POLL_MS = 2_000;
const AUTH_TIMEOUT_MS = 10_000;
const HEARTBEAT_PING_MS = 5_000;
const HEARTBEAT_REAP_MS = 1_000;
const HEARTBEAT_TIMEOUT_MS = 15_000;
const ACTOR_NAME = "Hirozen";
const ACTOR_TIMEOUT_MS = 10_000;
const GATE_TIMEOUT_MS = 120_000;
const NAVIGATE_TIMEOUT_MS = 12_000;
const NAVIGATE_POLL_MS = 100;
const AGENT_SPACE_NAME = "Hirozen Agent";
const AGENT_SPACE_TIMEOUT_MS = 5_000;
const AGENT_SPACE_POLL_MS = 100;
const GLANCE_TIMEOUT_MS = 10_000;
const TAB_OPEN_GRACE_MS = 1_000; // popups from an agent-space tab are re-homed for 1 s after the act
const TAB_KEY_TIMEOUT_MS = 2_000; // a freshly opened tab's Zen sync id may land after addTab returns
const TAB_KEY_POLL_MS = 50;
const XHTML_NS = "http://www.w3.org/1999/xhtml";
// The Zen internals Hirozen needs, by the name the report and every per-call guard use. The four
// objects are probed for presence; every other name must be callable.
const CAPABILITY_OBJECTS = new Set(["gZenWorkspaces", "ReaderMode", "Downloads", "Services.cookies"]);
const CAPABILITY_NAMES = [
  "gZenWorkspaces",
  "gZenWorkspaces.getWorkspaces",
  "gZenWorkspaces.moveTabToWorkspace",
  "gZenWorkspaces.changeWorkspace",
  "gZenWorkspaces.createAndSaveWorkspace",
  "gZenWorkspaces.getWorkspaceFromId",
  "gZenViewSplitter.splitTabs",
  "gZenViewSplitter.removeTabFromGroup",
  "gZenGlanceManager.openGlance",
  "gZenGlanceManager.closeGlance",
  "gBrowser.insertBrowser",
  "ReaderMode",
  "Downloads",
  "Services.cookies",
];

// The gate's permissions, weakest first. `act` implies `read` (a page you may act on is a page you
// may read); `network` is independent of both, so an Allow for pages never covers a network call.
const PERMISSIONS = ["read", "act", "network"];
// What a notice says each permission lets Hirozen do.
const PERMISSION_VERBS = {
  read: "read pages",
  act: "read and act on pages",
  network: "read network data: cookies, downloads, storage, request headers",
};
// The only privileged pages a navigate may leave: an empty tab has no content to protect, and the
// agent needs to reach the web from one (plan: navigate's exemption from E_PRIVILEGED_PAGE).
const ABOUT_NAVIGABLE = ["about:blank", "about:newtab", "about:home"];

// The network tools (T9-T11). One 64 KB budget per answer, and the two bounds the storage answer uses.
const NET_CAP_BYTES = 65_536;
const STORAGE_VALUE_CHARS = 200;

// Close codes (contract): 1000 done, 4002 pre-auth message, 4003 auth failed, 4010 stopped by user,
// 4012 heartbeat timeout.
const CLOSE_DONE = 1000;
const CLOSE_PROTO = 4002;
const CLOSE_AUTH = 4003;
const CLOSE_STOPPED = 4010;
const CLOSE_HEARTBEAT = 4012;

class LoaderError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "LoaderError";
    this.code = code;
  }
}

const encoder = new TextEncoder();
const toHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
const randomHex = n => toHex(crypto.getRandomValues(new Uint8Array(n)));

async function hmacHex(key, message) {
  const k = await crypto.subtle.importKey("raw", encoder.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(new Uint8Array(await crypto.subtle.sign("HMAC", k, encoder.encode(message))));
}

// Constant-time comparison of two hex strings of equal expected length.
function sameHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Opens an outgoing WebSocket from chrome scope (same pattern as PushServiceWebSocket). No Origin
// header is sent: omp's server never checks one.
function openWebSocket(url, handlers) {
  const uri = Services.io.newURI(url);
  const channel = Cc["@mozilla.org/network/protocol;1?name=ws"]
    .getService(Ci.nsIWebSocketProtocolHandler)
    .newWebSocketChannel();
  channel.initLoadInfo(
    null,
    Services.scriptSecurityManager.getSystemPrincipal(),
    null,
    Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
    Ci.nsIContentPolicy.TYPE_WEBSOCKET
  );
  channel.loadInfo.allowDeprecatedSystemRequests = true;
  const ws = channel.QueryInterface(Ci.nsIWebSocketChannel);
  let closed = false;
  const finish = (code, reason) => {
    if (closed) return;
    closed = true;
    handlers.onClose(code, reason);
  };
  ws.asyncOpen(uri, "", {}, 0, {
    onStart: () => handlers.onOpen(),
    onStop: (_ctx, status) => finish(1006, `stopped 0x${(status >>> 0).toString(16)}`),
    onMessageAvailable: (_ctx, msg) => handlers.onMessage(msg),
    onBinaryMessageAvailable: () => {},
    onAcknowledge: () => {},
    onServerClose: (_ctx, code, reason) => finish(code, reason),
    onError: () => finish(1006, "error"),
    QueryInterface: ChromeUtils.generateQI(["nsIWebSocketListener"]),
  }, null);
  return {
    send: obj => {
      // A peer that vanished mid-write must never break the loader: the close handler owns cleanup.
      try {
        if (!closed) ws.sendMsg(JSON.stringify(obj));
      } catch {
        // Reported through onError/onStop, which runs the close handler.
      }
    },
    close: (code = CLOSE_DONE, reason = "") => {
      if (closed) return;
      try {
        ws.close(code, reason);
      } catch {
        // The channel is already gone; the close handler still has to run.
      }
      finish(code, reason);
    },
    get closed() {
      return closed;
    },
  };
}

// Every navigator:browser window, private ones included: a private tab key must resolve to E_PRIVATE
// rather than E_TAB_UNKNOWN, even though private windows never show up in the inventory.
function allBrowserWindows() {
  return [...Services.wm.getEnumerator("navigator:browser")].filter(w => !w.closed);
}

function isPrivateWindow(w) {
  return lazy.PrivateBrowsingUtils.isWindowPrivate(w);
}

// A brand-new tab the agent may navigate away from: about:blank/newtab/home, nothing else. Anything
// under about: (about:config, about:addons, ...) stays E_PRIVILEGED_PAGE like everywhere else.
function isNavigableAbout(spec) {
  return ABOUT_NAVIGABLE.some(prefix => spec === prefix || spec.startsWith(`${prefix}#`) || spec.startsWith(`${prefix}?`));
}

// Upload paths travel from omp already resolved against the omp working directory (src/index.ts), so a
// relative or empty path is a contract violation, not something to guess about (Gecko would resolve it
// against Zen's own CWD). Windows drive/UNC paths and POSIX paths are the only accepted shapes.
function isAbsolutePath(path) {
  return typeof path === "string" && (/^[a-zA-Z]:[\\/]/.test(path) || path.startsWith("\\\\") || path.startsWith("/"));
}

function hexOrNull(value) {
  return typeof value === "string" ? value : null;
}

// The windows the inventory may describe: the same shape zen.spaces returns.
function browserWindows() {
  return allBrowserWindows().filter(w => !isPrivateWindow(w));
}

// Zen keeps one tab copy per window in its workspace containers (`gZenWorkspaces.allStoredTabs`,
// modules/zen/ZenSpaceManager.mjs); window sync moves the live docshell between those copies.
// Windows without workspace containers (private/unsynced) fall back to their own tab list.
function windowTabs(w) {
  const stored = w.gZenWorkspaces?.allStoredTabs;
  return Array.from(stored?.length ? stored : (w.gBrowser?.tabs ?? []));
}

// Same test the spike used for "lazy": a pending tab has not been given a docshell yet.
function tabIsLoaded(tab) {
  return !!tab.linkedPanel && !tab.hasAttribute("pending");
}

// Prefer the copy that owns the live docshell; between two loaded copies prefer the selected one.
function isBetterCopy(a, b) {
  if (a.loaded !== b.loaded) return a.loaded;
  return a.selected && !b.selected;
}

// All real tabs, deduped across synced windows by Zen's window-sync id (`tab.id`). Tabs that have no
// sync id yet are still listed, but they cannot be addressed (their key is null).
function collectTabs() {
  const byKey = new Map();
  const unkeyed = [];
  for (const w of allBrowserWindows()) {
    const isPrivate = isPrivateWindow(w);
    for (const tab of windowTabs(w)) {
      if (!tab.linkedBrowser || tab.closing || tab.hasAttribute("zen-empty-tab")) continue;
      const entry = {
        key: tab.id || null,
        tab,
        window: w,
        browser: tab.linkedBrowser,
        loaded: tabIsLoaded(tab),
        selected: !!tab.selected,
        private: isPrivate,
      };
      if (!entry.key) {
        unkeyed.push(entry);
        continue;
      }
      const previous = byKey.get(entry.key);
      if (!previous || isBetterCopy(entry, previous)) byKey.set(entry.key, entry);
    }
  }
  return [...byKey.values(), ...unkeyed];
}

function spaceSummary(activeSpace, space) {
  return {
    uuid: space.uuid,
    name: space.name,
    icon: space.icon ?? null,
    containerTabId: space.containerTabId ?? 0,
    active: space.uuid === activeSpace,
  };
}

// Zen's getWorkspaces() dereferences a workspace cache that does not exist in every window (its own
// getWorkspaceFromId wraps the same call in a try/catch): a window without it simply reports no spaces.
function spacesOf(w) {
  try {
    return w.gZenWorkspaces?.getWorkspaces() ?? [];
  } catch {
    return [];
  }
}

function windowSummary(w) {
  const activeSpace = w.gZenWorkspaces?.activeWorkspace ?? null;
  return { activeSpace, spaces: spacesOf(w).map(space => spaceSummary(activeSpace, space)) };
}

function tabSummary(entry) {
  return {
    tabKey: entry.key,
    title: entry.tab.label,
    url: entry.browser.currentURI.spec,
    space: entry.tab.getAttribute("zen-workspace-id"),
    pinned: !!entry.tab.pinned,
    essential: entry.tab.getAttribute("zen-essential") === "true",
    lazy: !entry.loaded,
    selected: entry.selected,
  };
}

// Documents the loader refuses to read: privileged schemes, and synthetic documents (the PDF viewer,
// images, video, view-source). `isSyntheticDocument` and the pdf.js viewer principal check are
// Gecko's own tests (chrome/browser/content/browser/tabbrowser/browser-fullZoom.js).
function isPrivilegedPage(browser) {
  const spec = browser.currentURI.spec;
  return (
    isPrivilegedSpec(spec) ||
    browser.documentContentType === "application/pdf" ||
    browser.isSyntheticDocument ||
    browser.contentPrincipal?.spec === "resource://pdf.js/web/viewer.html"
  );
}

// The three schemes Hirozen never loads or navigates to, tested on a URL string: a pending tab has no
// document yet, so its stored URL is all there is to judge (zen.loadTab).
function isPrivilegedSpec(spec) {
  return (
    typeof spec === "string" &&
    (spec.startsWith("about:") || spec.startsWith("chrome:") || spec.startsWith("resource:"))
  );
}

// The URL a pending tab will load: SessionStore's lazy-tab state, which is what Zen's own restore
// reads (SessionStore.sys.mjs getLazyTabValue -> the tab's stored url), with the browser that is not
// bound to a docshell yet as the fallback (about:blank for a tab SessionStore never saw - which
// isPrivilegedSpec then refuses, because a load with no known target is not one Hirozen starts).
function lazyTabURL(win, tab) {
  let stored = null;
  try {
    stored = win.SessionStore?.getLazyTabValue?.(tab, "url") ?? null;
  } catch {
    // A SessionStore that is not there, or a tab it does not know: the browser's URL answers.
    stored = null;
  }
  if (typeof stored === "string" && stored) return stored;
  try {
    return tab.linkedBrowser?.currentURI?.spec ?? "";
  } catch {
    return "";
  }
}

// The value a capability name points at: ReaderMode/Downloads live on `lazy`, Services.* on Services,
// every other name walks the window. A missing link is undefined, never a throw.
function capabilityValue(name, win) {
  if (name === "ReaderMode" || name === "Downloads") return lazy[name];
  const parts = name.split(".");
  if (parts[0] === "Services") return Services[parts[1]];
  let value = win;
  for (const part of parts) value = value == null ? undefined : value[part];
  return value;
}

// One probed name. A lazy getter whose module cannot be imported (a Zen update moved it) is exactly
// "this Zen does not have it", so the probe answers false rather than throwing at init.
function capabilityPresent(name, win) {
  try {
    const value = capabilityValue(name, win);
    return CAPABILITY_OBJECTS.has(name) ? value !== null && typeof value === "object" : typeof value === "function";
  } catch {
    return false;
  }
}

// The notice's wording for a set of permissions: "read pages", "read and act on pages", "read network
// data: cookies, downloads, storage, request headers". `act` covers `read`, so the two are never named
// together.
function permissionVerbs(permissions) {
  return PERMISSIONS.filter(need => permissions.has(need) && !(need === "read" && permissions.has("act")))
    .map(need => PERMISSION_VERBS[need])
    .join(" and ");
}

class Loader {
  #started = false;
  #loaderSha256 = null;
  #childSha256 = null;
  #parentSha256 = null;
  #actorError = null; // {code, message, at}: the actor did not register, so no gated method may run
  #client = null; // authenticated omp connection
  #handshakeInFlight = false; // an outgoing connection attempt is in progress
  #notices = new Map(); // live notice element -> the notification box of the window showing it
  #noticeGen = 0; // bumped on every close, so an append still in flight cannot revive itself
  #status = {
    version: STATUS_VERSION,
    loaderSha256: null,
    childSha256: null,
    parentSha256: null,
    zenPid: null,
    state: "dormant",
    mode: null,
    // What the running Zen exposes; filled by #probeCapabilities() at init and again at ready.
    capabilities: {},
    updated: null,
    lastHandoff: null,
    // The granted permissions (e.g. ["read","act"]) and what a pending notice is asking for.
    consent: [],
    consentPending: null,
    actorError: null,
    lastClose: null,
  };
  #pingTimer = null; // heartbeat ping interval, live only while #client is set
  #reapTimer = null; // heartbeat reap interval
  #lastInbound = 0; // last frame (JSON) heard from omp; pongs included
  #noticeState = null; // {generation, text, warning, buttons} of the notice currently shown
  #noticeBase = null; // {text, warning, buttons}: the notice every window gets, Stop included
  #noticeObserver = null; // browser-delayed-startup-finished observer while a notice is up
  #consent = { granted: new Set(), pending: null }; // per link; created on auth, cleared in #teardown
  #tabOpenWatchers = new Map(); // window -> {states: [state], handler}: agent-space popup re-homing

  init(mode, hashes) {
    if (this.#started) return "already-started";
    if (mode !== "startup" && mode !== "attach") {
      throw new Error(`HirozenLoader.init: unknown mode ${mode}`);
    }
    this.#started = true;
    this.#loaderSha256 = hexOrNull(hashes?.loader);
    this.#childSha256 = hexOrNull(hashes?.child);
    this.#parentSha256 = hexOrNull(hashes?.parent);
    // Registration first: a failure is a status fact, and every gated method refuses with E_ACTOR
    // until it is fixed (plan: actor registration failure is the only install-time failure code).
    this.#registerActor();
    this.#writeStatus({
      state: "dormant",
      mode,
      zenPid: Services.appinfo.processID,
      loaderSha256: this.#loaderSha256,
      childSha256: this.#childSha256,
      parentSha256: this.#parentSha256,
      capabilities: this.#probeCapabilities(),
      actorError: this.#actorError,
      consent: [],
      consentPending: null,
      lastClose: null,
    });
    this.#schedulePoll();
    return "started";
  }

  // Probed at init and again at ready, on the most recent window: a session can start before any
  // window exists, and the report is a fact about the Zen that is running now.
  #probeCapabilities() {
    const win = Services.wm.getMostRecentWindow("navigator:browser") ?? null;
    const capabilities = {};
    for (const name of CAPABILITY_NAMES) capabilities[name] = capabilityPresent(name, win);
    return capabilities;
  }

  // Every call into a probed Zen internal that would otherwise be a TypeError from calling undefined
  // goes through this. The ready-time report was taken on one window, and windows open later (or a Zen
  // update renames a method), so the check is per call. A missing internal is E_UNSUPPORTED naming it.
  // Sites that already tolerate absence by design (the optional-chained space lookups, whose failure
  // path is a documented refusal or a best-effort restore) keep their `?.` instead.
  #need(win, name) {
    if (capabilityPresent(name, win)) return;
    throw new LoaderError("E_UNSUPPORTED", `this Zen lacks ${name}; Hirozen needs an update`);
  }

  // The Hirozen actor is registered here, at init and before the first poll: attach re-init means a
  // previous registration may exist, and registerWindowActor would throw on a duplicate name.
  // `remoteTypes: ["web", "file"]` matters: the parent actor map matches by prefix, so "web" covers
  // every webIsolated content process (temp/spikes/v2 S1). A failure never throws: it is recorded as
  // actorError, and every gated method refuses with E_ACTOR.
  #registerActor() {
    try {
      ChromeUtils.unregisterWindowActor(ACTOR_NAME);
    } catch {
      // Not registered (a fresh startup): nothing to undo.
    }
    try {
      ChromeUtils.registerWindowActor(ACTOR_NAME, {
        parent: { esModuleURI: "resource://hirozen/HirozenParent.sys.mjs" },
        child: { esModuleURI: "resource://hirozen/HirozenChild.sys.mjs" },
        allFrames: false,
        includeChrome: false,
        safeForUntrustedWebProcess: true,
        remoteTypes: ["web", "file"],
      });
      this.#actorError = null;
    } catch (e) {
      this.#actorError = { code: "E_ACTOR", message: String(e?.message ?? e), at: new Date().toISOString() };
    }
  }

  #writeStatus(patch) {
    Object.assign(this.#status, patch, { updated: new Date().toISOString() });
    const path = PathUtils.join(PathUtils.profileDir, STATUS_FILE);
    // Best effort: the status file is a diagnostic channel that omp polls; a failed write must never
    // break the loader.
    IOUtils.writeJSON(path, this.#status).catch(() => {});
  }

  #schedulePoll() {
    setTimeout(() => this.#poll().finally(() => this.#schedulePoll()), POLL_MS);
  }

  async #poll() {
    // One owner at a time: no new handoff while a link is up or while our own handshake is still in
    // flight (a second connection would fight the first one for the single session).
    if (this.#client || this.#handshakeInFlight) return;
    const path = PathUtils.join(PathUtils.profileDir, HANDOFF_FILE);
    let handoff;
    try {
      handoff = await IOUtils.readJSON(path);
    } catch {
      return; // no handoff pending
    }
    await IOUtils.remove(path).catch(() => {}); // single use
    const valid =
      Number.isInteger(handoff?.port) && handoff.port > 1024 && handoff.port < 65536 &&
      typeof handoff.nonce === "string" && /^[0-9a-f]{64}$/.test(handoff.nonce) &&
      typeof handoff.expiry === "number" && handoff.expiry > Date.now();
    if (!valid) {
      this.#writeStatus({ state: "dormant", lastClose: "handoff rejected: invalid or expired" });
      return;
    }
    this.#connect(handoff);
  }

  // Removal goes through the box with the slide-out animation skipped. Notification.close() only
  // starts that animation and the element is detached on the stack's `transitionend`, which a
  // background (occluded) window never runs - the notice, Stop button included, stays on screen.
  #removeNotice(box, notification) {
    try {
      box.removeNotification(notification, true);
    } catch {
      // Zen may have removed the notification already, or the window (and its box) went away; UI
      // cleanup must never break the connection teardown.
    }
  }

  #closeNotice() {
    this.#noticeGen++;
    if (this.#noticeObserver) {
      try {
        Services.obs.removeObserver(this.#noticeObserver, "browser-delayed-startup-finished");
      } catch {
        // The observer is already gone (shutdown); UI cleanup must never break the connection teardown.
      }
      this.#noticeObserver = null;
    }
    this.#noticeState = null;
    for (const [notification, box] of this.#notices) this.#removeNotice(box, notification);
    this.#notices.clear();
  }

  // Takes the notice off screen for good (link teardown): unlike #closeNotice, the base is dropped too,
  // so a later #showNotice from a dead link cannot bring its notice back.
  #hideNotice() {
    this.#noticeBase = null;
    this.#closeNotice();
  }

  // Shown in every open non-private window, each with its own Stop button: the user may be looking at
  // any of them, and Stop has to be reachable from wherever the prompt is. A window opened while the
  // notice is up gets it too: "browser-delayed-startup-finished" is notified once per top-level
  // browser window (browser-init.js L739, the topic DevToolsStartup.sys.mjs L372-375 listens on).
  // Private windows are excluded, exactly like everywhere else.
  #showNotice(text, { warning = false, stopButton = true, buttons = null } = {}) {
    this.#noticeBase = {
      text,
      warning,
      buttons: buttons ?? (stopButton
        ? [{ label: "Stop", callback: () => { this.#disconnect("stopped by user in Zen", CLOSE_STOPPED); return false; } }]
        : []),
    };
    this.#renderNotice();
  }

  #renderNotice() {
    this.#closeNotice();
    if (!this.#noticeBase) return;
    const state = {
      generation: this.#noticeGen,
      text: this.#noticeBase.text,
      warning: this.#noticeBase.warning,
      buttons: this.#noticeBase.buttons,
    };
    this.#noticeState = state;
    this.#noticeObserver = subject => {
      if (this.#noticeState !== state || !subject || subject.closed) return;
      if (!subject.gNotificationBox || isPrivateWindow(subject)) return;
      this.#appendNotice(subject, state);
    };
    Services.obs.addObserver(this.#noticeObserver, "browser-delayed-startup-finished");
    for (const win of browserWindows()) this.#appendNotice(win, state);
  }

  // dismissable=false: the notice must have no ✕. The 5th appendNotification argument lands on the
  // notification-message element (notificationbox.js L145-151, L178) and moz-message-bar.mjs renders
  // its dismiss button only when dismissable is true (L196): with a ✕ the user could drop the notice -
  // and with it the only Stop button - while the session is still connected.
  #appendNotice(win, state) {
    const box = win.gNotificationBox;
    if (!box) return;
    box.appendNotification(
      "hirozen",
      { label: state.text, priority: state.warning ? box.PRIORITY_WARNING_HIGH : box.PRIORITY_INFO_HIGH },
      state.buttons,
      false,
      false
    ).then(
      notification => {
        if (state.generation === this.#noticeGen && this.#noticeState === state) this.#notices.set(notification, box);
        else this.#removeNotice(box, notification); // a newer notice (or teardown) replaced it meanwhile
      },
      () => {} // the window went away before the notification was appended
    );
  }

  // The omp identity from the handoff that started this link, as every notice names it.
  #who() {
    const handoff = this.#status.lastHandoff;
    return `omp pid ${handoff?.pid ?? "?"} (${handoff?.cwd ?? "unknown folder"})`;
  }

  #connect({ port, nonce, pid, cwd }) {
    this.#handshakeInFlight = true;
    this.#writeStatus({ state: "authenticating", lastHandoff: { pid: pid ?? null, cwd: cwd ?? null, at: new Date().toISOString() } });
    // Shown as soon as the link authenticates, before any Allow/Deny notice, so the user can
    // correlate the prompt with a terminal process.
    this.#showNotice(`Hirozen: ${this.#who()} is connecting to Zen.`);
    const myChallenge = randomHex(32);
    let authed = false;
    const authTimer = setTimeout(() => {
      if (!authed) ws.close(CLOSE_AUTH, "auth timeout");
    }, AUTH_TIMEOUT_MS);
    const ws = openWebSocket(`ws://127.0.0.1:${port}/hirozen`, {
      onOpen: () => {},
      onMessage: async raw => {
        let msg;
        try {
          msg = JSON.parse(raw);
        } catch {
          ws.close(CLOSE_PROTO, "bad json");
          return;
        }
        if (!authed) {
          if (msg.type === "challenge" && typeof msg.challenge === "string") {
            ws.send({ type: "auth", mac: await hmacHex(nonce, `loader:${msg.challenge}`), challenge: myChallenge });
          } else if (msg.type === "auth") {
            if (!sameHex(msg.mac, await hmacHex(nonce, `omp:${myChallenge}`))) {
              this.#writeStatus({ state: "dormant", lastClose: `${CLOSE_AUTH} auth failed: omp proof mismatch` });
              ws.close(CLOSE_AUTH, "auth failed");
              return;
            }
            authed = true;
            clearTimeout(authTimer);
            this.#handshakeInFlight = false;
            this.#client = ws;
            // The consent state belongs to this link and is never inherited: the previous link's grant
            // dies with it, so the user's Allow is asked for again (plan §8.2).
            this.#consent = { granted: new Set(), pending: null };
            this.#startHeartbeat();
            this.#showNotice(`Hirozen: ${this.#who()} is connected. Stop ends the session.`);
            this.#writeStatus({ state: "connected", consent: [], consentPending: null, lastClose: null });
            ws.send({
              type: "ready",
              loaderVersion: LOADER_VERSION,
              loaderSha256: this.#loaderSha256,
              childSha256: this.#childSha256,
              parentSha256: this.#parentSha256,
              zenVersion: Services.appinfo.version,
              platformVersion: Services.appinfo.platformVersion,
              zenDir: Services.dirsvc.get("GreD", Ci.nsIFile).path,
              capabilities: this.#probeCapabilities(),
              zenPid: Services.appinfo.processID,
            });
          } else {
            ws.close(CLOSE_PROTO, "unexpected message before auth");
          }
          return;
        }
        // The heartbeat is answered by the peer, so any frame proves the link is alive; a pong is a
        // heartbeat reply, not a request: it must never reach #handle (which would answer
        // E_UNKNOWN_METHOD for a frame that has no method).
        this.#lastInbound = Date.now();
        if (msg.type === "pong") return;
        this.#handle(msg).then(
          result => ws.send({ id: msg.id, result }),
          e => ws.send({
            id: msg.id,
            // Every failure path throws a LoaderError; anything else is a loader bug, reported as
            // E_INTERNAL with its real message.
            error: { code: e instanceof LoaderError ? e.code : "E_INTERNAL", message: `${e instanceof LoaderError ? "" : "internal error: "}${e?.message ?? e}` },
          })
        );
      },
      onClose: (code, reason) => {
        clearTimeout(authTimer);
        this.#stopHeartbeat();
        this.#handshakeInFlight = false;
        if (this.#client === ws) {
          this.#teardown(`${code} ${reason}`);
        } else if (!authed) {
          this.#closeNotice();
          this.#writeStatus({ state: "dormant", lastClose: `${code} ${reason}` });
        }
      },
    });
  }

  // Closes the omp link and runs the teardown, then closes the socket (which re-enters onClose, where
  // the teardown has already run and the link is already cleared).
  #disconnect(reason, code) {
    this.#stopHeartbeat();
    const ws = this.#client;
    this.#teardown(reason);
    ws?.close(code, reason);
  }

  // Heartbeat (V1.1): a ping every 5 s, plus a separate 1 s check that reaps a peer which has sent
  // nothing for 15 s. Enforced from authentication on - no first-pong gate - so a frozen omp (its
  // event loop blocked, the socket still open) is noticed and the session does not stay locked.
  #startHeartbeat() {
    this.#lastInbound = Date.now();
    this.#stopHeartbeat();
    this.#pingTimer = setInterval(() => {
      this.#client?.send({ type: "ping", t: Date.now() });
    }, HEARTBEAT_PING_MS);
    this.#reapTimer = setInterval(() => {
      if (!this.#client) return;
      if (Date.now() - this.#lastInbound > HEARTBEAT_TIMEOUT_MS) {
        this.#disconnect("heartbeat timeout", CLOSE_HEARTBEAT);
      }
    }, HEARTBEAT_REAP_MS);
  }

  #stopHeartbeat() {
    if (this.#pingTimer !== null) {
      clearInterval(this.#pingTimer);
      this.#pingTimer = null;
    }
    if (this.#reapTimer !== null) {
      clearInterval(this.#reapTimer);
      this.#reapTimer = null;
    }
  }

  // Runs whenever the omp connection ends, however it ends: the link's state must not outlive it.
  // Synchronous on purpose - nothing here waits on anything - so a new handoff cannot be served in the
  // middle of a teardown (#poll runs between tasks, and this method never yields).
  #teardown(reason) {
    this.#client = null;
    // The link is gone: a pending gate has nobody to answer to, its waiters must not hang, and the
    // grant itself dies here (resetScope: a new link asks again, and nothing between this teardown and
    // the next auth may inherit the old permissions).
    this.#clearConsent({
      rejectPending: new LoaderError("E_STOPPED", "the omp link closed while the Allow/Deny notice was up"),
      resetScope: true,
    });
    this.#clearTabOpenWatchers();
    this.#writeStatus({ state: "stopping", consent: [], consentPending: null, lastClose: reason });
    this.#hideNotice();
    this.#writeStatus({ state: "dormant", consent: [], consentPending: null });
  }

  // Clears the gate: a pending Allow/Deny notice is cancelled (its waiters get `rejectPending`), the
  // notice returns to the pre-prompt state (or is dropped entirely when the link is going away), and
  // the granted permissions are either cleared (link teardown) or left alone (prompt cancelled on its
  // own).
  #clearConsent({ rejectPending, resetScope = false } = {}) {
    const pending = this.#consent.pending;
    if (pending) {
      clearTimeout(pending.timer);
      this.#consent.pending = null;
      pending.reject(rejectPending ?? new LoaderError("E_DENIED", "the Allow/Deny notice was cancelled"));
    }
    if (resetScope) this.#consent.granted.clear();
  }

  async #handle(msg) {
    const params = msg.params ?? {};
    // Per-request budget: frames run concurrently, so the deadline travels with the call, not in a
    // field. Checkpoint 1 of the plan: the entry check, before any prompt.
    const req = { deadline: Number.isFinite(msg.deadline) ? msg.deadline : null };
    this.#checkDeadline(req);
    switch (msg.method) {
      case "zen.inventory":
        return this.#inventory();
      case "zen.spaces":
        return browserWindows().map(windowSummary);
      case "browser.read":
        return this.#read(params, req);
      case "browser.screenshot":
        return this.#screenshot(params, req);
      case "browser.snapshot":
        return this.#snapshot(params, req);
      case "browser.act":
        return this.#act(params, req);
      case "browser.upload":
        return this.#upload(params, req);
      case "browser.dialog":
        return this.#dialog(params, req);
      case "zen.open":
        return this.#zenOpen(params, req);
      case "zen.move":
        return this.#zenMove(params, req);
      case "zen.split":
        return this.#zenSplit(params, req);
      case "zen.unsplit":
        return this.#zenUnsplit(params, req);
      case "zen.glance":
        return this.#zenGlance(params, req);
      case "zen.loadTab":
        return this.#zenLoadTab(params, req);
      case "network.cookies":
        return this.#networkCookies(params, req);
      case "network.storage":
        return this.#networkStorage(params, req);
      default:
        throw new LoaderError("E_UNKNOWN_METHOD", `unknown method ${msg.method}`);
    }
  }

  // The plan's checkpoints (1), (2) and (4): a request whose absolute deadline passed must not act.
  // The caller checks it again after the gate (2) and immediately before each side effect (4); a
  // missing/non-finite deadline means no check at all (V1 callers send none).
  #checkDeadline(req) {
    if (!req || !Number.isFinite(req.deadline)) return;
    if (Date.now() >= req.deadline) {
      throw new LoaderError("E_DEADLINE", "omp's budget for this call passed before anything was done; nothing was changed and the call can be retried");
    }
  }

  // ---------------------------------------------------------------- consent gate (§8.2)

  // Independent permissions: a granted `act` covers `read` (a page you may act on is a page you may
  // read), and nothing else covers anything - a `network` call is never settled by an Allow for pages.
  #scopeCovers(needed) {
    const granted = this.#consent.granted;
    return granted.has(needed) || (needed === "read" && granted.has("act"));
  }

  // Body of the gate call: the actor must be registered (a broken install refuses loudly, and no
  // prompt is shown for a feature that cannot work), then the granted set decides whether the user has
  // to be asked. A call that joins a pending notice adds its own permission to the asked set and waits
  // on the same promise, so one Allow settles every waiter; the loop re-checks coverage after the
  // answer instead of returning, so a call can never ride an Allow that did not cover it.
  async #gate(need, req) {
    if (this.#actorError) {
      throw new LoaderError("E_ACTOR", `Hirozen's actor is not registered in Zen (${this.#actorError.message}); reinstall or fix the loader and restart Zen`);
    }
    for (;;) {
      if (this.#scopeCovers(need)) return;
      const pending = this.#consent.pending;
      if (pending) {
        if (!pending.asks.has(need)) {
          pending.asks.add(need);
          this.#writeStatus({ consentPending: [...pending.asks] });
          this.#emit("consent.pending", { asked: [...pending.asks] });
          this.#showConsentNotice();
        }
        await pending.promise;
        continue;
      }
      const { promise, resolve, reject } = Promise.withResolvers();
      const fresh = { asks: new Set([need]), promise, resolve, reject, timer: null };
      this.#consent.pending = fresh;
      // 120 s is the plan's bound: no answer is a Deny (not sticky - the next call asks again). The
      // timer is real (the loader has no clock of its own), and never restarted when a call joins.
      fresh.timer = setTimeout(() => this.#settleConsent(fresh, { granted: false, timedOut: true }), GATE_TIMEOUT_MS);
      this.#writeStatus({ consentPending: [...fresh.asks] });
      this.#emit("consent.pending", { asked: [...fresh.asks] });
      this.#showConsentNotice();
      await promise;
    }
  }

  // Allow: every asked permission is added to the granted set, the status is written before the event
  // (plan: the status file must never contradict the terminal hint), and the notice becomes the
  // persistent connected notice naming every granted permission. The event carries the whole granted
  // set, not only what this answer added.
  #settleConsent(pending, { granted, timedOut = false }) {
    if (this.#consent.pending !== pending) return;
    clearTimeout(pending.timer);
    this.#consent.pending = null;
    const asked = [...pending.asks];
    if (granted) {
      for (const need of pending.asks) this.#consent.granted.add(need);
      this.#writeStatus({ consent: [...this.#consent.granted], consentPending: null });
      this.#emit("consent.granted", { granted: [...this.#consent.granted] });
      this.#showConsentNotice();
      pending.resolve();
      return;
    }
    // Deny or timeout: the granted set is untouched, so the notice returns to the one shown before the
    // prompt, and the next call asks again.
    this.#writeStatus({ consent: [...this.#consent.granted], consentPending: null });
    this.#emit("consent.denied", { asked });
    this.#showConsentNotice();
    pending.reject(new LoaderError("E_DENIED", timedOut
      ? "the Allow/Deny notice in Zen was not answered within 120 s; the next call asks again"
      : "the Allow/Deny notice in Zen was denied; the next call asks again"));
  }

  // The gate notice: the prompt while an answer is owed (naming everything it asks for), the V1
  // connected notice plus every granted permission otherwise. Private windows stay excluded, as for
  // every notice.
  #showConsentNotice() {
    const pending = this.#consent.pending;
    if (pending) {
      this.#showNotice(`Hirozen: ${this.#who()} wants to ${permissionVerbs(pending.asks)} in Zen.`, {
        buttons: [
          { label: "Allow", callback: () => { this.#settleConsent(pending, { granted: true }); return false; } },
          { label: "Deny", callback: () => { this.#settleConsent(pending, { granted: false }); return false; } },
        ],
      });
      return;
    }
    const granted = this.#consent.granted;
    const suffix = granted.size > 0 ? ` - Hirozen can ${permissionVerbs(granted)}` : "";
    this.#showNotice(`Hirozen: ${this.#who()} is connected${suffix}. Stop ends the session.`);
  }

  #inventory() {
    const tabs = collectTabs();
    return browserWindows().map(w => {
      const summary = windowSummary(w);
      summary.tabs = tabs.filter(entry => entry.window === w && !entry.private).map(tabSummary);
      return summary;
    });
  }

  // Resolves a tabKey (= Zen's window-sync tab.id, set on every tab by ZenWindowSync.sys.mjs) into the
  // tab, its browser and the actor's WindowGlobalParent. Same five codes and order as V1's
  // #resolveTarget. What a method needs a tab *for* is no longer resolved here: uploads and dialogs act
  // through the actor and the tab's own dialog box, so neither needs a WebDriver context.
  //
  // `write` (V3): a loaded tab in an inactive space is readable - read, snapshot and screenshot reach it
  // without switching spaces - while everything that changes the page (act, navigate, upload, dialog)
  // keeps E_TAB_INACTIVE_SPACE, because that is the call that would need the space to be the one the
  // user is looking at. The agent-space exemption below covers both.
  #resolveTab(tabKey, { allowAbout = false, write = false } = {}) {
    if (typeof tabKey !== "string" || !tabKey) {
      throw new LoaderError("E_TAB_UNKNOWN", "a tabKey from zen.inventory is required");
    }
    const entry = collectTabs().find(candidate => candidate.key === tabKey);
    if (!entry) {
      throw new LoaderError("E_TAB_UNKNOWN", `no tab with key ${tabKey}; list tabs with zen.inventory`);
    }
    if (entry.private) {
      throw new LoaderError("E_PRIVATE", `tab ${tabKey} lives in a private window; Hirozen never touches private windows`);
    }
    // Checked before the loaded state: an unloaded tab in another space is unreachable for that
    // reason, not because it is lazy. Deviation 3 narrows the rule: every tab in the agent space stays
    // reachable while that space is inactive - reads, snapshot, input and screenshots (drawSnapshot
    // renders a tab of an inactive space correctly, verified live) - while every other inactive-space
    // tab keeps E_TAB_INACTIVE_SPACE for writes.
    if (write && !this.#isInActiveSpace(entry)) {
      const agentSpaceId = this.#agentSpaceIdOf(entry.window);
      const inAgentSpace = !!agentSpaceId && entry.tab.getAttribute("zen-workspace-id") === agentSpaceId;
      if (!inAgentSpace) {
        throw new LoaderError("E_TAB_INACTIVE_SPACE", `tab ${tabKey} is in an inactive space; Zen would have to switch spaces to reach it`);
      }
    }
    if (!entry.loaded) {
      throw new LoaderError("E_TAB_UNLOADED", `tab ${tabKey} has no docshell yet; open it in Zen first (Hirozen never loads tabs)`);
    }
    const spec = entry.browser.currentURI.spec;
    if (isPrivilegedPage(entry.browser) && !(allowAbout && isNavigableAbout(spec))) {
      throw new LoaderError("E_PRIVILEGED_PAGE", `tab ${tabKey} is a privileged page (${spec})`);
    }
    const wg = entry.browser.browsingContext?.currentWindowGlobal ?? null;
    if (!wg) {
      throw new LoaderError("E_TAB_UNLOADED", `tab ${tabKey} has no live document; open it in Zen first (Hirozen never loads tabs)`);
    }
    return { tabKey, tab: entry.tab, browser: entry.browser, wg };
  }

  // Pinned and essential tabs carry no zen-workspace-id and are visible from every space.
  #isInActiveSpace(entry) {
    const spaceId = entry.tab.getAttribute("zen-workspace-id");
    if (!spaceId) return true;
    return spaceId === entry.window.gZenWorkspaces?.activeWorkspace;
  }

  // ---------------------------------------------------------------- actor calls

  // One round trip to the Hirozen content actor. `getActor` throws (or answers null) for a window
  // global the registration does not cover - privileged pages included - which is exactly what
  // E_PRIVILEGED_PAGE means here. AbortError/actor-destroyed is a stale ref for `act` (the document
  // the ref came from is gone) and a read failure otherwise; a child `{error}` reply crosses as its
  // own LoaderError; the 10 s bound is the plan's.
  async #query(wg, name, data, { kind = "read" } = {}) {
    let actor = null;
    try {
      actor = wg.getActor(ACTOR_NAME);
    } catch {
      actor = null;
    }
    if (!actor) {
      throw new LoaderError("E_PRIVILEGED_PAGE", `Hirozen's actor is not available for this document (${name})`);
    }
    const query = Promise.resolve()
      .then(() => actor.sendQuery(name, data))
      .then(
        reply => {
          if (reply?.error) {
            throw new LoaderError(reply.error.code ?? "E_INTERNAL", reply.error.message ?? `actor ${name} failed`);
          }
          return reply;
        },
        e => { throw actorFailure(e, name, kind); }
      );
    return this.#withTimeout(query, ACTOR_TIMEOUT_MS, new LoaderError("E_TIMEOUT", `the page actor did not answer ${name} within ${ACTOR_TIMEOUT_MS} ms`));
  }

  // A bound that never leaves its timer behind: the race is settled by whichever side finishes first.
  #withTimeout(promise, ms, error) {
    const { promise: timeout, resolve } = Promise.withResolvers();
    const timer = setTimeout(() => resolve(error), ms);
    return Promise.race([promise, timeout]).then(
      value => { clearTimeout(timer); if (value instanceof LoaderError) throw value; return value; },
      e => { clearTimeout(timer); throw e; }
    );
  }

  // For `act` (and navigate): the page may open a dialog instead of doing anything visible - a click
  // on a confirm() trigger, an alert during a load. The loader watches that moment through the
  // `common-dialog-loaded` observer and answers {ok:true, dialog:{type, message}}, so omp learns why
  // the page stopped and can call browser_dialog (which then answers it in chrome scope).
  async #queryAct(wg, data, browser) {
    const query = this.#query(wg, "act", data, { kind: "act" });
    const dialog = this.#dialogRace(browser);
    try {
      const winner = await Promise.race([query.then(reply => ({ reply })), dialog.promise.then(info => ({ info }))]);
      if (winner.info) {
        // The actor's answer is no longer interesting: the dialog owns the tab now. A late rejection
        // is reported to nobody, because the race already settled this call.
        query.catch(() => {});
        return { ok: true, dialog: winner.info };
      }
      return winner.reply;
    } finally {
      dialog.cancel();
    }
  }

  // Watches `common-dialog-loaded` for a dialog owned by this tab's browsing context
  // (PromptListener matches the same `subject.args.owningBrowsingContext`) and resolves with
  // {type, message}; the promise never settles on its own, which is why every caller races it and
  // cancels the observer when the race is over.
  #dialogRace(browser) {
    let resolve = null;
    const promise = new Promise(r => { resolve = r; });
    const observer = {
      observe(subject) {
        let args = null;
        try {
          args = subject?.Dialog?.args ?? null;
        } catch {
          args = null;
        }
        const owning = args?.owningBrowsingContext ?? null;
        if (!owning || !browser.browsingContext) return;
        let same = false;
        try {
          same = owning === browser.browsingContext || owning.top === browser.browsingContext;
        } catch {
          same = false;
        }
        if (!same) return;
        let message = "";
        try {
          message = subject.Dialog?.ui?.infoBody?.textContent ?? "";
        } catch {
          message = "";
        }
        resolve({ type: args.inPermitUnload ? "beforeunload" : (args.promptType ?? null), message });
      },
    };
    Services.obs.addObserver(observer, "common-dialog-loaded");
    return { promise, cancel: () => Services.obs.removeObserver(observer, "common-dialog-loaded") };
  }

  // `mode` (V3): "text" (the default) is the V1 extraction; "article" is the reader view's parse of
  // the same document - the child runs ReaderMode.parseDocument, the page is never navigated and never
  // mutated. Both answer through the same read permission.
  async #read(params, req) {
    const mode = params?.mode ?? "text";
    if (mode !== "text" && mode !== "article") {
      throw new LoaderError("E_BAD_PARAMS", 'browser.read accepts mode as "text" or "article"');
    }
    const { tabKey, wg } = this.#resolveTab(params?.tabKey);
    await this.#gate("read", req);
    this.#checkDeadline(req);
    if (mode === "article") {
      const reply = await this.#query(wg, "article", {});
      return {
        tabKey,
        url: reply?.url ?? "",
        title: reply?.title ?? "",
        byline: reply?.byline ?? "",
        text: typeof reply?.text === "string" ? reply.text : "",
        truncated: reply?.truncated === true,
      };
    }
    const reply = await this.#query(wg, "read", {});
    const fullLength = Number.isFinite(reply?.fullLength) ? reply.fullLength : null;
    let page;
    try {
      page = JSON.parse(reply?.json ?? "");
    } catch {
      throw new LoaderError("E_READ_FAILED", `browser.read could not read tab ${tabKey}: the page actor returned no usable JSON`);
    }
    const text = typeof page?.text === "string" ? page.text : "";
    return {
      tabKey,
      url: page?.url ?? "",
      title: page?.title ?? "",
      text,
      // The actor reports the untruncated length too, so the flag survives an extraction that no
      // longer ships the "truncated" field.
      truncated: page?.truncated === true || (fullLength !== null && fullLength > text.length),
    };
  }

  // The screenshot runs in the parent exactly as S4 measured it: the actor returns the visual
  // viewport, drawSnapshot returns an ImageBitmap, and a chrome canvas turns it into the same PNG
  // byte-for-byte.
  async #screenshot(params, req) {
    const { tabKey, tab, browser, wg } = this.#resolveTab(params?.tabKey);
    await this.#gate("read", req);
    this.#checkDeadline(req);
    const vp = await this.#query(wg, "viewport", {});
    const win = browser.ownerGlobal ?? tab.ownerDocument?.defaultView ?? null;
    if (!win) {
      throw new LoaderError("E_READ_FAILED", `browser.screenshot could not find the window that owns tab ${tabKey}`);
    }
    const scale = browser.browsingContext?.overrideDPPX || win.devicePixelRatio || 1;
    const rect = new win.DOMRect(vp.x, vp.y, vp.width, vp.height);
    let snapshot;
    try {
      snapshot = await wg.drawSnapshot(rect, scale, "rgb(255,255,255)");
    } catch (e) {
      // A hidden tab (one in an inactive space) is rendered correctly by drawSnapshot - verified live
      // - so a failure here is either that one Gecko case or a real read failure. The hidden case gets
      // the refusal that names the space; anything else stays a read failure with Gecko's message.
      if (tab.hidden) {
        throw new LoaderError("E_TAB_INACTIVE_SPACE", `screenshot unavailable for hidden tabs (tab ${tabKey} is in an inactive space): ${e?.message ?? e}`);
      }
      throw new LoaderError("E_READ_FAILED", `browser.screenshot could not render tab ${tabKey}: ${e?.message ?? e}`);
    }
    try {
      const canvas = win.document.createElementNS(XHTML_NS, "canvas");
      canvas.width = Math.round(vp.width * scale);
      canvas.height = Math.round(vp.height * scale);
      const ctx = canvas.getContext("2d");
      ctx.drawImage(snapshot, 0, 0);
      const dataUrl = canvas.toDataURL("image/png");
      const data = dataUrl.slice(dataUrl.indexOf(",") + 1);
      if (!data) throw new LoaderError("E_READ_FAILED", `browser.screenshot produced no image data for tab ${tabKey}`);
      return { tabKey, mimeType: "image/png", data };
    } finally {
      // ImageBitmap.close is best-effort: a closed bitmap must never mask the real result.
      try {
        snapshot.close();
      } catch {
        // Nothing to do: the bitmap is collected with the canvas either way.
      }
    }
  }

  async #snapshot(params, req) {
    const { tabKey, wg } = this.#resolveTab(params?.tabKey);
    await this.#gate("read", req);
    this.#checkDeadline(req);
    const reply = await this.#query(wg, "snapshot", {});
    return {
      tabKey,
      url: reply?.url ?? "",
      title: reply?.title ?? "",
      elements: Array.isArray(reply?.elements) ? reply.elements : [],
      truncated: reply?.truncated === true,
    };
  }

  // The dialog-owned act: `{action, ref?, text?, key?, dy?}`, validated here and forwarded to the
  // actor as-is (the child re-checks, because the parent cannot see the DOM). Params are validated
  // before the gate, so a malformed call never costs the user a prompt.
  async #act(params, req) {
    const action = params?.action;
    const ref = params?.ref;
    const text = params?.text;
    const key = params?.key;
    const dy = params?.dy;
    const ACTIONS = ["click", "type", "press", "scroll", "hover", "navigate"];
    if (typeof action !== "string" || !ACTIONS.includes(action)) {
      throw new LoaderError("E_BAD_PARAMS", `browser.act needs action to be one of ${ACTIONS.join(", ")}`);
    }
    if ((action === "click" || action === "hover") && (typeof ref !== "string" || !ref)) {
      throw new LoaderError("E_BAD_PARAMS", `browser.act ${action} needs a ref from browser_snapshot`);
    }
    if (action === "type") {
      if (typeof ref !== "string" || !ref) throw new LoaderError("E_BAD_PARAMS", "browser.act type needs a ref from browser_snapshot");
      if (typeof text !== "string") throw new LoaderError("E_BAD_PARAMS", "browser.act type needs text");
      if (text.length > 2000) throw new LoaderError("E_BAD_PARAMS", "browser.act type accepts at most 2000 characters per call");
    }
    if (action === "press") {
      const KEYS = ["Enter", "Tab", "Escape", "Backspace", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "PageUp", "PageDown", "Home", "End"];
      if (typeof key !== "string" || !KEYS.includes(key)) {
        throw new LoaderError("E_BAD_PARAMS", `browser.act press needs key to be one of ${KEYS.join(", ")}`);
      }
      if (ref !== undefined && (typeof ref !== "string" || !ref)) {
        throw new LoaderError("E_BAD_PARAMS", "browser.act press accepts a ref only as a non-empty string");
      }
    }
    if (action === "scroll") {
      const hasRef = typeof ref === "string" && !!ref;
      const hasDy = Number.isInteger(dy);
      if (hasRef === hasDy) {
        throw new LoaderError("E_BAD_PARAMS", "browser.act scroll needs either a ref or an integer dy");
      }
      if (hasDy && Math.abs(dy) > 10_000) {
        throw new LoaderError("E_BAD_PARAMS", "browser.act scroll accepts |dy| up to 10000 pixels per call");
      }
    }
    if (action === "navigate") return this.#navigate(params, req);

    const { tabKey, tab, browser, wg } = this.#resolveTab(params?.tabKey, { write: true });
    await this.#gate("act", req);
    this.#checkDeadline(req);
    const payload = { action, ref, text, key, dy };
    // Checkpoint 4: nothing may reach the page once omp gave up (the actor call is the side effect).
    this.#checkDeadline(req);
    // The watch on the tab starts only after that check: created any earlier, an E_DEADLINE thrown here
    // would leave the window with a TabOpen/TabSelect capture listener and a state nothing ever takes
    // down (nothing reaches the try below, so neither the finally nor #collectOpened runs).
    const watcher = this.#watchAgentTabOpens(tab, browser);
    let reply;
    try {
      reply = await this.#queryAct(wg, payload, browser);
    } finally {
      // The act is over however it ended: start the re-homing grace (a no-op when #collectOpened below
      // already did) so a popup the act opened is still re-homed and the watcher's listeners go away.
      this.#armGrace(watcher);
    }
    const opened = await this.#collectOpened(watcher);
    return { ...reply, tabKey, opened };
  }

  // navigate never reaches the child: the loader drives the load itself, with the system principal,
  // and waits for the URL to move. about:blank/newtab/home are the only privileged pages it may
  // leave (the plan's exemption); everything else is E_PRIVILEGED_PAGE before anything happens.
  async #navigate(params, req) {
    const url = params?.url;
    if (typeof url !== "string" || !url) {
      throw new LoaderError("E_BAD_PARAMS", "browser.act navigate needs a url");
    }
    let scheme = null;
    let target = null;
    try {
      const uri = Services.io.newURI(url);
      scheme = uri.scheme;
      target = uri.spec;
    } catch {
      scheme = null;
    }
    if (scheme !== "http" && scheme !== "https") {
      throw new LoaderError("E_BAD_PARAMS", "browser.act navigate accepts http(s) URLs only");
    }
    const { tabKey, tab, browser } = this.#resolveTab(params?.tabKey, { allowAbout: true, write: true });
    await this.#gate("act", req);
    this.#checkDeadline(req);
    const watcher = this.#watchAgentTabOpens(tab, browser);
    const before = browser.currentURI.spec;
    // The document the load starts from: a same-URL load (reload, navigate to the URL already shown,
    // a redirect back to it) proves itself by replacing this window global.
    const beforeWg = browser.browsingContext?.currentWindowGlobal ?? null;
    // The URL already shown, with a #ref: Gecko scrolls the same document to the anchor - no load,
    // no new window global and no spec change - so only "the tab shows exactly that URL and is not
    // loading" can prove it (see #loadLanded).
    const sameDocument = target.includes("#") && before === target ? target : null;
    const dialog = this.#dialogRace(browser);
    try {
      this.#checkDeadline(req);
      browser.fixupAndLoadURIString(url, { triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal() });
      const landed = await this.#waitForLoad(tabKey, browser, {
        previous: before,
        previousWg: beforeWg,
        sameDocument,
        bound: NAVIGATE_TIMEOUT_MS,
        what: `browser.act navigate to ${url} (tab ${tabKey})`,
        dialog,
      });
      // A page that answered with a dialog instead of loading (beforeunload, an alert during load):
      // omp gets the dialog facts rather than a timeout.
      if (landed.dialog) {
        return { ok: true, tabKey, dialog: landed.dialog, opened: await this.#collectOpened(watcher) };
      }
      return { ok: true, tabKey, url: landed.url, title: tab.label ?? "", opened: await this.#collectOpened(watcher) };
    } finally {
      dialog.cancel();
      // Same as #act: a navigate that timed out or hit a dialog still ends its watch on the tab (a
      // no-op once #collectOpened awaited the grace itself).
      this.#armGrace(watcher);
    }
  }

  // ---------------------------------------------------------------- loads

  // The load test navigate and zen.open share: the browser is not loading a document any more and the
  // load itself can be seen to have happened. A URL string comparison alone is not enough - a reload, a
  // navigate to the URL the tab already shows and a redirect back to it all leave `currentURI.spec`
  // exactly as it was, so a load that worked would poll to E_TIMEOUT ("did not finish loading") - and
  // neither is `isLoadingDocument` alone, because a wait can start after a fast load already ended.
  //
  // Four signals, any one of them enough:
  //  - the spec moved off `previous` (navigate to a different URL, zen.open leaving about:blank);
  //  - the browsing context's currentWindowGlobal is not the one the load started from (`previousWg`):
  //    a cross-document load replaces the document, so a new (or no) window global proves the load;
  //  - this wait watched the browser load (`sawLoading`) and it has now stopped;
  //  - a same-document navigate (`sameDocument`: the exact URL already shown, with a #ref) after at
  //    least one poll: the scroll has no load to watch, and the poll gives a real load Gecko might
  //    start instead the time to show up as loading or as a new window global first.
  #loadLanded(browser, previous, previousWg, sawLoading, sameDocument = null, polled = false) {
    if (browser.webProgress?.isLoadingDocument === true) return null;
    const spec = browser.currentURI.spec;
    if (spec !== previous) return spec;
    const wg = browser.browsingContext?.currentWindowGlobal ?? null;
    if (previousWg && wg !== previousWg) return spec;
    if (sawLoading) return spec;
    return sameDocument && polled && spec === sameDocument ? spec : null;
  }

  // Waits, bounded, for a load this loader started to land, polling every NAVIGATE_POLL_MS. Returns
  // {url} - or {dialog} early when `dialog` (navigate's common-dialog race) fires instead, because a
  // page that answers with a prompt never finishes loading. `what` names the operation in the timeout,
  // which must tell omp what already exists (E_DEADLINE promises "nothing was done"; a load wait is
  // after the side effect, so only its own bound may fail).
  async #waitForLoad(tabKey, browser, { previous, previousWg = null, sameDocument = null, bound, what, dialog = null }) {
    const started = Date.now();
    let sawLoading = false;
    let polled = false;
    for (;;) {
      if (browser.webProgress?.isLoadingDocument === true) sawLoading = true;
      const landed = this.#loadLanded(browser, previous, previousWg, sawLoading, sameDocument, polled);
      if (landed) return { url: landed };
      if (Date.now() - started > bound) {
        throw new LoaderError("E_TIMEOUT", `${what} did not finish loading within ${bound} ms`);
      }
      const winner = dialog
        ? await Promise.race([pageSleep(NAVIGATE_POLL_MS), dialog.promise.then(info => ({ dialog: info }))])
        : await pageSleep(NAVIGATE_POLL_MS);
      if (winner?.dialog) return { dialog: winner.dialog };
      polled = true;
    }
  }

  // File uploads run entirely in chrome scope (Rev 2): the parent builds one File per path - the same
  // ChromeOnly File.createFromFileName the shipped content-side recipe uses - and the actor sets them
  // on the element (mozSetFileArray + input + change, its own recipe). No file picker, no DOM
  // attribute: nothing is left in the page afterwards.
  async #upload(params, req) {
    const ref = params?.ref;
    const paths = params?.paths;
    if (typeof ref !== "string" || !ref) {
      throw new LoaderError("E_BAD_PARAMS", "browser.upload needs a ref from browser_snapshot");
    }
    if (!Array.isArray(paths) || paths.length === 0 || paths.some(path => !isAbsolutePath(path))) {
      throw new LoaderError("E_BAD_PARAMS", "browser.upload needs paths as a non-empty array of absolute file paths");
    }
    const { tabKey, tab, browser, wg } = this.#resolveTab(params?.tabKey, { write: true });
    await this.#gate("act", req);
    this.#checkDeadline(req);
    const files = [];
    for (const path of paths) {
      try {
        files.push(await File.createFromFileName(path));
      } catch (e) {
        // The plugin checked existence before sending, so a path Gecko refuses is a params problem
        // (it vanished, or the process cannot read it), never a page problem.
        throw new LoaderError("E_BAD_PARAMS", `browser.upload could not read ${path}: ${e?.message ?? e}`);
      }
    }
    // Checkpoint 4: nothing may reach the page once omp gave up (the actor call is the side effect).
    this.#checkDeadline(req);
    // kind "act": a document that dies under the query means the ref's document is gone, exactly as
    // for browser.act (E_REF_STALE), while the child reports its own stale/refused cases squarely.
    const reply = await this.#query(wg, "setFiles", { ref, files }, { kind: "act" });
    // url/title name the page the files were set on, as navigate and zen.open report theirs.
    return {
      ok: true,
      tabKey,
      count: Number.isFinite(reply?.count) ? reply.count : files.length,
      url: browser.currentURI.spec,
      title: tab.label ?? "",
    };
  }

  // Answers the common prompt open in a tab, in chrome scope: the tab's own dialog box holds it
  // (TabDialogBox), and the commonDialog inside it exposes `Dialog.ui` - the same fields
  // shared/Prompt.sys.mjs drives (ui.button0 = accept, ui.button1 = cancel, ui.loginTextbox = the text
  // box, ui.infoBody = the message). Returns null when this tab has no prompt up.
  #findPrompt(browser) {
    // `browser.tabDialogBox` is created on demand the first time a prompt opens for a browser
    // (Tabbrowser.getTabDialogBox L1507-1517), so its absence is exactly "no prompt was ever opened
    // for this browser" - and no prompt means nothing to answer.
    const box = browser.tabDialogBox ?? null;
    if (!box) return null;
    // The lookup is modal.findPrompt's (Prompt.sys.mjs L64-79): the tab-level manager first
    // (beforeunload, tab alerts), then the content manager (page alert/confirm/prompt).
    const dialogs = [
      ...box.getTabDialogManager().dialogs,
      ...box.getContentDialogManager().dialogs,
    ];
    for (const dialog of dialogs) {
      if (dialog?._isClosing) continue;
      let win = null;
      try {
        win = dialog.frameContentWindow ?? null;
      } catch {
        win = null; // the dialog's frame is already gone
      }
      // `Dialog` is assigned by commonDialog.js when the dialog loads, and is what Prompt.sys.mjs
      // reads too: without it the window is not a common prompt, or is not set up yet.
      const ui = win?.Dialog?.ui ?? null;
      if (!ui) continue;
      return { ui, args: win.Dialog.args ?? null };
    }
    return null;
  }

  // browser.dialog: answer the tab's open prompt. `accept` clicks button0 and a dismiss clicks button1
  // (button0 again when the dialog has no cancel, the alert shape Prompt.sys.mjs's dismiss uses), and
  // `text` fills the prompt's text box before the click - a field only prompt() shows.
  async #dialog(params, req) {
    const accept = params?.accept;
    const text = params?.text;
    if (typeof accept !== "boolean") {
      throw new LoaderError("E_BAD_PARAMS", "browser.dialog needs accept as a boolean");
    }
    if (text !== undefined && typeof text !== "string") {
      throw new LoaderError("E_BAD_PARAMS", "browser.dialog accepts text as a string only");
    }
    const { tabKey, tab, browser } = this.#resolveTab(params?.tabKey, { write: true });
    // Looked up before the gate: prompting the user about a tab that has no dialog would be noise.
    if (!this.#findPrompt(browser)) {
      throw new LoaderError("E_NO_DIALOG", `tab ${tabKey} has no open prompt; act on the page and watch for a dialog first`);
    }
    await this.#gate("act", req);
    this.#checkDeadline(req);
    // The gate can take the full 120 s, so the live dialog is read again after it: a prompt the user
    // answered meanwhile (Escape, the window) is gone, and clicking its dead buttons would be a lie.
    const found = this.#findPrompt(browser);
    if (!found) {
      throw new LoaderError("E_NO_DIALOG", `tab ${tabKey} has no open prompt any more; it was answered before this call could act`);
    }
    const { ui, args } = found;
    // Checkpoint 4: the button click (and the text write) is the side effect.
    this.#checkDeadline(req);
    if (typeof text === "string" && ui.loginTextbox) ui.loginTextbox.value = text;
    // The page as it was when the dialog was answered: accepting a beforeunload or a confirm can start
    // a navigation, which these fields do not follow.
    const url = browser.currentURI.spec;
    const title = tab.label ?? "";
    const button = accept ? ui.button0 : (ui.button1 ?? ui.button0);
    button.click();
    return {
      ok: true,
      tabKey,
      type: args?.inPermitUnload ? "beforeunload" : (args?.promptType ?? null),
      message: ui.infoBody?.textContent ?? "",
      url,
      title,
    };
  }

  // ---------------------------------------------------------------- agent-space popups

  // While an act/navigate runs on an agent-space tab (and for 1 s after), a tab that tab opens - a
  // window.open the agent's trusted click is allowed to make - is moved into the agent space, and if
  // it stole the selection the user's previous tab is re-selected: the user's space must not change
  // (plan: "popups from agent-space tabs").
  #watchAgentTabOpens(tab, browser) {
    const win = browser.ownerGlobal ?? tab.ownerDocument?.defaultView ?? null;
    const spaceId = win ? this.#agentSpaceIdOf(win) : null;
    if (!win || !spaceId || tab.getAttribute("zen-workspace-id") !== spaceId) return null;
    let box = this.#tabOpenWatchers.get(win);
    if (!box) {
      box = { win, states: [], handler: null, selectHandler: null };
      box.handler = event => this.#onAgentTabOpen(box, event);
      // Capture phase: this runs before Zen's own TabSelect listener (ZenSpaceManager onLocationChange
      // is a bubble listener), so a popup that steals the selection can be put back before Zen starts
      // switching the user's space.
      box.selectHandler = event => { for (const state of box.states) this.#restoreUserView(state, event?.target ?? null); };
      win.addEventListener("TabOpen", box.handler, true);
      win.addEventListener("TabSelect", box.selectHandler, true);
      this.#tabOpenWatchers.set(win, box);
    }
    const state = {
      win,
      box,
      agentTab: tab,
      spaceId,
      previousSelected: win.gBrowser?.selectedTab ?? null,
      // The space the user was looking at: Zen switches spaces on TabSelect (ZenSpaceManager
      // onLocationChange -> changeWorkspace), and that switch can land after our re-selection.
      userSpaceId: win.gZenWorkspaces?.activeWorkspace ?? null,
      restoring: false,
      openedTabs: [], // the tab elements a popup created; keys are resolved once the grace is over
      done: null,
      finish: null,
      timer: null, // armed by #armGrace once the act is over, never before it
      finished: false, // set when the grace ends: #armGrace must not revive an unwatched state
    };
    state.done = new Promise(resolve => { state.finish = resolve; });
    box.states.push(state);
    return state;
  }

  // Starts the 1 s re-homing grace for a watcher: called the moment the act/navigate it belongs to is
  // over (success or failure), never when the watcher is created. Arming it up front ended the grace
  // before a slow act finished - a navigate that waits seconds for its load, or a window.open the page
  // calls after an await (still inside the click's transient activation) - so that popup was neither
  // moved into the agent space nor reported, and could keep the selection and switch the user's space
  // (plan: re-homing covers the act "and for 1 s after").
  #armGrace(state) {
    // `finished`: the state was already unwatched (a teardown, or #collectOpened's awaited grace) -
    // arming it again would leave a stray timer that unwatches a state the box no longer holds and
    // would put a view back a second time.
    if (!state || state.finished || state.timer !== null) return;
    state.timer = setTimeout(() => this.#unwatchAgentTabOpens(state.win, state.box, state), TAB_OPEN_GRACE_MS);
  }

  #onAgentTabOpen(box, event) {
    const opened = event?.target;
    if (!opened || !box.states.length) return;
    const state = box.states.find(candidate => opened.openerTab === candidate.agentTab || opened.ownerTab === candidate.agentTab);
    if (!state) return;
    const win = box.win;
    try {
      win.gZenWorkspaces?.moveTabToWorkspace(opened, state.spaceId);
    } catch {
      // Zen refused the move (a pinned/essential tab): the tab stays where it opened, and the reply
      // still reports it so omp can react.
    }
    state.openedTabs.push(opened);
    // Only a popup that actually took the selection has a view to put back: a background popup leaves
    // the user where they are, and #restoreUserView acts only on a re-homed popup as the selection.
    if (win.gBrowser?.selectedTab === opened) this.#restoreUserView(state, opened);
  }

  // Puts the user's view back after a popup was re-homed: the popup must not stay selected, and the
  // space must stay the one the user was in (plan: "the user's space never changes"). The selection is
  // the primary lever - Zen switches spaces on TabSelect, exactly as it does when the user clicks a tab
  // of another space - but a switch Zen already started for the popup can land after our re-selection,
  // so the space is checked here as well and restored with the same call Zen's own onLocationChange
  // makes, and only ever to the space captured before the act. Called when the popup appears, on every
  // TabSelect inside the grace (capture, before Zen reacts), and one last time when the grace ends.
  //
  // Only a popup *this act* re-homed may be undone, so `blamed` - the tab a TabSelect is about, or with
  // none the tab selected right now - must be one of `openedTabs`. A selection or a space switch the act
  // did not cause (the user clicking any other tab, an agent-space tab included, or switching spaces
  // during the grace) is the user's own view and is never put back: "Your view stays yours".
  #restoreUserView(state, selected = null) {
    if (state.restoring) return;
    const win = state.win;
    const previous = state.previousSelected;
    if (!win || !previous || previous.closed) return;
    const blamed = selected && !selected.closed ? selected : (win.gBrowser?.selectedTab ?? null);
    if (!blamed || !state.openedTabs.includes(blamed)) return;
    state.restoring = true;
    try {
      if (win.gBrowser?.selectedTab !== previous) {
        try {
          win.gBrowser.selectedTab = previous;
        } catch {
          // The previous tab went away in the same breath: there is nothing left to restore.
        }
      }
      // The space: only the user's own, only when the re-homed popup moved Zen off it. The popup being
      // the selection is what makes the move the popup's doing - a space switch the user made selects
      // one of their own tabs, so this code never runs for it.
      const active = win.gZenWorkspaces?.activeWorkspace;
      if (state.userSpaceId && active && active !== state.userSpaceId) {
        try {
          const space = win.gZenWorkspaces.getWorkspaceFromId?.(state.userSpaceId) ?? null;
          if (space) win.gZenWorkspaces.changeWorkspace?.(space);
        } catch {
          // A Zen that refuses the switch leaves the user where they are; nothing else to try here.
        }
      }
    } finally {
      state.restoring = false;
    }
  }

  // Ends the act's watch: starts the 1 s grace (if a failure path has not already) so a popup that only
  // reaches the parent after the action returned is still re-homed and reported, then returns the tab
  // keys that were opened by the acted-on tab.
  // A tabKey is Zen's window-sync id: `tab.id`, assigned by ZenWindowSync.mjs's TabOpen handler
  // (`on_TabOpen`, shipped L1368-1379: `if (!tab.id) tab.id = this.#newTabSyncId`). Live QA showed that
  // assignment can land *after* addTab/moveTabToWorkspace returned (zen.open answered an empty key
  // while zen_tabs listed the tab with its id a moment later), and "" is not caught by `??`. So every
  // key this loader mints for a tab it just opened is waited for, bounded, never guessed.
  // The bound is deliberately not the request deadline: by the time this runs the tab exists, and
  // E_DEADLINE promises "nothing was done", which would be untrue.
  async #waitForTabKey(tab) {
    const started = Date.now();
    for (;;) {
      if (tab?.id) return tab.id;
      if (Date.now() - started > TAB_KEY_TIMEOUT_MS) {
        throw new LoaderError("E_TIMEOUT", `the tab was opened, but Zen did not assign its key within ${TAB_KEY_TIMEOUT_MS} ms; list tabs with zen_tabs`);
      }
      await pageSleep(TAB_KEY_POLL_MS);
    }
  }

  // The same wait, for a popup the act already proved opened: a key that never appears must not turn a
  // successful act into a failure, so that tab is simply left out of `opened`.
  async #tabKeyOrNull(tab) {
    try {
      return await this.#waitForTabKey(tab);
    } catch {
      return null;
    }
  }

  async #collectOpened(state) {
    if (!state) return [];
    // The grace starts here, when the action has returned (see #armGrace).
    this.#armGrace(state);
    await state.done;
    const keys = [];
    for (const tab of state.openedTabs) {
      if (tab.closed) continue;
      const key = await this.#tabKeyOrNull(tab);
      if (key) keys.push(key);
    }
    return keys;
  }

  #unwatchAgentTabOpens(win, box, state) {
    clearTimeout(state.timer);
    state.timer = null;
    state.finished = true;
    // One last look before the grace ends: Zen's own space switch for a re-homed popup may have landed
    // while the timer was running, and that switch re-selects the popup - which is exactly what lets
    // #restoreUserView act (see there: nobody else's selection is ever put back).
    this.#restoreUserView(state);
    const index = box.states.indexOf(state);
    if (index >= 0) box.states.splice(index, 1);
    state.finish();
    if (!box.states.length) {
      try {
        win.removeEventListener("TabOpen", box.handler, true);
        win.removeEventListener("TabSelect", box.selectHandler, true);
      } catch {
        // The window is gone; its listeners went with it.
      }
      this.#tabOpenWatchers.delete(win);
    }
  }

  #clearTabOpenWatchers() {
    for (const [win, box] of [...this.#tabOpenWatchers]) {
      for (const state of [...box.states]) this.#unwatchAgentTabOpens(win, box, state);
    }
    this.#tabOpenWatchers.clear();
  }

  // ---------------------------------------------------------------- Zen layout

  // The most recent non-private browser window: layout methods act on one window (its own tab copies
  // are the ones Zen moves), and a private window is never a target.
  #targetWindow() {
    const recent = Services.wm.getMostRecentWindow?.("navigator:browser") ?? null;
    if (recent && !recent.closed && !isPrivateWindow(recent)) return recent;
    return browserWindows().find(w => !w.closed) ?? null;
  }

  // The window's tab element for a sync id: fenix-style lookups elsewhere use collectTabs(), but Zen
  // moves a tab by the copy the target window owns.
  #windowTab(win, tabKey) {
    if (typeof tabKey !== "string" || !tabKey) {
      throw new LoaderError("E_TAB_UNKNOWN", "a tabKey from zen.inventory is required");
    }
    const tab = windowTabs(win).find(candidate => candidate.id === tabKey);
    if (!tab) {
      throw new LoaderError("E_TAB_UNKNOWN", `no tab with key ${tabKey} in the target window; list tabs with zen.inventory`);
    }
    return tab;
  }

  // The agent space, by name: found when it exists, never created here (only zen.open creates it).
  #agentSpaceIdOf(win) {
    try {
      this.#need(win, "gZenWorkspaces.getWorkspaces");
      const space = win.gZenWorkspaces?.getWorkspaces?.()?.find(candidate => candidate.name === AGENT_SPACE_NAME);
      return space?.uuid ?? null;
    } catch {
      return null;
    }
  }

  // The shipped ZenSpaceManager.createAndSaveWorkspace is `async` (temp/extract/t2/modules/zen/
  // ZenSpaceManager.mjs L2574) and resolves to the new workspace data (or null when workspaces are
  // disabled), so its uuid may only be read after awaiting it. The name lookup stays first: an
  // existing "Hirozen Agent" space is reused, never created twice.
  async #ensureAgentSpace(win) {
    let spaceId = this.#agentSpaceIdOf(win);
    if (!spaceId) {
      // dontChange=true: creating the space must not switch the user's own space (plan).
      this.#need(win, "gZenWorkspaces.createAndSaveWorkspace");
      const created = await win.gZenWorkspaces?.createAndSaveWorkspace?.(AGENT_SPACE_NAME, undefined, true);
      // Either shape is accepted: the resolved workspace data, or a fresh name lookup (Zen returns
      // null when workspaces are disabled, and an unsynced window renames the space on creation).
      spaceId = created?.uuid ?? this.#agentSpaceIdOf(win);
    }
    if (!spaceId) {
      throw new LoaderError("E_LAYOUT_REFUSED", "Zen did not create the agent space");
    }
    return spaceId;
  }

  // Wait, bounded, for the space's element to exist: moveTabToWorkspace needs its container.
  async #waitForSpaceElement(win, spaceId) {
    const started = Date.now();
    for (;;) {
      const el = win.gZenWorkspaces?.workspaceElement?.(spaceId) ?? null;
      if (el) return;
      if (Date.now() - started > AGENT_SPACE_TIMEOUT_MS) {
        throw new LoaderError("E_TIMEOUT", `the Zen space ${AGENT_SPACE_NAME} did not finish loading within ${AGENT_SPACE_TIMEOUT_MS} ms`);
      }
      await pageSleep(AGENT_SPACE_POLL_MS);
    }
  }

  async #zenOpen(params, req) {
    const url = params?.url;
    let scheme = null;
    try {
      scheme = Services.io.newURI(url).scheme;
    } catch {
      scheme = null;
    }
    if (typeof url !== "string" || (scheme !== "http" && scheme !== "https")) {
      throw new LoaderError("E_BAD_PARAMS", "zen.open accepts http(s) URLs only");
    }
    const win = this.#targetWindow();
    if (!win) {
      throw new LoaderError("E_TAB_UNKNOWN", "no browser window is open");
    }
    await this.#gate("act", req);
    this.#checkDeadline(req);
    // The load bound is measured from here, after the gate: the time a person spends on the Allow/Deny
    // notice is their own (omp's budget already allows for it), and must not be charged to the page
    // load - a long Allow would otherwise leave the load as little as 1 s and fail a tab that opened.
    const started = Date.now();
    const spaceId = await this.#ensureAgentSpace(win);
    await this.#waitForSpaceElement(win, spaceId);
    this.#checkDeadline(req);
    const tab = win.gBrowser.addTab(url, {
      triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
      inBackground: true,
    });
    this.#need(win, "gZenWorkspaces.moveTabToWorkspace");
    win.gZenWorkspaces.moveTabToWorkspace(tab, spaceId);
    const tabKey = await this.#waitForTabKey(tab);
    // The tab exists now, so E_DEADLINE ("nothing was done") would be a lie: only the load wait's own
    // bound may fail from here on. zen.open's worst case is the agent-space wait (5 s) + the tab-key
    // wait (2 s) + this load, and NAVIGATE's 12 s is the whole budget the plugin gives a load, so the
    // load gets 12 s minus what the agent-space and tab-key waits already took.
    const bound = Math.max(1_000, NAVIGATE_TIMEOUT_MS - (Date.now() - started));
    const landed = await this.#waitForLoad(tabKey, tab.linkedBrowser, {
      // A brand-new tab starts on about:blank (live QA saw exactly that) and only an http(s) load may
      // leave it, so about:blank is the "before" here just as the pre-navigation URL is for navigate.
      previous: "about:blank",
      bound,
      what: `zen.open's page ${url} (tab ${tabKey}, already open in the "${AGENT_SPACE_NAME}" space and still usable)`,
    });
    return { tabKey, spaceId, url: landed.url, title: tab.label ?? "" };
  }

  async #zenMove(params, req) {
    const spaceId = params?.spaceId;
    if (typeof spaceId !== "string" || !spaceId) {
      throw new LoaderError("E_BAD_PARAMS", "zen.move needs spaceId from zen.spaces");
    }
    const win = this.#targetWindow();
    if (!win) {
      throw new LoaderError("E_TAB_UNKNOWN", "no browser window is open");
    }
    const tab = this.#windowTab(win, params?.tabKey);
    const tabKey = tab.id;
    await this.#gate("act", req);
    this.#checkDeadline(req);
    if (!spacesOf(win).some(space => space.uuid === spaceId)) {
      throw new LoaderError("E_LAYOUT_REFUSED", `no Zen space with id ${spaceId}`);
    }
    // Pinned and essential tabs live in every space and carry no zen-workspace-id: Zen would clone
    // them instead of moving one tab, so they are refused (plan: layout safety).
    if (tab.pinned || tab.getAttribute("zen-essential") === "true") {
      throw new LoaderError("E_LAYOUT_REFUSED", `tab ${tabKey} is pinned or essential; Zen clones those instead of moving them`);
    }
    this.#checkDeadline(req);
    this.#need(win, "gZenWorkspaces.moveTabToWorkspace");
    win.gZenWorkspaces.moveTabToWorkspace(tab, spaceId);
    if (tab.getAttribute("zen-workspace-id") !== spaceId) {
      throw new LoaderError("E_LAYOUT_REFUSED", `Zen did not move tab ${tabKey} to space ${spaceId}`);
    }
    return { tabKey, spaceId };
  }

  async #zenSplit(params, req) {
    const tabKeys = params?.tabKeys;
    const layout = params?.layout;
    if (!Array.isArray(tabKeys) || tabKeys.length < 2 || tabKeys.length > 4 || tabKeys.some(key => typeof key !== "string" || !key)) {
      throw new LoaderError("E_BAD_PARAMS", "zen.split needs tabKeys as an array of 2 to 4 tab keys");
    }
    if (!["vsep", "hsep", "grid"].includes(layout)) {
      throw new LoaderError("E_BAD_PARAMS", "zen.split needs layout to be vsep, hsep or grid");
    }
    const win = this.#targetWindow();
    if (!win) {
      throw new LoaderError("E_TAB_UNKNOWN", "no browser window is open");
    }
    const tabs = tabKeys.map(key => this.#windowTab(win, key));
    await this.#gate("act", req);
    this.#checkDeadline(req);
    // Split view is a layout change of the space the user is looking at: never the selected tab (that
    // would move the user's view), never a tab Zen would clone or silently drop (pinned, essential, or
    // one in an inactive space - splitTabs filters hidden tabs out and would return undefined).
    if (win.gBrowser.selectedTab && tabs.includes(win.gBrowser.selectedTab)) {
      throw new LoaderError("E_LAYOUT_REFUSED", "zen.split refuses to include the selected tab; Zen would move the user's view");
    }
    if (tabs.some(tab => tab.pinned || tab.getAttribute("zen-essential") === "true" || tab.hidden)) {
      throw new LoaderError("E_LAYOUT_REFUSED", "zen.split refuses pinned, essential or hidden tabs; Zen would clone or drop them");
    }
    this.#checkDeadline(req);
    // -1 keeps Zen from selecting any of the tabs (the shipped splitTabs has no activate option).
    this.#need(win, "gZenViewSplitter.splitTabs");
    const group = win.gZenViewSplitter.splitTabs(tabs, layout, -1);
    if (!group) {
      throw new LoaderError("E_LAYOUT_REFUSED", "Zen refused the split view");
    }
    return { groupId: group.groupId ?? null };
  }

  async #zenUnsplit(params, req) {
    const win = this.#targetWindow();
    if (!win) {
      throw new LoaderError("E_TAB_UNKNOWN", "no browser window is open");
    }
    const tab = this.#windowTab(win, params?.tabKey);
    await this.#gate("act", req);
    this.#checkDeadline(req);
    const splitter = win.gZenViewSplitter;
    const inSplit = !!tab.group?.hasAttribute?.("split-view-group") ||
      !!splitter?._data?.some(group => group.tabs.includes(tab));
    if (!inSplit) {
      throw new LoaderError("E_LAYOUT_REFUSED", `tab ${params?.tabKey} is not in a split view`);
    }
    this.#checkDeadline(req);
    // changeTab:false: the tab leaves its group without the user's selection moving.
    this.#need(win, "gZenViewSplitter.removeTabFromGroup");
    splitter.removeTabFromGroup(tab, undefined, { changeTab: false });
    return { ok: true, tabKey: params?.tabKey };
  }

  async #zenGlance(params, req) {
    const url = params?.url;
    let scheme = null;
    try {
      scheme = Services.io.newURI(url).scheme;
    } catch {
      scheme = null;
    }
    if (typeof url !== "string" || (scheme !== "http" && scheme !== "https")) {
      throw new LoaderError("E_BAD_PARAMS", "zen.glance accepts http(s) URLs only");
    }
    const win = this.#targetWindow();
    if (!win) {
      throw new LoaderError("E_TAB_UNKNOWN", "no browser window is open");
    }
    await this.#gate("act", req);
    this.#checkDeadline(req);
    this.#need(win, "gZenGlanceManager.openGlance");
    const manager = win.gZenGlanceManager;
    if (manager?.overlay?.classList?.contains("zen-glance-overlay")) {
      throw new LoaderError("E_LAYOUT_REFUSED", "a glance is already open in this window");
    }
    this.#checkDeadline(req);
    // The data contract is exact (§14): wrong coordinate keys wedge the glance, and a missing
    // triggeringPrincipal makes it refuse silently. The 10 s bound plus the recovery below are the
    // spike's fix for a glance that never finishes animating.
    const opened = manager.openGlance({
      url,
      clientX: 400,
      clientY: 300,
      width: 20,
      height: 20,
      triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
    });
    let tab = null;
    try {
      tab = await this.#withTimeout(opened, GLANCE_TIMEOUT_MS, new LoaderError("E_TIMEOUT", `Zen's glance for ${url} did not open within ${GLANCE_TIMEOUT_MS} ms`));
    } catch (e) {
      if (e instanceof LoaderError && e.code === "E_TIMEOUT") {
        // §14 recovery: a wedged animation refuses every later closeGlance, so clear the flags first.
        try {
          manager._animating = false;
          manager.animatingOpen = false;
          this.#need(win, "gZenGlanceManager.closeGlance");
          manager.closeGlance();
        } catch {
          // Nothing else can be done; the timeout is still the honest answer.
        }
      }
      throw e;
    }
    if (!tab) {
      throw new LoaderError("E_LAYOUT_REFUSED", `Zen refused to open a glance for ${url}`);
    }
    return { tabKey: await this.#waitForTabKey(tab) };
  }

  // ---------------------------------------------------------------- lazy tabs

  // zen.loadTab: gives one unloaded tab its docshell where it is. No navigation (the stored URL is
  // Zen's own restore path, never a load this loader starts), no space switch, no selection change,
  // no new tab. Every refusal is decided before the gate, so nobody is asked about a call that cannot
  // run:
  //  - an unknown/blank key is E_TAB_UNKNOWN and a private window's tab is E_PRIVATE (a private tab
  //    key must resolve to the reason, not to "unknown");
  //  - an already loaded tab, a pinned tab and an essential tab are E_BAD_PARAMS. Zen's
  //    onTabBrowserInserted (ZenSpaceManager, window listener) stamps the *active* workspace onto a
  //    tab that has no zen-workspace-id - which pinned and essential tabs never have - so inserting
  //    one would mark the user's current space onto it for good;
  //  - a stored about:/chrome:/resource: URL is E_PRIVILEGED_PAGE, read from SessionStore's lazy-tab
  //    state (what Zen's own restore reads) with the unbound browser's currentURI as the fallback.
  async #zenLoadTab(params, req) {
    const tabKey = params?.tabKey;
    if (typeof tabKey !== "string" || !tabKey) {
      throw new LoaderError("E_TAB_UNKNOWN", "a tabKey from zen.inventory is required");
    }
    const entry = collectTabs().find(candidate => candidate.key === tabKey);
    if (!entry) {
      throw new LoaderError("E_TAB_UNKNOWN", `no tab with key ${tabKey}; list tabs with zen.inventory`);
    }
    if (entry.private) {
      throw new LoaderError("E_PRIVATE", `tab ${tabKey} lives in a private window; Hirozen never touches private windows`);
    }
    const tab = entry.tab;
    const win = entry.window;
    if (entry.loaded) {
      throw new LoaderError("E_BAD_PARAMS", `tab ${tabKey} is already loaded; zen.loadTab loads an unloaded tab (see zen.inventory's lazy flag)`);
    }
    if (tab.pinned) {
      throw new LoaderError("E_BAD_PARAMS", `tab ${tabKey} is pinned; Zen would stamp the space you are looking at onto it for good`);
    }
    if (tab.getAttribute("zen-essential") === "true") {
      throw new LoaderError("E_BAD_PARAMS", `tab ${tabKey} is essential; Zen keeps essential tabs out of every space's restore path`);
    }
    const stored = lazyTabURL(win, tab);
    if (isPrivilegedSpec(stored)) {
      throw new LoaderError("E_PRIVILEGED_PAGE", `tab ${tabKey} holds a privileged URL (${stored}); Hirozen never loads privileged pages`);
    }
    // A missing internal refuses before the prompt, like the actor check in #gate.
    this.#need(win, "gBrowser.insertBrowser");
    await this.#gate("act", req);
    this.#checkDeadline(req);
    // The load bound is measured from here, after the gate (see #zenOpen): the time a person spends on
    // the Allow/Deny notice is theirs and must not be charged to the page load.
    const started = Date.now();
    // The user's view, captured before anything is inserted: the selection and the space are restored
    // separately (a switch Zen started can land without the selection having moved).
    const previousSelected = win.gBrowser?.selectedTab ?? null;
    const userSpaceId = win.gZenWorkspaces?.activeWorkspace ?? null;
    win.gBrowser.insertBrowser(tab);
    // Zen's own restore path for a pending tab (ZenViewSplitter.activateSplitView): insert the
    // browser, then hand the tab to SessionStore with this event on the tab container - kept
    // non-bubbling exactly as Zen does, so it never reaches tabbrowser's own split-view tracking.
    win.gBrowser.tabContainer.dispatchEvent(
      new win.CustomEvent("TabSplitViewActivate", { detail: { tabs: [tab] } })
    );
    // The browser the tab now has (a pending tab's substitute properties are gone after the insert),
    // falling back to the copy collectTabs saw.
    const browser = tab.linkedBrowser ?? entry.browser;
    const bound = Math.max(1_000, NAVIGATE_TIMEOUT_MS - (Date.now() - started));
    let landed = null;
    try {
      landed = await this.#waitForLoad(tabKey, browser, {
        previous: "about:blank",
        bound,
        what: `zen.loadTab's page (tab ${tabKey}, already inserted and restored, and still usable)`,
      });
    } finally {
      // The tab exists now, so a failed load may not leave the user somewhere else.
      this.#restoreLoadedView(win, previousSelected, userSpaceId);
    }
    return { tabKey, url: landed.url, title: tab.label ?? "" };
  }

  // Puts the user's view back after a pending tab was inserted. The selection first: #restoreUserView
  // only acts on a popup it re-homed, and this tab is not one - so the space is checked here on its
  // own, with the same call Zen's own onLocationChange makes, and only ever to the space captured
  // before the insert. Both are best-effort: a Zen that refuses leaves the user where they are.
  #restoreLoadedView(win, previousSelected, userSpaceId) {
    if (previousSelected && !previousSelected.closed && win.gBrowser?.selectedTab !== previousSelected) {
      try {
        win.gBrowser.selectedTab = previousSelected;
      } catch {
        // The previous tab went away in the same breath: there is nothing left to restore.
      }
    }
    const active = win.gZenWorkspaces?.activeWorkspace;
    if (userSpaceId && active && active !== userSpaceId) {
      try {
        const space = win.gZenWorkspaces.getWorkspaceFromId?.(userSpaceId) ?? null;
        if (space) win.gZenWorkspaces.changeWorkspace?.(space);
      } catch {
        // A Zen that refuses the switch leaves the user where they are; nothing else to try here.
      }
    }
  }

  // ---------------------------------------------------------------- network (T9-T11)

  // Every network tool runs behind the `network` permission, refuses private windows through
  // #resolveTab (which is why none of them has to think about one), and reads only - no bodies, no
  // blocking, no modification. `reveal` is what turns a redacted answer into a real one, and the
  // plugin's own prompt is what guards that.

  // T9: the tab's own cookies. `getCookiesFromHost(host, originAttributes)` answers the host's cookies
  // and its registrable-domain parents' (marionette walks the host suffixes of what it returns for
  // exactly that reason), scoped to the tab's own origin attributes - containers and partitioned
  // storage included - because that is what makes it this tab's jar rather than the default one.
  async #networkCookies(params, req) {
    const { tabKey, browser } = this.#resolveTab(params?.tabKey);
    this.#need(browser.ownerGlobal ?? null, "Services.cookies");
    await this.#gate("network", req);
    this.#checkDeadline(req);
    const uri = browser.currentURI;
    const reveal = params?.reveal === true;
    const cookies = [];
    let bytes = 0;
    let truncated = false;
    for (const cookie of Services.cookies.getCookiesFromHost(String(uri.host ?? ""), browser.contentPrincipal?.originAttributes ?? {}) ?? []) {
      const value = String(cookie.value ?? "");
      const item = {
        name: String(cookie.name ?? ""),
        value: reveal ? value : `<${value.length} chars>`,
        domain: String(cookie.host ?? ""),
        path: String(cookie.path ?? ""),
        // nsICookie.expiry is milliseconds since the epoch (marionette divides by 1000 for WebDriver);
        // a session cookie has none.
        expires: cookie.isSession ? null : Number(cookie.expiry) || null,
        secure: cookie.isSecure === true,
        httpOnly: cookie.isHttpOnly === true,
        sameSite: String(cookie.sameSite ?? "unspecified"),
      };
      const size = JSON.stringify(item).length + 1;
      if (bytes + size > NET_CAP_BYTES) {
        truncated = true;
        break;
      }
      bytes += size;
      cookies.push(item);
    }
    return { tabKey, url: uri.spec, cookies, truncated };
  }

  // T9: the top document's storage. The child reads it (only the content process has the document);
  // the redaction and both caps are here, because `reveal` is a decision the loader owns. IndexedDB
  // is names only, which is what the child answers with `value: null`.
  async #networkStorage(params, req) {
    const kind = params?.kind;
    if (kind !== "local" && kind !== "session" && kind !== "indexeddb") {
      throw new LoaderError("E_BAD_PARAMS", 'browser_storage needs kind to be "local", "session" or "indexeddb"');
    }
    const { tabKey, wg } = this.#resolveTab(params?.tabKey);
    await this.#gate("network", req);
    this.#checkDeadline(req);
    const reply = await this.#query(wg, "storage", { kind });
    const reveal = params?.reveal === true;
    const entries = [];
    let bytes = 0;
    let truncated = reply?.truncated === true;
    for (const entry of Array.isArray(reply?.entries) ? reply.entries : []) {
      const value = entry?.value === null || entry?.value === undefined ? null : String(entry.value);
      let shown = null;
      if (value !== null) {
        if (!reveal) {
          shown = `<${value.length} chars>`;
        } else if (value.length > STORAGE_VALUE_CHARS) {
          shown = value.slice(0, STORAGE_VALUE_CHARS);
          truncated = true;
        } else {
          shown = value;
        }
      }
      const item = { key: String(entry?.key ?? ""), value: shown };
      const size = JSON.stringify(item).length + 1;
      if (bytes + size > NET_CAP_BYTES) {
        truncated = true;
        break;
      }
      bytes += size;
      entries.push(item);
    }
    return { tabKey, url: reply?.url ?? "", kind, entries, truncated };
  }

  #emit(name, data) {
    this.#client?.send({ type: "event", name, data });
  }
}

// A sendQuery that dies because the document went away is a stale ref for `act` (the element the ref
// came from is in the old document) and a read failure for everything else (plan: the E_REF_STALE /
// E_READ_FAILED split by method). Anything else is a read failure with the real message.
function actorFailure(e, name, kind) {
  const text = String(e?.message ?? e);
  const stale = e?.name === "AbortError" || /aborted|actor is dead|destroyed|no longer exists|invalid state/i.test(text);
  if (stale) {
    return new LoaderError(kind === "act" ? "E_REF_STALE" : "E_READ_FAILED", `${name} could not be delivered to the page: ${text}`);
  }
  return new LoaderError("E_READ_FAILED", `${name} failed: ${text}`);
}

// The loader's own waits (navigate polling, the agent space element): they must run on the module's
// timer so the harness can cancel them with every other loader timer.
function pageSleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export const HirozenLoader = new Loader();
