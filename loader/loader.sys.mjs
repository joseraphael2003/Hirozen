// Hirozen loader: dormant chrome-scope module inside Zen's parent process.
//
// It never listens on a port. It polls the profile for a one-shot omp handoff file, connects OUT to
// omp, proves a shared nonce with HMAC, and from then on serves one omp session: inventory/spaces come
// from chrome scope, reads, snapshot, screenshots and page input run through the Hirozen JSWindowActor
// this module registers (V2: no port 9222, no Firefox prompt), Zen layout through the window's gZen*,
// and WebDriver BiDi is started on demand for the two features actors cannot provide (file uploads,
// page dialogs) - see .sisyphus/plans/hirozen-v2.md.
//
// V2 consent gate (§8.2): the actor path has no Firefox prompt, so this loader owns an in-Zen
// Allow/Deny notice per link (state `#consent`, default Deny, persistent while connected) before any
// gated method runs, and omp keeps its per-action approval on top.
//
// Wire & status contract (.sisyphus/plans/hirozen-v1.md, hirozen-v1.1.md, hirozen-v2.md, shared with
// the omp side in src/link.ts):
//   request {id, method, params, deadline?}; success {id, result}; error {id, error: {code, message}};
//   loader events {type: "event", name, data}. Status file: hirozen-status.json. `deadline` is omp's
//   absolute epoch-ms budget for the request: the loader refuses with E_DEADLINE before it acts once
//   that moment has passed (a missing/non-finite deadline means no check).
//   loader->omp heartbeat {type: "ping", t}; omp->loader {type: "pong", t}, dropped before #handle.
//   Close codes: 1000 done, 4002 pre-auth message, 4003 auth failed, 4010 stopped by user,
//   4011 remote control turned off in Zen (sticky), 4012 heartbeat timeout (not sticky).
//
// Every Gecko/Zen API used here was checked against the shipped Zen 1.22.3b (Gecko 156.0.1) sources:
//  - RemoteAgent.sys.mjs: running / isDynamicStartRunning / isBrowserAutomationRunning / server /
//    startAtRuntime / stopAtRuntime, and MOZ_REMOTE_ALLOW_SYSTEM_ACCESS read in its constructor.
//    #stop() swallows httpd errors ("this function must never fail"), so a resolved stopAtRuntime()
//    is not proof the agent stopped; #stopBidi re-checks running.
//  - WebDriverBiDi.sys.mjs createSession: the SessionNotCreatedError texts classified below. Its
//    stop() deletes the session and closes every sessionless connection (shipped L296-310);
//    shared/webdriver/Session.sys.mjs destroy() (L303-320) closes the session's WebSocket
//    connections - this is why Firefox's own buttons surface here as a BiDi onClose.
//  - browser/components/remotecontrol/RemoteControlBanner.sys.mjs: the buttons are "Disconnect"
//    (connected banner), "Turn off remote control" and "Disable remote control permanently". All
//    three run #stopServers -> RemoteControlServers.stop() -> RemoteAgent.stopAtRuntime(), and only
//    Disable writes remote.experimental.dynamicstart.enabled=false, which it does *before* stopping.
//  - httpd.sys.mjs: server._connections; stop() waits for every connection whose request had started.
//  - NavigableManager.sys.mjs getIdForBrowser: one stable uuid per browser.permanentKey.
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
  RemoteAgent: "chrome://remote/content/components/RemoteAgent.sys.mjs",
  PrivateBrowsingUtils: "resource://gre/modules/PrivateBrowsingUtils.sys.mjs",
  NavigableManager: "chrome://remote/content/shared/NavigableManager.sys.mjs",
});

const LOADER_VERSION = "1";
const STATUS_VERSION = 1;
const HANDOFF_FILE = "hirozen-handoff.json";
const STATUS_FILE = "hirozen-status.json";
const POLL_MS = 2_000;
const AUTH_TIMEOUT_MS = 10_000;
const SESSION_END_TIMEOUT_MS = 5_000;
const STOP_TIMEOUT_MS = 10_000;
const STOP_SETTLE_TIMEOUT_MS = 5_000;
const STOP_SETTLE_POLL_MS = 100;
const HEARTBEAT_PING_MS = 5_000;
const HEARTBEAT_REAP_MS = 1_000;
const HEARTBEAT_TIMEOUT_MS = 15_000;
const BIDI_PORT = 9222;
const BIDI_URL = `ws://127.0.0.1:${BIDI_PORT}/session`;
const ACTOR_NAME = "Hirozen";
const ACTOR_TIMEOUT_MS = 10_000;
const ONDEMAND_BIDI_TIMEOUT_MS = 10_000; // upload/dialog commands: the V1 60 s #call default is too long
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
const DEFERRED_CLOSE_MS = 5_000; // an external stop closes even if replies are still owed
const XHTML_NS = "http://www.w3.org/1999/xhtml";
// The only privileged pages a navigate may leave: an empty tab has no content to protect, and the
// agent needs to reach the web from one (plan: navigate's exemption from E_PRIVILEGED_PAGE).
const ABOUT_NAVIGABLE = ["about:blank", "about:newtab", "about:home"];

// Prefs: the dynamic-start switch Firefox's own remote-control UI drives, and the Hirozen-owned
// memory of "Disable remote control permanently" (set on that reason, cleared only when the user
// puts dynamicstart back to true - see #startBidi).
const PREF_DYNAMIC_START = "remote.experimental.dynamicstart.enabled";
const PREF_DISABLED_BY_USER = "hirozen.remotecontrol.disabledByUser";
// Firefox gates the content-process File constructor on this pref (windowglobal/input.sys.mjs
// createFromFileName), and RemoteAgent only sets it through RecommendedPreferences - which this loader
// refuses to apply (isBrowserAutomation:false). It is flipped for the input.setFiles command alone.
const PREF_CREATE_IN_CHILD = "dom.file.createInChild";

// Close codes (contract): 1000 done, 4002 pre-auth message, 4003 auth failed, 4010 stopped by user,
// 4011 remote control turned off in Zen (sticky, after owed replies), 4012 heartbeat timeout.
const CLOSE_DONE = 1000;
const CLOSE_PROTO = 4002;
const CLOSE_AUTH = 4003;
const CLOSE_STOPPED = 4010;
const CLOSE_REMOTE_OFF = 4011;
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

// Opens an outgoing WebSocket from chrome scope (same pattern as PushServiceWebSocket).
// The origin is left empty: the Remote Agent accepts a missing Origin header but rejects any Origin
// that is not allow-listed, including an empty one (WebSocketHandshake.sys.mjs).
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

// Binds 127.0.0.1:9222 exactly the way RemoteAgent's httpd does; a busy port would make
// startAtRuntime's listener give up and force-quit Zen (RemoteAgent #listen catch -> quit(69)).
function bidiPortFree() {
  const s = Cc["@mozilla.org/network/server-socket;1"].createInstance(Ci.nsIServerSocket);
  try {
    s.init(BIDI_PORT, true, -1);
    return true;
  } catch {
    return false;
  } finally {
    try {
      s.close();
    } catch {
      // Closing a socket that never bound is a no-op failure; the bind result is what matters.
    }
  }
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
    spec.startsWith("about:") ||
    spec.startsWith("chrome:") ||
    spec.startsWith("resource:") ||
    browser.documentContentType === "application/pdf" ||
    browser.isSyntheticDocument ||
    browser.contentPrincipal?.spec === "resource://pdf.js/web/viewer.html"
  );
}

const SESSION_NEW_PARAMS = {
  // "ignore" keeps Zen's own prompt handling untouched: the default behaviour auto-dismisses alerts
  // in the user's tabs (UserPromptHandler.sys.mjs).
  capabilities: { alwaysMatch: { unhandledPromptBehavior: { default: "ignore" } } },
};

class Loader {
  #started = false;
  #loaderSha256 = null;
  #childSha256 = null;
  #parentSha256 = null;
  #actorError = null; // {code, message, at}: the actor did not register, so no gated method may run
  #client = null; // authenticated omp connection
  #handshakeInFlight = false; // an outgoing connection attempt is in progress
  #tearingDown = false; // a teardown is stopping BiDi; #poll must leave any new handoff to it
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
    updated: null,
    lastHandoff: null,
    bidi: { state: "off" },
    consent: "none",
    consentPending: null,
    actorError: null,
    lastClose: null,
    lastStartError: null,
    lastStopError: null,
  };
  #bidi = null; // loader-owned BiDi socket
  #bidiPending = new Map();
  #bidiNextId = 1;
  #bidiPort = null;
  #bidiSessionId = null;
  #startPromise = null; // single-flight BiDi start
  #stopPromise = null; // single-flight BiDi stop; concurrent callers share the first one
  #abandoned = false; // omp dropped while a consent prompt was still pending
  #lastStopError = null; // our own stop failed; the next start retries once instead of blaming a rogue client
  #prefSetByUs = false; // true only while remote.experimental.dynamicstart.enabled is ours to reset
  #externalStop = null; // Firefox turned remote control off; read by the pending start's catch
  #deferredClose = null; // {ws, reason, starting, stopping}: the 4011 close owes this connection replies
  #pingTimer = null; // heartbeat ping interval, live only while #client is set
  #reapTimer = null; // heartbeat reap interval
  #lastInbound = 0; // last frame (JSON) heard from omp; pongs included
  #noticeState = null; // {generation, text, warning, buttons} of the notice currently shown
  #noticeBase = null; // {text, warning, buttons}: the base notice a BiDi line is appended to
  #noticeLine = null; // {text, warning}: the BiDi start/stop line, never a replacement (plan)
  #noticeObserver = null; // browser-delayed-startup-finished observer while a notice is up
  #consent = { scope: null, pending: null }; // per link; created on auth, cleared in #teardown
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
    // until it is fixed (plan: actorError is separate from lastStartError, which BiDi clears).
    this.#registerActor();
    this.#writeStatus({
      state: "dormant",
      mode,
      zenPid: Services.appinfo.processID,
      loaderSha256: this.#loaderSha256,
      childSha256: this.#childSha256,
      parentSha256: this.#parentSha256,
      actorError: this.#actorError,
      bidi: { state: "off" },
      consent: "none",
      consentPending: null,
      lastClose: null,
      lastStopError: null,
    });
    this.#schedulePoll();
    return "started";
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
    // One owner at a time: no new handoff while our own handshake is still in flight (a second
    // connection would fight the first one for the single BiDi session), and none while a teardown is
    // still stopping BiDi - the handoff file waits (or expires) until the teardown's trailing
    // "dormant" status write is done, so that write cannot clobber the fresh session.
    if (this.#client || this.#handshakeInFlight || this.#tearingDown) return;
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
  // so a later #setNoticeLine cannot bring a dead link's notice back.
  #hideNotice() {
    this.#noticeBase = null;
    this.#noticeLine = null;
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

  // The BiDi lifecycle (starting / running / refused) is a second line under whatever the base notice
  // is: while the consent scope is act, the act notice - with the Stop button the user needs - must
  // never be replaced by a line about uploads (plan: "appended as a second line of the act notice").
  #setNoticeLine(text, warning = false) {
    this.#noticeLine = text ? { text, warning } : null;
    if (this.#noticeBase) this.#renderNotice();
  }

  #renderNotice() {
    this.#closeNotice();
    if (!this.#noticeBase) return;
    const line = this.#noticeLine;
    const state = {
      generation: this.#noticeGen,
      text: line ? `${this.#noticeBase.text}\n${line.text}` : this.#noticeBase.text,
      warning: this.#noticeBase.warning || (line?.warning ?? false),
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
  // and with it the only Stop button - while the session and Firefox's prompt are still up.
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
    // Shown before any Firefox prompt, so the user can correlate the dialog with a terminal process.
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
            ws.pendingReplies = 0;
            // A fresh authenticated connection clears the abandoned flag and joins the pending start:
            // the consent prompt stays open until the user answers it, so it can still be adopted.
            this.#abandoned = false;
            // The consent state belongs to this link and is never inherited: the previous link's grant
            // dies with it, so the user's Allow is asked for again (plan §8.2).
            this.#consent = { scope: null, pending: null };
            this.#startHeartbeat();
            this.#showNotice(`Hirozen: ${this.#who()} is connected. Stop ends the session.`);
            this.#writeStatus({ state: "connected", consent: "none", consentPending: null, lastClose: null });
            ws.send({
              type: "ready",
              loaderVersion: LOADER_VERSION,
              loaderSha256: this.#loaderSha256,
              childSha256: this.#childSha256,
              parentSha256: this.#parentSha256,
              zenVersion: Services.appinfo.version,
              platformVersion: Services.appinfo.platformVersion,
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
        ws.pendingReplies++;
        this.#handle(msg).then(
          result => ws.send({ id: msg.id, result }),
          e => ws.send({
            id: msg.id,
            // Every failure path throws a LoaderError; anything else is a loader bug, reported as
            // E_INTERNAL with its real message.
            error: { code: e instanceof LoaderError ? e.code : "E_INTERNAL", message: `${e instanceof LoaderError ? "" : "internal error: "}${e?.message ?? e}` },
          })
        ).finally(() => {
          ws.pendingReplies--;
          // The 4011 close armed by an external stop owes this connection its replies: it waits here,
          // after the send, until the count is back to 0 (and only ever closes the current link).
          const deferred = this.#deferredClose;
          if (deferred?.ws === ws && this.#client === ws && ws.pendingReplies === 0) {
            this.#disconnect(deferred.reason, CLOSE_REMOTE_OFF, { notice: true, starting: deferred.starting, stopping: deferred.stopping });
          }
        });
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

  // Closes the omp link and runs the teardown, which is returned so a caller can act when the state
  // really settled. `stopping` joins an external path's stop instead of running a second one; `notice`
  // is for the external path, whose sticky notice may only appear once the teardown is done.
  #disconnect(reason, code, { notice = false, starting = false, stopping = null } = {}) {
    this.#stopHeartbeat();
    this.#clearDeferredClose();
    const ws = this.#client;
    const done = this.#teardown(reason, { stopping });
    ws?.close(code, reason);
    if (notice) done.then(() => this.#showRemoteOffNotice(reason, starting));
    return done;
  }

  // Drops the deferred 4011 close and its 5 s guard timer, if one is armed.
  #clearDeferredClose() {
    const deferred = this.#deferredClose;
    this.#deferredClose = null;
    if (deferred?.timer) clearTimeout(deferred.timer);
  }

  // The one notice that survives its teardown (user decision 2026-09-28): the link is gone, so there
  // is no Stop button, and the user has to run /hirozen-connect in omp to allow control again. It is
  // shown without a ✕ and stays - in every window, including windows opened later - until the next
  // authenticated connect replaces it or Zen restarts.
  #showRemoteOffNotice(reason, starting) {
    if (this.#client) return; // a new link took over while the teardown was finishing
    const text =
      `Hirozen: remote control was turned off in Zen (${reason}). Run /hirozen-connect in omp to allow it again.` +
      (starting ? " Zen's remote-control dialog may still be open; you can Deny it." : "");
    this.#showNotice(text, { warning: true, stopButton: false });
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

  // Runs whenever the omp connection ends, however it ends: BiDi must not outlive its owner.
  async #teardown(reason, { stopping = null } = {}) {
    this.#client = null;
    // Held until the trailing status write: while it is set, #poll leaves a new handoff in the profile
    // instead of accepting a session whose status this teardown would immediately overwrite.
    this.#tearingDown = true;
    this.#clearDeferredClose();
    // The link is gone: a pending gate has nobody to answer to, its waiters must not hang, and the
    // grant itself dies here (a new link asks again).
    this.#clearConsent({ rejectPending: new LoaderError("E_STOPPED", "the omp link closed while the Allow/Deny notice was up") });
    this.#clearTabOpenWatchers();
    try {
      this.#writeStatus({ state: "stopping", consent: "none", consentPending: null, lastClose: reason });
      if (this.#startPromise) {
        // A consent prompt is still pending. Gecko's confirmEx cannot be dismissed from code, and
        // stopAtRuntime never waits for createSession (RemoteAgent #stop), so the start may stay pending
        // without blocking our teardown: it is marked abandoned and cleaned up when the user answers.
        this.#abandoned = true;
      } else {
        // #stopBidi records its own failure in the status file; teardown has nothing left to report.
        // An external stop that is already on its way is joined, never duplicated: a second
        // stopAtRuntime() would race the first one's httpd teardown.
        await (stopping ?? this.#stopBidi(reason)).catch(() => {});
      }
      this.#hideNotice();
      this.#writeStatus({ state: "dormant", consent: "none", consentPending: null });
    } finally {
      this.#tearingDown = false;
    }
  }

  // Clears the gate: a pending Allow/Deny notice is cancelled (its waiters get `rejectPending`), the
  // notice returns to the pre-prompt state (or is dropped entirely when the link is going away), and
  // the granted scope is either reset (link teardown) or left alone (prompt cancelled on its own).
  #clearConsent({ rejectPending, resetScope = false } = {}) {
    const pending = this.#consent.pending;
    if (pending) {
      clearTimeout(pending.timer);
      this.#consent.pending = null;
      pending.reject(rejectPending ?? new LoaderError("E_DENIED", "the Allow/Deny notice was cancelled"));
    }
    if (resetScope) this.#consent.scope = null;
  }

  async #handle(msg) {
    // An external stop already armed the deferred 4011 close: nothing new may start on this link
    // (plan: "#handle rejects new requests with E_STOPPED").
    if (this.#deferredClose) {
      throw new LoaderError("E_STOPPED", "remote control was turned off in Zen; the session is ending");
    }
    const params = msg.params ?? {};
    // Per-request budget: frames run concurrently, so the deadline travels with the call, not in a
    // field. Checkpoint 1 of the plan: the entry check, before any prompt. `bidi.stop` is exempt - it
    // is the way out, and refusing to stop because a budget passed would be worse than the delay.
    const req = { deadline: Number.isFinite(msg.deadline) ? msg.deadline : null };
    if (msg.method !== "bidi.stop") this.#checkDeadline(req);
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
      case "bidi.stop":
        return this.#stopBidi("omp requested");
      default:
        throw new LoaderError("E_UNKNOWN_METHOD", `unknown method ${msg.method}`);
    }
  }

  // The plan's checkpoint (1)-(4): a request whose absolute deadline passed must not act. The caller
  // checks it again after the gate (2), after #ensureBidi (3) and immediately before each side effect
  // (4); a missing/non-finite deadline means no check at all (V1 callers send none).
  #checkDeadline(req) {
    if (!req || !Number.isFinite(req.deadline)) return;
    if (Date.now() >= req.deadline) {
      throw new LoaderError("E_DEADLINE", "omp's budget for this call passed before anything was done; nothing was changed and the call can be retried");
    }
  }

  // ---------------------------------------------------------------- consent gate (§8.2)

  // Order of strength: null < "read" < "act". A granted act covers read.
  #scopeCovers(granted, needed) {
    if (granted === "act") return true;
    return granted === "read" && needed === "read";
  }

  #consentVerb(scope) {
    return scope === "act" ? "read and act on pages" : "read pages";
  }

  // Body of the gate call: the actor must be registered (a broken install refuses loudly, and no
  // prompt is shown for a feature that cannot work), then the current scope decides whether the user
  // has to be asked. Joined calls wait on the one pending promise, so one answer settles them all.
  async #gate(scope, req) {
    if (this.#actorError) {
      throw new LoaderError("E_ACTOR", `Hirozen's actor is not registered in Zen (${this.#actorError.message}); reinstall or fix the loader and restart Zen`);
    }
    if (this.#scopeCovers(this.#consent.scope, scope)) return;
    let pending = this.#consent.pending;
    if (pending) {
      if (scope === "act" && pending.scope === "read") this.#upgradePrompt(pending);
      await pending.promise;
      return;
    }
    const { promise, resolve, reject } = Promise.withResolvers();
    pending = { scope, promise, resolve, reject, timer: null };
    this.#consent.pending = pending;
    // 120 s is the plan's bound: no answer is a Deny (not sticky - the next call asks again). The
    // timer is real (the loader has no clock of its own), and never restarted by an upgrade.
    pending.timer = setTimeout(() => this.#settleConsent(pending, { granted: false, timedOut: true }), GATE_TIMEOUT_MS);
    this.#writeStatus({ consentPending: pending.scope });
    this.#emit("consent.pending", { scope: pending.scope });
    this.#showConsentNotice();
    await promise;
  }

  // An act call arriving while a read prompt is up upgrades the prompt in place: same notice, same
  // waiter, same 120 s timer - one answer settles both.
  #upgradePrompt(pending) {
    if (pending.scope === "act") return;
    pending.scope = "act";
    this.#writeStatus({ consentPending: "act" });
    this.#emit("consent.pending", { scope: "act" });
    this.#showConsentNotice();
  }

  // Allow: the scope is granted to every waiter, the status is written before the event (plan: the
  // status file must never contradict the terminal hint), and the notice becomes the persistent
  // connected notice with the granted scope.
  #settleConsent(pending, { granted, timedOut = false }) {
    if (this.#consent.pending !== pending) return;
    clearTimeout(pending.timer);
    this.#consent.pending = null;
    const scope = pending.scope;
    if (granted) {
      this.#consent.scope = scope;
      this.#writeStatus({ consent: scope, consentPending: null });
      this.#emit("consent.granted", { scope });
      this.#showConsentNotice();
      pending.resolve({ scope });
      return;
    }
    // Deny or timeout: the scope goes back to what it was, so the notice returns to the one shown
    // before the prompt, and the next call asks again.
    this.#writeStatus({ consent: this.#consent.scope ?? "none", consentPending: null });
    this.#emit("consent.denied", { scope });
    this.#showConsentNotice();
    pending.reject(new LoaderError("E_DENIED", timedOut
      ? "the Allow/Deny notice in Zen was not answered within 120 s; the next call asks again"
      : "the Allow/Deny notice in Zen was denied; the next call asks again"));
  }

  // The gate notice: the prompt while an answer is owed, the V1 connected notice plus the granted
  // scope otherwise. Private windows stay excluded, as for every notice.
  #showConsentNotice() {
    const pending = this.#consent.pending;
    if (pending) {
      const scope = pending.scope;
      this.#showNotice(`Hirozen: ${this.#who()} wants to ${this.#consentVerb(scope)} in Zen.`, {
        buttons: [
          { label: "Allow", callback: () => { this.#settleConsent(pending, { granted: true }); return false; } },
          { label: "Deny", callback: () => { this.#settleConsent(pending, { granted: false }); return false; } },
        ],
      });
      return;
    }
    const suffix = this.#consent.scope ? ` - Hirozen can ${this.#consentVerb(this.#consent.scope)}` : "";
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
  // #resolveTarget; the WebDriver context id is no longer resolved here (only upload/dialog need it,
  // and only after BiDi started).
  #resolveTab(tabKey, { forScreenshot = false, allowAbout = false } = {}) {
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
    // reason, not because it is lazy. Deviation 3 narrows the rule: a tab in the agent space stays
    // reachable while that space is inactive (reads, snapshot, input), but a screenshot of a hidden
    // tab is still refused - there is nothing on screen to draw.
    if (!this.#isInActiveSpace(entry)) {
      const inAgentSpace = !!this.#agentSpaceIdOf(entry.window) && entry.tab.getAttribute("zen-workspace-id") === this.#agentSpaceIdOf(entry.window);
      const exempt = inAgentSpace && (!forScreenshot || !entry.tab.hidden);
      if (!exempt) {
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
  // on a confirm() trigger, an alert during a load. BiDi would answer userPromptOpened; with no BiDi
  // running the loader races the same moment through the `common-dialog-loaded` observer and answers
  // {ok:true, dialog:{type, message}}, so omp learns why the page stopped and can call browser_dialog.
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

  async #read(params, req) {
    const { tabKey, wg } = this.#resolveTab(params?.tabKey);
    await this.#gate("read", req);
    this.#checkDeadline(req);
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

  // The screenshot path BiDi used (captureScreenshot = currentWindowGlobal.drawSnapshot) moved into
  // the parent, exactly as the S4 spike ran it: the actor measures the visual viewport, drawSnapshot
  // returns an ImageBitmap, and a chrome canvas turns it into the same PNG byte-for-byte.
  async #screenshot(params, req) {
    const { tabKey, tab, browser, wg } = this.#resolveTab(params?.tabKey, { forScreenshot: true });
    await this.#gate("read", req);
    this.#checkDeadline(req);
    const vp = await this.#query(wg, "viewport", {});
    const win = browser.ownerGlobal ?? tab.ownerDocument?.defaultView ?? null;
    if (!win) {
      throw new LoaderError("E_READ_FAILED", `browser.screenshot could not find the window that owns tab ${tabKey}`);
    }
    const scale = browser.browsingContext?.overrideDPPX || win.devicePixelRatio || 1;
    const rect = new win.DOMRect(vp.x, vp.y, vp.width, vp.height);
    const snapshot = await wg.drawSnapshot(rect, scale, "rgb(255,255,255)");
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
    const ACTIONS = ["click", "type", "press", "scroll", "navigate"];
    if (typeof action !== "string" || !ACTIONS.includes(action)) {
      throw new LoaderError("E_BAD_PARAMS", `browser.act needs action to be one of ${ACTIONS.join(", ")}`);
    }
    if (action === "click" && (typeof ref !== "string" || !ref)) {
      throw new LoaderError("E_BAD_PARAMS", "browser.act click needs a ref from browser_snapshot");
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

    const { tabKey, tab, browser, wg } = this.#resolveTab(params?.tabKey);
    await this.#gate("act", req);
    this.#checkDeadline(req);
    const watcher = this.#watchAgentTabOpens(tab, browser);
    const payload = { action, ref, text, key, dy };
    // Checkpoint 4: nothing may reach the page once omp gave up (the actor call is the side effect).
    this.#checkDeadline(req);
    const reply = await this.#queryAct(wg, payload, browser);
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
    try {
      scheme = Services.io.newURI(url).scheme;
    } catch {
      scheme = null;
    }
    if (scheme !== "http" && scheme !== "https") {
      throw new LoaderError("E_BAD_PARAMS", "browser.act navigate accepts http(s) URLs only");
    }
    const { tabKey, tab, browser } = this.#resolveTab(params?.tabKey, { allowAbout: true });
    await this.#gate("act", req);
    this.#checkDeadline(req);
    const watcher = this.#watchAgentTabOpens(tab, browser);
    const before = browser.currentURI.spec;
    const dialog = this.#dialogRace(browser);
    const started = Date.now();
    try {
      this.#checkDeadline(req);
      browser.fixupAndLoadURIString(url, { triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal() });
      for (;;) {
        const spec = browser.currentURI.spec;
        if (browser.webProgress?.isLoadingDocument !== true && spec !== before) {
          return { ok: true, tabKey, url: spec, title: tab.label ?? "", opened: await this.#collectOpened(watcher) };
        }
        if (Date.now() - started > NAVIGATE_TIMEOUT_MS) {
          throw new LoaderError("E_TIMEOUT", `browser.act navigate waited ${NAVIGATE_TIMEOUT_MS} ms for tab ${tabKey} to load ${url}`);
        }
        // A page that answers with a dialog instead of loading (beforeunload, an alert during load):
        // the same race act uses, so omp gets the dialog facts rather than a timeout.
        const winner = await Promise.race([
          pageSleep(NAVIGATE_POLL_MS),
          dialog.promise.then(info => ({ info })),
        ]);
        if (winner?.info) {
          return { ok: true, tabKey, dialog: winner.info, opened: await this.#collectOpened(watcher) };
        }
      }
    } finally {
      dialog.cancel();
    }
  }

  // File uploads are one of the two BiDi-on-demand features (the actor cannot set files on an input
  // without a file picker). mark/unmark bracket the work so the node can be located by attribute and
  // nothing is left in the DOM afterwards (plan: "no DOM attributes left behind").
  async #upload(params, req) {
    const ref = params?.ref;
    const paths = params?.paths;
    if (typeof ref !== "string" || !ref) {
      throw new LoaderError("E_BAD_PARAMS", "browser.upload needs a ref from browser_snapshot");
    }
    if (!Array.isArray(paths) || paths.length === 0 || paths.some(path => !isAbsolutePath(path))) {
      throw new LoaderError("E_BAD_PARAMS", "browser.upload needs paths as a non-empty array of absolute file paths");
    }
    const { tabKey, browser, wg } = this.#resolveTab(params?.tabKey);
    await this.#gate("act", req);
    this.#checkDeadline(req);
    await this.#ensureBidi();
    this.#checkDeadline(req);
    const contextId = lazy.NavigableManager.getIdForBrowser(browser);
    if (!contextId) {
      throw new LoaderError("E_TAB_UNKNOWN", `tab ${tabKey} has no WebDriver context id`);
    }
    // Per call and selector-safe (hex): the attribute is what locateNodes looks for, and the child
    // compares the value it was given, so a stale attribute from a crashed call can never match.
    const nonce = randomHex(8);
    await this.#query(wg, "mark", { ref, nonce });
    try {
      const located = await this.#bidiCall("browsingContext.locateNodes", {
        context: contextId,
        locator: { type: "css", value: `[data-hirozen-upload="${nonce}"]` },
      }, "upload");
      const element = { sharedId: located?.nodes?.[0]?.sharedId };
      if (!element.sharedId) {
        throw new LoaderError("E_REF_STALE", `the element ref is gone from tab ${tabKey}; take a fresh browser_snapshot`);
      }
      this.#checkDeadline(req);
      await this.#withCreateInChild(() => this.#bidiCall("input.setFiles", { context: contextId, element, files: paths }, "upload"));
      return { ok: true, tabKey, files: paths };
    } finally {
      // The attribute must never survive the call, whatever happened (plan: mark/unmark in finally).
      await this.#query(wg, "unmark", { nonce }).catch(() => {});
    }
  }

  // input.setFiles builds its File objects in the content process, which Firefox refuses unless
  // dom.file.createInChild is set - the pref RemoteAgent would have applied through its
  // RecommendedPreferences, and the one thing this loader must never do (isBrowserAutomation:false is
  // what keeps navigator.webdriver false and the automation prefs out of the profile). So the pref is
  // raised for the setFiles command alone and put back exactly as it was: a user value is restored to
  // that value, and no user value is cleared again. ChromeOnly API, so no page gains anything.
  async #withCreateInChild(command) {
    const hadUserValue = Services.prefs.prefHasUserValue(PREF_CREATE_IN_CHILD);
    const previous = hadUserValue ? Services.prefs.getBoolPref(PREF_CREATE_IN_CHILD, false) : false;
    Services.prefs.setBoolPref(PREF_CREATE_IN_CHILD, true);
    try {
      return await command();
    } finally {
      if (hadUserValue) Services.prefs.setBoolPref(PREF_CREATE_IN_CHILD, previous);
      else Services.prefs.clearUserPref(PREF_CREATE_IN_CHILD);
    }
  }

  async #dialog(params, req) {
    const accept = params?.accept;
    const text = params?.text;
    if (typeof accept !== "boolean") {
      throw new LoaderError("E_BAD_PARAMS", "browser.dialog needs accept as a boolean");
    }
    if (text !== undefined && typeof text !== "string") {
      throw new LoaderError("E_BAD_PARAMS", "browser.dialog accepts text as a string only");
    }
    const { tabKey, browser } = this.#resolveTab(params?.tabKey);
    await this.#gate("act", req);
    this.#checkDeadline(req);
    await this.#ensureBidi();
    this.#checkDeadline(req);
    const contextId = lazy.NavigableManager.getIdForBrowser(browser);
    if (!contextId) {
      throw new LoaderError("E_TAB_UNKNOWN", `tab ${tabKey} has no WebDriver context id`);
    }
    const command = { context: contextId, accept };
    if (typeof text === "string") command.userText = text;
    this.#checkDeadline(req);
    await this.#bidiCall("browsingContext.handleUserPrompt", command, "dialog");
    return { ok: true, tabKey, accept };
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
      box = { win, states: [], handler: null };
      box.handler = event => this.#onAgentTabOpen(box, event);
      win.addEventListener("TabOpen", box.handler, true);
      this.#tabOpenWatchers.set(win, box);
    }
    const state = {
      agentTab: tab,
      spaceId,
      previousSelected: win.gBrowser?.selectedTab ?? null,
      openedTabs: [], // the tab elements a popup created; keys are resolved once the grace is over
      done: null,
      finish: null,
      timer: null,
    };
    state.done = new Promise(resolve => { state.finish = resolve; });
    state.timer = setTimeout(() => this.#unwatchAgentTabOpens(win, box, state), TAB_OPEN_GRACE_MS);
    box.states.push(state);
    return state;
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
    if (opened.selected && state.previousSelected && !state.previousSelected.closed) {
      try {
        win.gBrowser.selectedTab = state.previousSelected;
      } catch {
        // The previous tab went away in the same breath: there is nothing to restore.
      }
    }
    state.openedTabs.push(opened);
  }

  // Waits out the 1 s grace so a popup that only reaches the parent after the actor answered is still
  // re-homed and reported, then returns the tab keys that were opened by the acted-on tab.
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
    const index = box.states.indexOf(state);
    if (index >= 0) box.states.splice(index, 1);
    state.finish();
    if (!box.states.length) {
      try {
        win.removeEventListener("TabOpen", box.handler, true);
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
    const spaceId = await this.#ensureAgentSpace(win);
    await this.#waitForSpaceElement(win, spaceId);
    this.#checkDeadline(req);
    const tab = win.gBrowser.addTab(url, {
      triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
      inBackground: true,
    });
    win.gZenWorkspaces.moveTabToWorkspace(tab, spaceId);
    return { tabKey: await this.#waitForTabKey(tab), spaceId };
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


  // would make the second bind fail and force-quit Zen. The promise is also where the failure is
  // persisted for /hirozen-status: every refusal code (#refuseStart) and every start failure lands
  // here, and a session that did start clears the record.
  async #ensureBidi() {
    if (this.#bidi && this.#bidiSessionId) {
      return { port: this.#bidiPort, sessionId: this.#bidiSessionId };
    }
    if (!this.#startPromise) {
      this.#startPromise = this.#startBidi().then(
        result => {
          // A start that reached a session proves the agent is ours and running cleanly: both failure
          // records of earlier attempts are stale now (same rule for #lastStopError, so a transient
          // concurrent-stop record cannot outlive the session that followed it).
          this.#lastStopError = null;
          this.#writeStatus({ lastStartError: null, lastStopError: null });
          return result;
        },
        e => {
          // A non-LoaderError here is a loader bug (or an unexpected Gecko throw): E_INTERNAL, with
          // its real message, is the only honest code for it.
          const failure = e instanceof LoaderError ? e : new LoaderError("E_INTERNAL", String(e?.message ?? e));
          this.#writeStatus({ lastStartError: { code: failure.code, message: failure.message, at: new Date().toISOString() } });
          throw failure;
        }
      ).finally(() => { this.#startPromise = null; });
    } else {
      // Joining a start that is already pending: a consent dialog may still be waiting for an answer,
      // so the caller waits for that, not for a second session.
      this.#emit("bidi.starting", {});
    }
    return this.#startPromise;
  }

  // A start that never produced a session still has to leave the status file and the event stream in a
  // state omp can trust: BiDi is off and omp sees phase "off" (not a stuck "starting"). The
  // dynamic-start pref is released only if this loader set it (V1.1 deviation 3): a `true` left by a
  // crashed Zen run, or one the user set in about:config, is not Hirozen's to clear.
  #refuseStart(code, message) {
    this.#releasePref();
    this.#writeStatus({ bidi: { state: "off" } });
    this.#emit("bidi.off", { reason: code });
    return new LoaderError(code, message);
  }

  // The loader owns remote.experimental.dynamicstart.enabled only while #prefSetByUs is set: Firefox's
  // own banner, a crashed run or the user may have set it, and Hirozen must never write over a value
  // it did not write. Never touches hirozen.remotecontrol.disabledByUser.
  #releasePref() {
    if (!this.#prefSetByUs) return;
    Services.prefs.setBoolPref(PREF_DYNAMIC_START, false);
    this.#prefSetByUs = false;
  }

  async #startBidi() {
    // Per-attempt state: a new start drops the deferred 4011 close of a previous episode (and its
    // guard timer), and clears the external-stop reason (it is only ever read by the catch of the
    // start that saw it).
    this.#clearDeferredClose();
    this.#externalStop = null;
    this.#writeStatus({ bidi: { state: "starting" } });
    this.#emit("bidi.starting", {});
    const RA = lazy.RemoteAgent;

    // "Disable remote control permanently" in Zen writes dynamicstart.enabled=false before stopping
    // the servers (RemoteControlBanner #stopServers), so that pref alone cannot tell a user's decision
    // from a crashed run. The Hirozen-owned flag remembers it; the only way out is the user setting the
    // pref back to true in about:config - this loader writes true just below and #releasePref only
    // writes false for its own write, so a `true` while the flag is set can only be the user's.
    if (Services.prefs.getBoolPref(PREF_DISABLED_BY_USER, false)) {
      if (Services.prefs.getBoolPref(PREF_DYNAMIC_START, false)) {
        Services.prefs.setBoolPref(PREF_DISABLED_BY_USER, false);
      } else {
        throw this.#refuseStart(
          "E_DISABLED_IN_ZEN",
          "remote control was disabled permanently in Zen; re-enable `remote.experimental.dynamicstart.enabled` in about:config to use browser_* again"
        );
      }
    }

    // Chrome-scope access is granted by the environment Zen was launched from, not by this module
    // (RemoteAgent reads the variable in its constructor): never open a session in that configuration.
    if (Services.env.exists("MOZ_REMOTE_ALLOW_SYSTEM_ACCESS")) {
      throw this.#refuseStart("E_SYSTEM_ACCESS", "MOZ_REMOTE_ALLOW_SYSTEM_ACCESS is set for this Zen process; refusing to open a remote-control session");
    }

    // A stop that is still in flight - Firefox's own banner stop of an episode this loader adopted,
    // or a previous link's teardown - leaves RA.running true for its whole duration (RemoteAgent #stop
    // is async; #stopBidiNow bounds the wait). Joining it here, before the rogue check, is what keeps a
    // /hirozen-connect landing inside that window from blaming a client for our own stop: once it
    // settles, this start sees a stopped agent - or, if the stop failed, #lastStopError and the retry
    // arm below. An agent still running after the shared stop had its chance stays E_COMPROMISE.
    if (this.#stopPromise) await this.#stopPromise.catch(() => {});
    if (RA.running) {
      if (this.#lastStopError) {
        // Our own previous stop failed, so this half-stopped agent is ours: retry the bounded stop once
        // instead of blaming a rogue client. The retry records its own outcome in the status file.
        await this.#stopBidi("retry after a failed stop").catch(() => {});
        if (RA.running) {
          throw this.#refuseStart("E_UNSAFE_START", `Remote Agent is still running after a stop retry: ${this.#lastStopError}`);
        }
      } else {
        // Another client reached the agent first: its session would receive everything we send, and
        // only one session is possible anyway (doc §4.2 rogue-client race).
        await this.#stopBidi("Remote Agent was already running").catch(() => {});
        // The act notice stays the base (with Stop); the compromise is its warning line, and the
        // catch below replaces this text with the refusal's own line.
        this.#setNoticeLine("Hirozen: Zen's remote agent was already running under another client and was stopped. If you did not expect that, check what else is connecting to Zen.", true);
        throw this.#refuseStart("E_COMPROMISE", "Remote Agent was already running before Hirozen started; another client may have been controlling Zen");
      }
    }

    // Port not bindable => startAtRuntime's listener would force-quit Zen, so refuse before touching the
    // agent. A Windows-reserved range (Hyper-V/WinNAT/WSL) refuses the bind just like a listener does.
    if (!bidiPortFree()) {
      throw this.#refuseStart(
        "E_PORT_BUSY",
        "127.0.0.1:9222 cannot be bound (in use or reserved by Windows: check `netsh int ipv4 show excludedportrange protocol=tcp`); refusing to start. zen.* keeps working."
      );
    }

    Services.prefs.setBoolPref("remote.prefs.recommended", false);
    Services.prefs.setBoolPref(PREF_DYNAMIC_START, true);
    // From here the pref is the loader's to reset (see #releasePref): teardown and refusals must not
    // write over a value the user set themselves.
    this.#prefSetByUs = true;
    try {
      const port = await RA.startAtRuntime({ isBrowserAutomation: false });
      // Post-start assertions: automation mode would set navigator.webdriver and skip the consent
      // prompt, and automation-recommended prefs crash Zen on input, so both must be absent.
      const applied = Services.prefs.prefHasUserValue("remote.prefs.recommended.applied");
      if (port !== BIDI_PORT || !RA.isDynamicStartRunning || RA.isBrowserAutomationRunning || applied) {
        throw new LoaderError("E_UNSAFE_START", `unsafe BiDi start: port=${port} dynamic=${RA.isDynamicStartRunning} automation=${RA.isBrowserAutomationRunning} recommendedPrefsApplied=${applied}`);
      }
      await this.#openBidiSocket();
      // The act notice stays the base (it carries Stop and the granted scope); the BiDi lifecycle is
      // a second line under it, never a replacement (plan §8.2).
      this.#setNoticeLine('Hirozen: answer Zen\'s "Allow remote control?" dialog to let uploads and page dialogs work.');
      // No timer here: Gecko's consent dialog cannot be dismissed from code, so a bound would only
      // strand the start while the dialog (and the agent) stayed up. This stays joinable until answered.
      const session = await this.#bidiCommand("session.new", SESSION_NEW_PARAMS, Infinity);
      this.#bidiSessionId = session.sessionId;
      this.#bidiPort = port;
      if (this.#abandoned) {
        // Late consent: omp is gone, so this session has no owner. Cleanup, not a compromise.
        throw new LoaderError("E_STOPPED", "the consent dialog was answered after omp disconnected; the session was ended");
      }
      if (this.#externalStop) {
        // Firefox's own stop landed between the session reply and this continuation: the session is
        // not ours to report as running (the external path already stopped BiDi and wrote the status).
        throw new LoaderError("E_STOPPED", `remote control was turned off in Zen (${this.#externalStop})`);
      }
      this.#writeStatus({ bidi: { state: "running", port, sessionId: session.sessionId } });
      this.#emit("bidi.running", { port, sessionId: session.sessionId });
      // Consent was granted: the "answer the dialog" line must not survive on screen. The act notice
      // beneath it stays - the user keeps its Stop button.
      this.#setNoticeLine("Hirozen: remote control is on for uploads and page dialogs.");
      return { port, sessionId: session.sessionId };
    } catch (e) {
      // Firefox's own stop already ran the external-stop path: it stopped BiDi through the shared
      // single-flight stop, wrote bidi off / lastClose and shows the sticky notice when the teardown
      // settles. This catch reports that outcome - never E_BIDI_LOST - and adds no notice of its own.
      this.#setNoticeLine(null);
      if (this.#externalStop) {
        throw e instanceof LoaderError ? e : new LoaderError("E_STOPPED", `remote control was turned off in Zen (${this.#externalStop})`);
      }
      // E_INTERNAL for whatever the specific classifiers cannot name: a startAtRuntime rejection and
      // every other unclassified start failure (an unsafe start and a deny keep their own codes).
      const failure = e instanceof LoaderError ? e : classifySessionNewError(e) ?? new LoaderError("E_INTERNAL", String(e?.message ?? e));
      // Only a line while omp is still there: an abandoned start already had its notice removed by
      // teardown, and re-adding one would leave a Stop button on a dead link.
      const connected = this.#client !== null;
      if (failure.code === "E_COMPROMISE") {
        // A fresh WebDriverBiDi is created per startAtRuntime and the in-progress flag is set by our own
        // call, so a max-sessions failure has no legitimate cause: someone else holds a session.
        await this.#stopBidi("session refused: another session is active").catch(() => {});
        if (connected) this.#setNoticeLine("Hirozen: Zen refused a remote-control session because another session is already active. The remote agent was stopped; Hirozen has no remote control.", true);
      } else {
        await this.#stopBidi("BiDi start failed").catch(() => {});
        if (connected) {
          // The prompt settled (Deny) or the start died: either way the dialog is no longer the task.
          this.#setNoticeLine(
            failure.code === "E_DENIED"
              ? 'Hirozen: the "Allow remote control?" prompt was denied in Zen - uploads and page dialogs are unavailable.'
              : `Hirozen: remote control could not start (${failure.code}) - uploads and page dialogs are unavailable.`,
            failure.code !== "E_DENIED"
          );
        }
      }
      throw failure;
    }
  }

  #openBidiSocket() {
    const { promise, resolve, reject } = Promise.withResolvers();
    // Per-socket record (external-stop step 0): #bidi is reassigned on every start, so the
    // self-stop discriminator has to travel with the socket it describes. `opened` is only true once
    // Gecko's WebSocket handshake finished; `selfClosing` is set by our own #stopBidi before it closes.
    const record = { opened: false, selfClosing: false };
    const ws = openWebSocket(BIDI_URL, {
      onOpen: () => {
        record.opened = true;
        resolve();
      },
      onMessage: raw => {
        let msg;
        try {
          msg = JSON.parse(raw);
        } catch {
          return; // a malformed frame from our own local session is dropped
        }
        if (typeof msg.id === "number" && this.#bidiPending.has(msg.id)) {
          const pending = this.#bidiPending.get(msg.id);
          this.#bidiPending.delete(msg.id);
          if (msg.type === "error") pending.reject(new Error(`${msg.error}: ${msg.message}`));
          else pending.resolve(msg.result);
        }
        // BiDi events are deliberately not forwarded: V1 exposes no getTree/event passthrough, so no
        // context (private or otherwise) can leak to omp through this socket.
      },
      onClose: (code, reason) => {
        const socketClosed = `BiDi socket closed ${code} ${reason}`;
        // External-stop detection (step 0) before #bidi is nulled below: only a socket that completed
        // its handshake, was not closed by our own stop, and is still the current one can have been
        // closed by Firefox itself. Firefox's buttons never touch our state, so this is the only
        // signal - and the pref cannot stand in (our own reset runs after the close).
        const external = this.#bidi === ws && !record.selfClosing && record.opened;
        // The reason is read before pending commands are rejected (step 1): only Disable writes this
        // pref, and RemoteControlBanner writes it before stopping, so `false` here is that user
        // decision while `true` can only be a Disconnect / Turn-off.
        const externalReason = external
          ? Services.prefs.getBoolPref(PREF_DYNAMIC_START, false) ? "external disconnect" : "disabled permanently"
          : null;
        // Pending commands: a socket we lost to Firefox is E_BIDI_LOST, one our own stop closed (or one
        // a newer socket superseded) is E_STOPPED, and a pending session.new carries the user's reason
        // so the start catch reports the sticky outcome instead of a lost socket.
        for (const pending of this.#bidiPending.values()) {
          if (external && pending.method === "session.new") {
            pending.reject(new LoaderError("E_STOPPED", `remote control was turned off in Zen (${externalReason})`));
          } else if (external) {
            pending.reject(new LoaderError("E_BIDI_LOST", socketClosed));
          } else {
            pending.reject(new LoaderError("E_STOPPED", socketClosed));
          }
        }
        this.#bidiPending.clear();
        if (this.#bidi === ws) {
          this.#bidi = null;
          this.#bidiSessionId = null;
          this.#bidiPort = null;
        }
        // A socket that never opened is a failed start, which the start catch reports as E_BIDI_LOST
        // (step 2); our own stop keeps E_STOPPED. No-op once the socket has opened.
        reject(record.selfClosing ? new LoaderError("E_STOPPED", socketClosed) : new LoaderError("E_BIDI_LOST", socketClosed));
        if (external) this.#onExternalStop(externalReason);
      },
    });
    ws.record = record;
    this.#bidi = ws;
    return promise;
  }

  // Firefox stopped remote control itself (Disconnect / Turn off remote control / Disable remote
  // control permanently: RemoteControlBanner #stopServers -> RemoteControlServers.stop ->
  // RemoteAgent.stopAtRuntime, which closes this socket). Steps 2-4 of the external-stop path; the
  // listener's own stopAtRuntime either hangs (our upgraded connection keeps httpd busy, doc §6.6) or
  // lands here first, so the loader's stop is what completes it.
  #onExternalStop(reason) {
    this.#externalStop = reason; // read by the pending start's catch; cleared by the next start
    const starting = this.#startPromise !== null;
    // Only Disable writes dynamicstart.enabled=false before stopping, so the reason is what turns the
    // user's decision into a sticky memory a later start refuses against.
    if (reason === "disabled permanently") Services.prefs.setBoolPref(PREF_DISABLED_BY_USER, true);
    // The session is over: a pending Allow/Deny notice is taken down and its waiters are told
    // (plan: "a pending gate prompt is removed and its waiters get E_STOPPED"). The scope itself is
    // cleared by the teardown that follows.
    this.#clearConsent({ rejectPending: new LoaderError("E_STOPPED", `remote control was turned off in Zen (${reason})`) });
    this.#showConsentNotice();
    // Step 3: the socket is already gone, so the shared stop skips session.end and goes straight to
    // stopAtRuntime(); the stop is handed to the teardown below so it is never run twice. Its rejection
    // is handled here (a failed stop is recorded in the status file, not thrown at the socket close).
    const stopping = this.#stopBidi(reason).catch(() => {});
    // Step 4: if omp is gone there is no link to close and nobody to tell; a connection that still owes
    // replies gets its 4011 close only after the last reply (see the reply chain in #connect) - and at
    // most DEFERRED_CLOSE_MS later, even if that reply never comes.
    const ws = this.#client;
    if (!ws) return;
    if (ws.pendingReplies === 0) {
      this.#disconnect(reason, CLOSE_REMOTE_OFF, { notice: true, starting, stopping });
    } else {
      const deferred = { ws, reason, starting, stopping, timer: null };
      deferred.timer = setTimeout(() => {
        if (this.#deferredClose !== deferred || this.#client !== ws) return;
        this.#disconnect(reason, CLOSE_REMOTE_OFF, { notice: true, starting, stopping });
      }, DEFERRED_CLOSE_MS);
      this.#deferredClose = deferred;
    }
  }

  // Every caller names its own bound: Infinity for session.new (Gecko's consent dialog cannot be
  // dismissed from code), 5 s for session.end, the on-demand 10 s for upload/dialog.
  #bidiCommand(method, params, timeoutMs) {
    if (!this.#bidi) return Promise.reject(new LoaderError("E_BIDI_LOST", "BiDi session is not running"));
    const id = this.#bidiNextId++;
    const { promise, resolve, reject } = Promise.withResolvers();
    let timer = null;
    const settle = {
      method,
      resolve: value => { clearTimeout(timer); resolve(value); },
      reject: error => { clearTimeout(timer); reject(error); },
    };
    if (timeoutMs !== Infinity) {
      timer = setTimeout(() => {
        this.#bidiPending.delete(id);
        reject(new LoaderError("E_TIMEOUT", `${method} did not answer within ${timeoutMs} ms`));
      }, timeoutMs);
    }
    this.#bidiPending.set(id, settle);
    this.#bidi.send({ id, method, params });
    return promise;
  }

  // The on-demand BiDi commands (upload/dialog) are bounded at 10 s, not V1's 60 s #call default:
  // they run while the user is waiting for a tool result, and the plan names E_TIMEOUT for them.
  #bidiCall(method, params, kind) {
    return this.#bidiCommand(method, params, ONDEMAND_BIDI_TIMEOUT_MS).catch(e => {
      throw classifyOnDemandFailure(e, kind);
    });
  }

  // Single-flight stop (V1.1): the start catch, the external path, the teardown and bidi.stop all
  // share one #stopPromise. Concurrent callers must never run stopAtRuntime() twice - the second call
  // would race the first one's httpd teardown - and a shared outcome cannot contradict itself.
  #stopBidi(reason) {
    if (!this.#stopPromise) {
      this.#stopPromise = this.#stopBidiNow(reason).finally(() => { this.#stopPromise = null; });
    }
    return this.#stopPromise;
  }

  async #stopBidiNow(reason) {
    const RA = lazy.RemoteAgent;
    let forceClosed = 0;
    const ws = this.#bidi;
    try {
      if (ws) {
        // Self-stop discriminator (external-stop step 0): set before the close, so this socket's
        // onClose cannot mistake our own stop for Firefox's. #bidi is nulled before the close too, so a
        // handler that runs synchronously inside close() finds a socket that is not the current one.
        ws.record.selfClosing = true;
        if (!ws.closed) {
          // Best effort: the session may already be gone (that is often why we are stopping).
          await this.#bidiCommand("session.end", {}, SESSION_END_TIMEOUT_MS).catch(() => {});
        }
        this.#bidi = null;
        this.#bidiSessionId = null;
        this.#bidiPort = null;
        ws.close(CLOSE_DONE, "loader stop");
      }
      if (RA.running) {
        // Remote Agent bug: a rejected WebSocket handshake leaves its connection in httpd forever, and
        // stop() waits for it (httpd L451-470). Close the leftovers, then bound the wait.
        for (const conn of Object.values(RA.server?._connections ?? {})) {
          try {
            conn.close();
            forceClosed++;
          } catch {
            // A connection that died on its own is one less leftover to worry about.
          }
        }
        const { promise: timedOut, resolve: onTimeout } = Promise.withResolvers();
        const timer = setTimeout(() => onTimeout("stopAtRuntime did not finish within 10 s"), STOP_TIMEOUT_MS);
        // A rejected stopAtRuntime is a failed stop too: record it so the next start retries instead of
        // treating the half-stopped agent as another client's.
        const rejected = await Promise.race([
          RA.stopAtRuntime().then(() => null, e => `stopAtRuntime failed: ${String(e?.message ?? e)}`),
          timedOut,
        ]);
        clearTimeout(timer);
        // RemoteAgent #stop swallows httpd errors ("this function must never fail", L429-437), so a
        // resolved stopAtRuntime() is no proof the agent is gone; an agent that is still running is a
        // failed stop as well. Recording it is what stops the next start from blaming a rogue client
        // (the retry path reads #lastStopError) instead of raising a false E_COMPROMISE.
        //
        // "Still running" is not failure by itself, though: Firefox's own banner stop (Disconnect /
        // Turn off / Disable) calls stopAtRuntime() first and is already inside #stop() when our
        // socket closes and we call stop too. There the second httpd stop() throws - its _socket is
        // already null (httpd L606-614) - and #stop's catch swallows it, so OUR call resolves early
        // while #server is still up and running (= !!#server && !#server.isStopped(), L142-144) stays
        // true until that stop finishes asynchronously. So give an in-flight stop a bounded chance to
        // settle before calling it a failure.
        const failure = rejected ?? (RA.running ? await this.#waitForStopSettle() : null);
        if (failure) {
          this.#lastStopError = failure;
          this.#writeStatus({ lastStopError: failure });
          throw new LoaderError("E_STOP_FAILED", failure);
        }
      }
      this.#lastStopError = null;
      this.#writeStatus({ bidi: { state: "off" }, lastStopError: null });
      this.#emit("bidi.off", { reason });
      return { stopped: true, forceClosed };
    } finally {
      // Released only if this loader set it (V1.1 deviation 3): a `true` the user set survives, while a
      // half-stopped agent can no longer leave the pref true for the next start.
      this.#releasePref();
    }
  }

  // Waits, bounded, for a stop that was already in progress elsewhere (Firefox's own banner stop) to
  // finish, so a concurrent stop is not recorded as our failure. Returns null as soon as the agent is
  // gone, or the reason it still is not.
  async #waitForStopSettle() {
    const deadline = Date.now() + STOP_SETTLE_TIMEOUT_MS;
    while (lazy.RemoteAgent.running) {
      if (Date.now() >= deadline) return "stopAtRuntime resolved but Remote Agent is still running";
      await new Promise(resolve => setTimeout(resolve, STOP_SETTLE_POLL_MS));
    }
    return null;
  }

  #emit(name, data) {
    this.#client?.send({ type: "event", name, data });
  }
}

// Gecko throws SessionNotCreatedError with these exact texts (WebDriverBiDi.sys.mjs createSession):
//   "The connection was denied by the user" / "Maximum number of active sessions[...]".
// Not a compromise: the user pressed Deny. Compromise: another client owns the session.
function classifySessionNewError(e) {
  const text = String(e?.message ?? e);
  if (/denied by the user/i.test(text)) return new LoaderError("E_DENIED", text);
  if (/Maximum number of active sessions/i.test(text)) return new LoaderError("E_COMPROMISE", text);
  return null;
}

// BiDi answers errors as {error: "<protocol error>", message: "<detail>"}, which #bidiCommand turns
// into "<error>: <detail>". Only upload and dialog reach BiDi now, and the plan names the two mappings
// they need: a node that went away is a stale ref (the page navigated after mark), and a file input
// that cannot take these files is not interactable. Everything else stays E_INTERNAL - the honest code
// for a protocol error neither the loader nor the plan can classify. A LoaderError (the socket-close
// codes included) passes through unchanged.
function classifyOnDemandFailure(e, kind) {
  if (e instanceof LoaderError) return e;
  const text = `${kind} failed: ${String(e?.message ?? e)}`;
  if (kind === "upload" && /no such node|no such element|no such frame|no such (window|context)/i.test(text)) {
    return new LoaderError("E_REF_STALE", text);
  }
  if (kind === "upload" && /unable to set file input/i.test(text)) {
    return new LoaderError("E_NOT_INTERACTABLE", text);
  }
  // Gecko's UnsupportedOperationError for a path it cannot turn into a File (it vanished, or the
  // plugin's existence check raced the call): the params are the problem, not the element.
  if (kind === "upload" && /failed to add file/i.test(text)) {
    return new LoaderError("E_BAD_PARAMS", text);
  }
  if (kind === "dialog" && /no such alert/i.test(text)) {
    return new LoaderError("E_NO_DIALOG", text);
  }
  return new LoaderError("E_INTERNAL", text);
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
