// Hirozen loader: dormant chrome-scope module inside Zen's parent process.
//
// It never listens on a port. It polls the profile for a one-shot omp handoff file, connects OUT to
// omp, proves a shared nonce with HMAC, and from then on is Zen's only WebDriver BiDi client.
// V1 is read-only: inventory/spaces come from chrome scope, browser.read/screenshot go through BiDi.
//
// Wire & status contract (.sisyphus/plans/hirozen-v1.md, shared with the omp side in src/link.ts):
//   request {id, method, params}; success {id, result}; error {id, error: {code, message}};
//   loader events {type: "event", name, data}. Status file: hirozen-status.json.
//
// Every Gecko/Zen API used here was checked against the shipped Zen 1.22.3b (Gecko 156.0.1) sources:
//  - RemoteAgent.sys.mjs: running / isDynamicStartRunning / isBrowserAutomationRunning / server /
//    startAtRuntime / stopAtRuntime, and MOZ_REMOTE_ALLOW_SYSTEM_ACCESS read in its constructor.
//  - WebDriverBiDi.sys.mjs createSession: the SessionNotCreatedError texts classified below.
//  - httpd.sys.mjs: server._connections; stop() waits for every connection whose request had started.
//  - NavigableManager.sys.mjs getIdForBrowser: one stable uuid per browser.permanentKey.
//  - modules/zen/ZenSpaceManager.mjs: allStoredTabs / getWorkspaces / activeWorkspace; a tab's
//    zen-workspace-id is absent on pinned/essential tabs; modules/zen/ZenWindowSync.sys.mjs sets
//    tab.id on every tab, private windows included.
import { setTimeout, clearTimeout } from "resource://gre/modules/Timer.sys.mjs";

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
const BIDI_COMMAND_TIMEOUT_MS = 60_000;
const SESSION_END_TIMEOUT_MS = 5_000;
const STOP_TIMEOUT_MS = 10_000;
const BIDI_PORT = 9222;
const BIDI_URL = `ws://127.0.0.1:${BIDI_PORT}/session`;
const SANDBOX = "hirozen";
const TEXT_CAP = 40_000;

// Close codes (contract): 1000 done, 4002 pre-auth message, 4003 auth failed, 4010 stopped by user.
const CLOSE_DONE = 1000;
const CLOSE_PROTO = 4002;
const CLOSE_AUTH = 4003;
const CLOSE_STOPPED = 4010;

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

// Runs in the page, in the "hirozen" BiDi sandbox realm, and returns a JSON string so the result
// crosses the protocol as a single string value.
const READ_FUNCTION = `() => {
  const body = document.body;
  const full = body ? body.innerText : "";
  const cap = ${TEXT_CAP};
  const omitted = full.length - cap;
  const text = omitted > 0 ? full.slice(0, cap) + "\\n\\n[hirozen: truncated - " + omitted + " more characters]" : full;
  return JSON.stringify({ url: document.location.href, title: document.title, text, truncated: omitted > 0 });
}`;

const SESSION_NEW_PARAMS = {
  // "ignore" keeps Zen's own prompt handling untouched: the default behaviour auto-dismisses alerts
  // in the user's tabs (UserPromptHandler.sys.mjs).
  capabilities: { alwaysMatch: { unhandledPromptBehavior: { default: "ignore" } } },
};

class Loader {
  #started = false;
  #loaderSha256 = null;
  #client = null; // authenticated omp connection
  #handshakeInFlight = false; // an outgoing connection attempt is in progress
  #notices = new Set(); // the live Hirozen notification, one per open non-private window
  #noticeGen = 0; // bumped on every close, so an append still in flight cannot revive itself
  #status = {
    version: STATUS_VERSION,
    loaderSha256: null,
    zenPid: null,
    state: "dormant",
    mode: null,
    updated: null,
    lastHandoff: null,
    bidi: { state: "off" },
    lastClose: null,
    lastStopError: null,
  };
  #bidi = null; // loader-owned BiDi socket
  #bidiPending = new Map();
  #bidiNextId = 1;
  #bidiPort = null;
  #bidiSessionId = null;
  #startPromise = null; // single-flight BiDi start
  #abandoned = false; // omp dropped while a consent prompt was still pending
  #lastStopError = null; // our own stop failed; the next start retries once instead of blaming a rogue client

  init(mode, sha256) {
    if (this.#started) return "already-started";
    if (mode !== "startup" && mode !== "attach") {
      throw new Error(`HirozenLoader.init: unknown mode ${mode}`);
    }
    this.#started = true;
    this.#loaderSha256 = typeof sha256 === "string" ? sha256 : null;
    this.#writeStatus({
      state: "dormant",
      mode,
      zenPid: Services.appinfo.processID,
      loaderSha256: this.#loaderSha256,
      bidi: { state: "off" },
      lastClose: null,
      lastStopError: null,
    });
    this.#schedulePoll();
    return "started";
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
    // One owner at a time, and no new handoff while our own handshake is still in flight
    // (a second connection would fight the first one for the single BiDi session).
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

  #closeNotice() {
    this.#noticeGen++;
    for (const notification of this.#notices) {
      try {
        notification.close();
      } catch {
        // Zen may have removed the notification already (window closed, user dismissed it); UI cleanup
        // must never break the connection teardown.
      }
    }
    this.#notices.clear();
  }

  // Shown in every open non-private window, each with its own Stop button: the user may be looking at
  // any of them, and Stop has to be reachable from wherever the prompt is. Windows opened later get
  // nothing (Hirozen does not watch for new windows).
  #showNotice(text, { warning = false, stopButton = true } = {}) {
    this.#closeNotice();
    const generation = this.#noticeGen;
    const buttons = stopButton
      ? [{ label: "Stop", callback: () => { this.#disconnect("stopped by user in Zen", CLOSE_STOPPED); return false; } }]
      : [];
    for (const win of browserWindows()) {
      const box = win.gNotificationBox;
      if (!box) continue;
      box.appendNotification(
        "hirozen",
        { label: text, priority: warning ? box.PRIORITY_WARNING_HIGH : box.PRIORITY_INFO_HIGH },
        buttons
      ).then(
        notification => {
          if (generation === this.#noticeGen) this.#notices.add(notification);
          else {
            try {
              notification.close(); // a newer notice (or teardown) replaced this one while it was appended
            } catch {
              // the window went away in the meantime
            }
          }
        },
        () => {} // the window went away before the notification was appended
      );
    }
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
            // A fresh authenticated connection clears the abandoned flag and joins the pending start:
            // the consent prompt stays open until the user answers it, so it can still be adopted.
            this.#abandoned = false;
            this.#showNotice(`Hirozen: ${this.#who()} is connected. Stop ends the session.`);
            this.#writeStatus({ state: "connected", lastClose: null });
            ws.send({
              type: "ready",
              loaderVersion: LOADER_VERSION,
              loaderSha256: this.#loaderSha256,
              zenVersion: Services.appinfo.version,
              platformVersion: Services.appinfo.platformVersion,
              zenPid: Services.appinfo.processID,
            });
          } else {
            ws.close(CLOSE_PROTO, "unexpected message before auth");
          }
          return;
        }
        this.#handle(msg).then(
          result => ws.send({ id: msg.id, result }),
          e => ws.send({
            id: msg.id,
            // Every failure path throws a LoaderError; anything else is a loader bug, reported with the
            // closest available code plus its real message.
            error: { code: e instanceof LoaderError ? e.code : "E_STOPPED", message: `${e instanceof LoaderError ? "" : "internal error: "}${e?.message ?? e}` },
          })
        );
      },
      onClose: (code, reason) => {
        clearTimeout(authTimer);
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

  #disconnect(reason, code) {
    const ws = this.#client;
    this.#teardown(reason);
    ws?.close(code, reason);
  }

  // Runs whenever the omp connection ends, however it ends: BiDi must not outlive its owner.
  async #teardown(reason) {
    this.#client = null;
    this.#writeStatus({ state: "stopping", lastClose: reason });
    if (this.#startPromise) {
      // A consent prompt is still pending. Gecko's confirmEx cannot be dismissed from code, and
      // stopAtRuntime never waits for createSession (RemoteAgent #stop), so the start may stay pending
      // without blocking our teardown: it is marked abandoned and cleaned up when the user answers.
      this.#abandoned = true;
    } else {
      // #stopBidi records its own failure in the status file; teardown has nothing left to report.
      await this.#stopBidi(reason).catch(() => {});
    }
    this.#closeNotice();
    this.#writeStatus({ state: "dormant" });
  }

  async #handle(msg) {
    const params = msg.params ?? {};
    switch (msg.method) {
      case "zen.inventory":
        return this.#inventory();
      case "zen.spaces":
        return browserWindows().map(windowSummary);
      case "browser.read":
        return this.#read(params);
      case "browser.screenshot":
        return this.#screenshot(params);
      case "bidi.stop":
        return this.#stopBidi("omp requested");
      default:
        throw new LoaderError("E_UNKNOWN_METHOD", `unknown method ${msg.method}`);
    }
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
  // BiDi context id for that tab, resolved fresh on every call: the ids are cleared when the last
  // session ends and follow browser.permanentKey across window-sync swaps.
  #resolveTarget(tabKey) {
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
    // Checked before the loaded state: BiDi only lists the active space, so an unloaded tab in another
    // space is unreachable for that reason, not because it is lazy.
    if (!this.#isInActiveSpace(entry)) {
      throw new LoaderError("E_TAB_INACTIVE_SPACE", `tab ${tabKey} is in an inactive space; Zen would have to switch spaces to reach it`);
    }
    if (!entry.loaded) {
      throw new LoaderError("E_TAB_UNLOADED", `tab ${tabKey} has no docshell yet; open it in Zen first (Hirozen never loads tabs)`);
    }
    if (isPrivilegedPage(entry.browser)) {
      throw new LoaderError("E_PRIVILEGED_PAGE", `tab ${tabKey} is a privileged page (${entry.browser.currentURI.spec})`);
    }
    const contextId = lazy.NavigableManager.getIdForBrowser(entry.browser);
    if (!contextId) {
      throw new LoaderError("E_TAB_UNKNOWN", `tab ${tabKey} has no WebDriver context id`);
    }
    return { tabKey, contextId };
  }

  // Pinned and essential tabs carry no zen-workspace-id and are visible from every space.
  #isInActiveSpace(entry) {
    const spaceId = entry.tab.getAttribute("zen-workspace-id");
    if (!spaceId) return true;
    return spaceId === entry.window.gZenWorkspaces?.activeWorkspace;
  }

  async #read(params) {
    const { tabKey, contextId } = this.#resolveTarget(params?.tabKey);
    await this.#ensureBidi();
    const result = await this.#call("script.callFunction", {
      functionDeclaration: READ_FUNCTION,
      target: { context: contextId, sandbox: SANDBOX },
      awaitPromise: false,
    }, "browser.read");
    // script.callFunction answers {realm, type, result: {type, value}} or {type: "exception", ...}.
    const value = result?.result?.value;
    if (typeof value !== "string") {
      const detail = result?.type === "exception"
        ? `script exception: ${result.exceptionDetails?.text ?? "unknown"}`
        : `unexpected result type ${result?.result?.type ?? result?.type ?? "none"}`;
      throw new LoaderError("E_STOPPED", `browser.read could not read tab ${tabKey}: ${detail}`);
    }
    const page = JSON.parse(value);
    return { tabKey, url: page.url, title: page.title, text: page.text, truncated: page.truncated };
  }

  async #screenshot(params) {
    const { tabKey, contextId } = this.#resolveTarget(params?.tabKey);
    await this.#ensureBidi();
    // captureScreenshot defaults to the viewport origin and the PNG format (browsingContext.sys.mjs).
    const result = await this.#call("browsingContext.captureScreenshot", { context: contextId }, "browser.screenshot");
    if (typeof result?.data !== "string" || !result.data) {
      throw new LoaderError("E_STOPPED", `captureScreenshot returned no image data for tab ${tabKey}`);
    }
    return { tabKey, mimeType: "image/png", data: result.data };
  }

  // Single-flight start: the caller assigns #startPromise synchronously, before any await, so every
  // browser.* call either starts one session or joins the one already starting. Two concurrent starts
  // would make the second bind fail and force-quit Zen.
  async #ensureBidi() {
    if (this.#bidi && this.#bidiSessionId) {
      return { port: this.#bidiPort, sessionId: this.#bidiSessionId };
    }
    if (!this.#startPromise) {
      this.#startPromise = this.#startBidi().finally(() => { this.#startPromise = null; });
    } else {
      // Joining a start that is already pending: a consent dialog may still be waiting for an answer,
      // so the caller waits for that, not for a second session.
      this.#emit("bidi.starting", {});
    }
    return this.#startPromise;
  }

  // A start that never produced a session still has to leave the status file, the event stream and the
  // dynamic-start pref in a state omp can trust: BiDi is off, omp sees phase "off" (not a stuck
  // "starting"), and a pref left true by an earlier crashed run does not survive a refusal.
  #refuseStart(code, message) {
    Services.prefs.setBoolPref("remote.experimental.dynamicstart.enabled", false);
    this.#writeStatus({ bidi: { state: "off" } });
    this.#emit("bidi.off", { reason: code });
    return new LoaderError(code, message);
  }

  async #startBidi() {
    this.#writeStatus({ bidi: { state: "starting" } });
    this.#emit("bidi.starting", {});
    const RA = lazy.RemoteAgent;

    // Chrome-scope access is granted by the environment Zen was launched from, not by this module
    // (RemoteAgent reads the variable in its constructor): never open a session in that configuration.
    if (Services.env.exists("MOZ_REMOTE_ALLOW_SYSTEM_ACCESS")) {
      throw this.#refuseStart("E_SYSTEM_ACCESS", "MOZ_REMOTE_ALLOW_SYSTEM_ACCESS is set for this Zen process; refusing to open a remote-control session");
    }

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
        this.#showNotice("Hirozen: Zen's remote agent was already running under another client and was stopped. If you did not expect that, check what else is connecting to Zen.", { warning: true, stopButton: false });
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
    Services.prefs.setBoolPref("remote.experimental.dynamicstart.enabled", true);
    try {
      const port = await RA.startAtRuntime({ isBrowserAutomation: false });
      // Post-start assertions: automation mode would set navigator.webdriver and skip the consent
      // prompt, and automation-recommended prefs crash Zen on input, so both must be absent.
      const applied = Services.prefs.prefHasUserValue("remote.prefs.recommended.applied");
      if (port !== BIDI_PORT || !RA.isDynamicStartRunning || RA.isBrowserAutomationRunning || applied) {
        throw new LoaderError("E_UNSAFE_START", `unsafe BiDi start: port=${port} dynamic=${RA.isDynamicStartRunning} automation=${RA.isBrowserAutomationRunning} recommendedPrefsApplied=${applied}`);
      }
      await this.#openBidiSocket();
      this.#showNotice(`Hirozen: answer Zen's "Allow remote control?" dialog to let ${this.#who()} read Zen tabs.`);
      // No timer here: Gecko's consent dialog cannot be dismissed from code, so a bound would only
      // strand the start while the dialog (and the agent) stayed up. This stays joinable until answered.
      const session = await this.#bidiCommand("session.new", SESSION_NEW_PARAMS, Infinity);
      this.#bidiSessionId = session.sessionId;
      this.#bidiPort = port;
      if (this.#abandoned) {
        // Late consent: omp is gone, so this session has no owner. Cleanup, not a compromise.
        throw new LoaderError("E_STOPPED", "the consent dialog was answered after omp disconnected; the session was ended");
      }
      this.#writeStatus({ bidi: { state: "running", port, sessionId: session.sessionId } });
      this.#emit("bidi.running", { port, sessionId: session.sessionId });
      // Consent was granted: the "answer the dialog" wording must not survive on screen.
      this.#showNotice(`Hirozen: ${this.#who()} is connected - Hirozen can read Zen tabs. Stop ends the session.`);
      return { port, sessionId: session.sessionId };
    } catch (e) {
      const failure = e instanceof LoaderError ? e : classifySessionNewError(e) ?? new LoaderError("E_STOPPED", String(e?.message ?? e));
      // Only a notice while omp is still there: an abandoned start already had its notice removed by
      // teardown, and re-adding one would leave a Stop button on a dead link.
      const connected = this.#client !== null;
      if (failure.code === "E_COMPROMISE") {
        // A fresh WebDriverBiDi is created per startAtRuntime and the in-progress flag is set by our own
        // call, so a max-sessions failure has no legitimate cause: someone else holds a session.
        await this.#stopBidi("session refused: another session is active").catch(() => {});
        if (connected) this.#showNotice("Hirozen: Zen refused a remote-control session because another session is already active. The remote agent was stopped; Hirozen has no control.", { warning: true, stopButton: false });
      } else {
        await this.#stopBidi("BiDi start failed").catch(() => {});
        if (connected) {
          // The prompt settled (Deny) or the start died: either way the dialog is no longer the task.
          this.#showNotice(
            failure.code === "E_DENIED"
              ? 'Hirozen: the "Allow remote control?" prompt was denied in Zen - Hirozen has no control of Zen. Stop ends the session.'
              : `Hirozen: remote control could not start (${failure.code}) - Hirozen has no control of Zen. Stop ends the session.`
          );
        }
      }
      throw failure;
    }
  }

  #openBidiSocket() {
    const { promise, resolve, reject } = Promise.withResolvers();
    const ws = openWebSocket(BIDI_URL, {
      onOpen: () => resolve(),
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
        for (const pending of this.#bidiPending.values()) pending.reject(new Error(`BiDi socket closed ${code} ${reason}`));
        this.#bidiPending.clear();
        if (this.#bidi === ws) {
          this.#bidi = null;
          this.#bidiSessionId = null;
          this.#bidiPort = null;
        }
        reject(new Error(`BiDi socket closed ${code} ${reason}`)); // no-op once the socket has opened
      },
    });
    this.#bidi = ws;
    return promise;
  }

  #bidiCommand(method, params, timeoutMs = BIDI_COMMAND_TIMEOUT_MS) {
    if (!this.#bidi) return Promise.reject(new LoaderError("E_STOPPED", "BiDi session is not running"));
    const id = this.#bidiNextId++;
    const { promise, resolve, reject } = Promise.withResolvers();
    let timer = null;
    const settle = {
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

  #call(method, params, label) {
    return this.#bidiCommand(method, params).catch(e => {
      throw classifyBidiFailure(e, label);
    });
  }

  async #stopBidi(reason) {
    const RA = lazy.RemoteAgent;
    let forceClosed = 0;
    if (this.#bidi) {
      // Best effort: the session may already be gone (that is often why we are stopping).
      await this.#bidiCommand("session.end", {}, SESSION_END_TIMEOUT_MS).catch(() => {});
      this.#bidi.close(CLOSE_DONE, "loader stop");
      this.#bidi = null;
      this.#bidiSessionId = null;
      this.#bidiPort = null;
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
      const failure = await Promise.race([
        RA.stopAtRuntime().then(() => null, e => `stopAtRuntime failed: ${String(e?.message ?? e)}`),
        timedOut,
      ]);
      clearTimeout(timer);
      if (failure) {
        this.#lastStopError = failure;
        this.#writeStatus({ lastStopError: failure });
        throw new LoaderError("E_STOPPED", failure);
      }
    }
    this.#lastStopError = null;
    Services.prefs.setBoolPref("remote.experimental.dynamicstart.enabled", false);
    this.#writeStatus({ bidi: { state: "off" }, lastStopError: null });
    this.#emit("bidi.off", { reason });
    return { stopped: true, forceClosed };
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
// into "<error>: <detail>".
function classifyBidiFailure(e, label) {
  if (e instanceof LoaderError) return e;
  const text = `${label} failed: ${String(e?.message ?? e)}`;
  if (/no such frame|no such node|no such (window|context)/i.test(text)) return new LoaderError("E_TAB_UNKNOWN", text);
  return new LoaderError("E_STOPPED", text);
}

export const HirozenLoader = new Loader();
