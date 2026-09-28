// One-shot attach: bootstraps the hash-pinned loader into an *already running* Zen (doc §6.2).
//
// Why: the autoconfig loader only runs at Zen startup. When the user does not want to restart, the
// plugin forwards a plain-TCP `--start-debugger-server <port>` command line to the running instance
// and evaluates loader/attach-now.js once in its parent process. The eval re-verifies the three
// module hashes, imports the loader as `init("attach", {loader, child, parent})`, saves both DevTools
// prefs back to false and closes the listener last - closing it drops this connection, so the eval's
// reply is normally lost.
//
// Safety rules enforced here:
//   * nothing is spawned unless prefs.js proves both DevTools prefs are on *and* the connection
//     prompt is still enabled: with the prefs off the forwarded command line opens a stray window;
//   * the target profile must be locked by a running Zen (parent.lock held), so the forwarded
//     `--profile` really lands in that instance instead of starting a second one;
//   * the installed loader and actor modules must match this plugin's copies (verify()) and their
//     hashes are the pins;
//   * plain TCP on 127.0.0.1 only (never `ws:`), no shell, no `\r` in the eval source;
//   * the whole operation is bounded by TIMEOUT_MS and every failure says how to close the listener.
import { randomInt } from "node:crypto";
import { closeSync, existsSync, openSync, readFileSync, rmSync } from "node:fs";
import { connect, createServer, type Socket } from "node:net";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MODULE_PLACEHOLDERS, type ModuleHashes, verify } from "./install";
import { HirozenError, readStatusFile, STATUS_FILE, type ZenStatus } from "./link";

export type AttachOptions = {
  /** Zen install directory (holds zen.exe and the installed loader). */
  zenDir: string;
  /** Exact profile directory of the running Zen; forwarded verbatim as `--profile`. */
  profileDir: string;
  /** Terminal notice (`ctx.ui.notify`): what to accept in Zen, then the local RDP client port. The
   * message is the body only - the presenter adds its own "Hirozen:" prefix, so adding one here would
   * render twice. */
  notify: (message: string) => void;
};

export type AttachResult = {
  /** Port of the one-shot DevTools listener; it is gone by the time this resolves. */
  port: number;
  mode: "attach";
  /** The confirmed loader hash from the status file, equal to the install pin. */
  loaderSha256: string;
  /** The confirmed actor child hash, equal to the install pin. */
  childSha256: string;
  /** The confirmed actor parent hash, equal to the install pin. */
  parentSha256: string;
};

const ATTACH_SCRIPT = fileURLToPath(new URL("../loader/attach-now.js", import.meta.url));
/** Whole-operation budget: the "Incoming Connection" prompt is the only slow part. */
const TIMEOUT_MS = 120_000;
const PORT_MIN = 20_000;
const PORT_MAX = 60_000;
const STATUS_POLL_MS = 200;
/** The eval's reply races the listener close; wait a little, then carry on without it. */
const EVAL_REPLY_MS = 10_000;
/** Shown on every failure after the spawn: the listener may outlive this call. */
const LISTENER_ADVICE =
  "the debugger listener may still be open; untick both DevTools settings in about:config or press Disable on the prompt";

const CHROME_ENABLED = "devtools.chrome.enabled";
const REMOTE_ENABLED = "devtools.debugger.remote-enabled";
const PROMPT_CONNECTION = "devtools.debugger.prompt-connection";

/** `user_pref("name", true);` - the last assignment wins, like Gecko's prefs parser. */
const USER_PREF = /^user_pref\("([^"\\]+)",\s*(true|false|-?\d+|"[^"]*")\);/gm;

/** PowerShell one-liner listing main-process command lines (content processes carry `contentproc`). */
const PS_ZEN_PROCESSES =
  "Get-CimInstance Win32_Process -Filter \"Name='zen.exe'\" " +
  "| Where-Object { $_.CommandLine -notmatch 'contentproc' } " +
  "| ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }";

/** One RDP packet: `JSON.parse` at the socket boundary, every field checked where it is used. */
type RdpPacket = Record<string, unknown>;

type Waiter = {
  predicate: (packet: RdpPacket) => boolean;
  /** What this wait is for; a dead socket reports it so the user knows how far the attach got. */
  what: string;
  settle: (packet: RdpPacket) => void;
  fail: (error: HirozenError) => void;
};

/** Raised when the budget runs out; the caller never gets a listener it cannot reason about. */
function rdpTimeout(what: string): HirozenError {
  return new HirozenError(
    "E_TIMEOUT",
    `attach-now timed out after ${TIMEOUT_MS / 1000} s while waiting for ${what}: ${LISTENER_ADVICE}`,
  );
}

/** Raised when the socket dies mid-handshake - normally the Cancel/Deny/Disable button. */
function rdpGone(what: string, reason: string): HirozenError {
  return new HirozenError(
    "E_TIMEOUT",
    `the RDP connection closed while waiting for ${what} (${reason}; the "Incoming Connection" prompt may ` +
      `have been cancelled, denied or disabled): ${LISTENER_ADVICE}`,
  );
}

/** Reads a dotted path of string keys, returning it only when it is a string (as in the spike). */
function str(packet: unknown, path: string): string | undefined {
  let current: unknown = packet;
  for (const key of path.split(".")) {
    if (typeof current !== "object" || current === null || !(key in current)) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === "string" ? current : undefined;
}

/** An empty path would silently resolve to the cwd; there is no default for either directory. */
function requireDir(label: string, value: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new HirozenError("E_CONFIG", `${label} is required: pass it explicitly (there is no default)`);
  }
  return resolve(value);
}

/** `process.kill(pid, 0)` as a liveness probe; EPERM (Windows) still means the process exists. */
function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Windows paths reach us quoted, with mixed separators and a trailing one: compare them canonically. */
function normalizePath(path: string): string {
  return resolve(path).replace(/[\\/]+$/, "").toLowerCase();
}

/**
 * Refusal for prefs.js, or null when the handoff is legal. Both prefs must be true (the flag handler
 * returns early otherwise and the default handler opens a new window) and the connection prompt must
 * not be false: `prompt-connection=false` makes Prompt.Server.authenticate() return ALLOW, which
 * hands chrome-level eval to any local process.
 */
function prefsRefusal(profileDir: string): string | null {
  const prefsPath = join(profileDir, "prefs.js");
  const source = existsSync(prefsPath) ? readFileSync(prefsPath, "utf8") : "";
  const prefs = new Map<string, string>();
  for (const match of source.matchAll(USER_PREF)) prefs.set(match[1], match[2]);

  if (prefs.get(PROMPT_CONNECTION) === "false") {
    return (
      `${PROMPT_CONNECTION} is false in ${prefsPath}: with the prompt off, any local process gets ` +
      `chrome-level eval on the running Zen. Set it back to true in about:config, then run /hirozen-attach again.`
    );
  }
  const missing = [REMOTE_ENABLED, CHROME_ENABLED].filter(name => prefs.get(name) !== "true");
  if (missing.length === 0) return null;
  return (
    `attach-now needs Zen's DevTools prefs first: set ${missing.join(" and ")} to true in about:config ` +
    `(DevTools Settings ticks the same two boxes), then run /hirozen-attach again. Read from ${prefsPath}; ` +
    `Hirozen never changes these prefs from outside Zen.`
  );
}

/** True when a live zen.exe process was launched with `--profile <profileDir>` (or `-profile`). */
async function zenProcessUsesProfile(profileDir: string): Promise<boolean> {
  if (process.platform !== "win32") return false;
  let output: string;
  try {
    const child = Bun.spawn({
      cmd: ["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_ZEN_PROCESSES],
      stdin: "ignore",
      stdout: "pipe",
      stderr: "ignore",
      windowsHide: true,
      timeout: 5_000,
    });
    output = await new Response(child.stdout).text();
    await child.exited;
  } catch {
    return false; // no PowerShell/CIM available: the lock file already answered
  }
  const wanted = normalizePath(profileDir);
  for (const line of output.split(/\r?\n/)) {
    const row = /^\s*\d+\s+(.*)$/.exec(line);
    if (!row) continue;
    const profile = /(?:^|\s)--?profile\s+("([^"]*)"|'([^']*)'|(\S+))/i.exec(row[1]);
    const value = profile?.[2] ?? profile?.[3] ?? profile?.[4];
    if (value && normalizePath(value) === wanted) return true;
  }
  return false;
}

/**
 * Does a running Zen own this profile?
 *
 * Primary: `<profile>/parent.lock`. Gecko opens it with share mode 0 (nsProfileLock.cpp), so while a
 * Zen runs any open from here fails with EBUSY, whatever share flags libuv passes; a profile no Zen
 * holds opens fine. Fallback: an explicit `--profile <dir>` on a live zen.exe - a launch that used
 * the default profile carries no `--profile`, so only the lock file covers that case.
 */
async function profileLocked(profileDir: string): Promise<boolean> {
  try {
    closeSync(openSync(join(profileDir, "parent.lock"), "r+"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EBUSY") return true;
    // ENOENT: never started (or cleaned up); anything else: fall through to the process list.
  }
  return zenProcessUsesProfile(profileDir);
}

/**
 * A live loader means there is nothing to attach: `init()` returns "already-started" and the status
 * file is never rewritten, so the confirmation below could only time out. A live *session* is
 * someone else's - the same single-owner rule the link enforces.
 */
function liveLoaderRefusal(profileDir: string): HirozenError | null {
  const status: ZenStatus | null = readStatusFile(profileDir);
  if (!status || typeof status.zenPid !== "number" || !pidAlive(status.zenPid)) return null;
  if (status.state === "connected" || status.state === "authenticating") {
    return new HirozenError("E_IN_USE", `Zen (pid ${status.zenPid}) is ${status.state} to another omp session`, {
      pid: status.zenPid,
    });
  }
  const mode = typeof status.mode === "string" ? status.mode : "unknown";
  return new HirozenError(
    "E_CONFIG",
    `the Hirozen loader is already running in Zen (pid ${status.zenPid}, mode ${mode}): there is nothing to ` +
      `attach - use the zen_* / browser_* tools, or /hirozen-connect if the session was stopped`,
  );
}

/** The eval source with all three install pins substituted; checked before anything is spawned. */
export function attachScript(pins: ModuleHashes): string {
  // Windows checkouts and shells leak \r into strings; the eval text is JS, so it stays LF-only.
  let source = readFileSync(ATTACH_SCRIPT, "utf8").replace(/\r\n?/g, "\n");
  for (const role of ["loader", "child", "parent"] as const) {
    const pin = pins[role];
    if (!/^[0-9a-f]{64}$/.test(pin)) {
      throw new HirozenError("E_CONFIG", `refusing to eval the attach script with a non-hex ${role} pin: ${pin}`);
    }
    const placeholder = MODULE_PLACEHOLDERS[role];
    const placeholders = source.split(placeholder).length - 1;
    if (placeholders !== 1) {
      throw new HirozenError(
        "E_CONFIG",
        `${ATTACH_SCRIPT} must contain exactly one ${placeholder} (found ${placeholders})`,
      );
    }
    source = source.replace(placeholder, pin);
  }
  return source;
}

/** A free loopback port in [PORT_MIN, PORT_MAX): Zen's listener must not lose the race to bind it. */
function pickFreePort(): Promise<number> {
  const { promise, resolve: resolvePort, reject: rejectPort } = Promise.withResolvers<number>();
  let attempts = 0;
  const tryOnce = () => {
    const port = randomInt(PORT_MIN, PORT_MAX);
    const probe = createServer();
    probe.once("error", () => {
      if (++attempts >= 20) {
        rejectPort(new HirozenError("E_CONFIG", `no free port in ${PORT_MIN}-${PORT_MAX} for the debugger listener`));
        return;
      }
      tryOnce();
    });
    probe.listen({ host: "127.0.0.1", port }, () => probe.close(() => resolvePort(port)));
  };
  tryOnce();
  return promise;
}

/** Minimal RDP client: length-prefixed JSON packets over one TCP connection (no HTTP bridge). */
class RdpClient {
  #socket: Socket;
  #deadline: number;
  #buffer = Buffer.alloc(0);
  #waiters: Waiter[] = [];
  #reason: string | null = null;

  constructor(socket: Socket, deadline: number) {
    this.#socket = socket;
    this.#deadline = deadline;
    socket.setNoDelay(true);
    // The socket never runs in string mode; the union is TypeScript's, not the runtime's.
    socket.on("data", chunk => this.#receive(typeof chunk === "string" ? Buffer.from(chunk) : chunk));
    socket.on("error", error => this.#fail(error.message));
    socket.on("close", () => this.#fail("the socket was closed"));
  }

  /** Read at call time: the socket is still connecting when the client is constructed. */
  get localPort(): number {
    return this.#socket.localPort ?? 0;
  }

  /** Retries until the listener the forwarded command line opened accepts a connection. */
  static async connect(port: number, deadline: number): Promise<RdpClient> {
    for (;;) {
      const left = deadline - Date.now();
      if (left <= 0) throw rdpTimeout(`the Zen debugger listener on 127.0.0.1:${port}`);
      const client = await RdpClient.#attempt(port, Math.min(left, 1_000), deadline);
      if (client) return client;
      const pause = deadline - Date.now();
      if (pause > 0) await Bun.sleep(Math.min(150, pause));
    }
  }

  static #attempt(port: number, budgetMs: number, deadline: number): Promise<RdpClient | null> {
    const { promise, resolve: resolveAttempt, reject: rejectAttempt } = Promise.withResolvers<RdpClient | null>();
    const socket = connect({ host: "127.0.0.1", port });
    const client = new RdpClient(socket, deadline);
    const timer = setTimeout(() => {
      socket.destroy();
      resolveAttempt(null);
    }, budgetMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      resolveAttempt(client);
    });
    socket.once("error", (error: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      if (error.code === "ECONNREFUSED") {
        socket.destroy();
        resolveAttempt(null);
        return;
      }
      rejectAttempt(
        new HirozenError("E_UNKNOWN", `cannot reach the Zen debugger listener on 127.0.0.1:${port}: ${error.message}`),
      );
    });
    return promise;
  }

  send(to: string, type: string, extra: RdpPacket = {}): void {
    const body = Buffer.from(JSON.stringify({ to, type, ...extra }));
    this.#socket.write(`${body.length}:`);
    this.#socket.write(body);
  }

  /** Resolves with the first packet matching `predicate`; bounded by `budgetMs` and the deadline. */
  wait(predicate: (packet: RdpPacket) => boolean, what: string, budgetMs?: number): Promise<RdpPacket> {
    if (this.#reason) return Promise.reject(rdpGone(what, this.#reason));
    const left = Math.min(this.#deadline - Date.now(), budgetMs ?? Number.POSITIVE_INFINITY);
    if (left <= 0) return Promise.reject(rdpTimeout(what));
    const { promise, resolve: resolveWait, reject: rejectWait } = Promise.withResolvers<RdpPacket>();
    const waiter: Waiter = {
      predicate,
      what,
      settle: packet => {
        clearTimeout(timer);
        resolveWait(packet);
      },
      fail: error => {
        clearTimeout(timer);
        rejectWait(error);
      },
    };
    const timer = setTimeout(() => {
      this.#drop(waiter);
      rejectWait(rdpTimeout(what));
    }, left);
    this.#waiters.push(waiter);
    return promise;
  }

  close(): void {
    this.#socket.destroy();
  }

  #receive(chunk: Buffer): void {
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    for (;;) {
      const colon = this.#buffer.indexOf(0x3a);
      if (colon < 0) return;
      const length = Number(this.#buffer.subarray(0, colon).toString());
      if (!Number.isInteger(length) || length <= 0) {
        this.#fail("a malformed packet header arrived");
        return;
      }
      if (this.#buffer.length < colon + 1 + length) return;
      const body = this.#buffer.subarray(colon + 1, colon + 1 + length).toString();
      this.#buffer = this.#buffer.subarray(colon + 1 + length);
      let packet: RdpPacket;
      try {
        packet = JSON.parse(body) as RdpPacket;
      } catch {
        this.#fail("a packet that is not JSON arrived");
        return;
      }
      const index = this.#waiters.findIndex(waiter => waiter.predicate(packet));
      if (index >= 0) this.#waiters.splice(index, 1)[0].settle(packet);
    }
  }

  #drop(waiter: Waiter): void {
    const index = this.#waiters.indexOf(waiter);
    if (index >= 0) this.#waiters.splice(index, 1);
  }

  #fail(reason: string): void {
    if (this.#reason) return;
    this.#reason = reason;
    for (const waiter of [...this.#waiters]) waiter.fail(rdpGone(waiter.what, reason));
    this.#waiters.length = 0;
  }
}

/** The eval returns a JSON string; a thrown eval leaves `exception`/`exceptionMessage` instead. */
function parseEvaluation(packet: RdpPacket | null): Record<string, unknown> | null {
  const value = packet?.result;
  if (typeof value !== "string") return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function describeStatus(seen: ZenStatus | null, reported: Record<string, unknown> | null): string {
  const parts: string[] = [];
  if (typeof reported?.loader === "string") parts.push(`the eval reported ${reported.loader}`);
  if (seen) {
    parts.push(`the status file shows mode=${seen.mode ?? "?"} state=${seen.state ?? "?"} updated=${seen.updated ?? "?"}`);
  }
  return parts.length > 0 ? ` (${parts.join("; ")})` : "";
}

/** Waits for the status the eval writes: mode attach, newer than the start, all three hashes === pins. */
async function waitForAttach(
  profileDir: string,
  pins: ModuleHashes,
  startMs: number,
  deadline: number,
  reported: Record<string, unknown> | null,
): Promise<ModuleHashes> {
  let seen: ZenStatus | null = null;
  for (;;) {
    const status = readStatusFile(profileDir);
    if (status) seen = status;
    if (
      status?.mode === "attach" &&
      status.loaderSha256 === pins.loader &&
      status.childSha256 === pins.child &&
      status.parentSha256 === pins.parent &&
      typeof status.updated === "string"
    ) {
      const updated = Date.parse(status.updated);
      if (Number.isFinite(updated) && updated > startMs) {
        return { loader: pins.loader, child: pins.child, parent: pins.parent };
      }
    }
    const left = deadline - Date.now();
    if (left <= 0) {
      throw new HirozenError(
        "E_TIMEOUT",
        `attach-now timed out after ${TIMEOUT_MS / 1000} s: the loader never reported mode=attach with the ` +
          `pinned hashes (was the "Incoming Connection" prompt accepted?)${describeStatus(seen, reported)}: ` +
          LISTENER_ADVICE,
      );
    }
    await Bun.sleep(Math.min(STATUS_POLL_MS, left));
  }
}

/**
 * Bootstraps the loader into the Zen that is holding `profileDir`. Resolves only once the loader's
 * status file confirms the attach; every other path throws a HirozenError whose message says how to
 * get rid of a listener that may still be open.
 */
export async function attachNow(options: AttachOptions): Promise<AttachResult> {
  const deadline = Date.now() + TIMEOUT_MS;
  const zenDir = requireDir("zenDir", options.zenDir);
  const profileDir = requireDir("profileDir", options.profileDir);
  const notify = options.notify;

  const prefsProblem = prefsRefusal(profileDir);
  if (prefsProblem) throw new HirozenError("E_CONFIG", prefsProblem);

  if (!existsSync(profileDir)) {
    throw new HirozenError("E_CONFIG", `profile directory not found: ${profileDir}`);
  }
  if (!(await profileLocked(profileDir))) {
    throw new HirozenError(
      "E_CONFIG",
      `no running Zen is holding ${profileDir}: start Zen normally first, then run /hirozen-attach again`,
    );
  }

  const zenExe = join(zenDir, "zen.exe");
  if (!existsSync(zenExe)) throw new HirozenError("E_CONFIG", `not a Zen install (no zen.exe): ${zenDir}`);
  const verified = verify(zenDir);
  if (!verified.ok || !verified.installed) {
    throw new HirozenError("E_CONFIG", `${verified.reason}; run /hirozen-install first`);
  }
  const pins = verified.installed;
  const script = attachScript(pins);

  const live = liveLoaderRefusal(profileDir);
  if (live) throw live;
  // The confirmation below only accepts a status written after this point, so a stale one must go.
  rmSync(join(profileDir, STATUS_FILE), { force: true });
  const attachStart = Date.now();

  // Forwarding needs the two DevTools prefs (checked above) and a plain-TCP flag: `ws:` has no Origin
  // or Host check and would let a web page reach chrome eval.
  const port = await pickFreePort();
  // Every check has passed and the command line is about to be forwarded: only now can the prompt
  // appear, so this is the first notice that may be shown (a refusal above sends none).
  notify(
    `attaching the loader to the running Zen: click OK on the "Incoming Connection" prompt (never ` +
      `"Disable") so this session can attach (server 127.0.0.1:${port}); Cancel aborts and leaves the loader unused.`,
  );
  Bun.spawn({
    cmd: [zenExe, "--profile", profileDir, "--start-debugger-server", String(port)],
    stdin: "ignore",
    stdout: "ignore",
    stderr: "ignore",
    windowsHide: true,
  }).unref();

  const client = await RdpClient.connect(port, deadline);
  await client.wait(packet => packet.from === "root" && "applicationType" in packet, "the DevTools greeting");
  notify(
    `connected to Zen's debugger (client 127.0.0.1:${client.localPort} -> server 127.0.0.1:${port}); ` +
      `installing the loader now - the listener closes when the eval is done.`,
  );

  client.send("root", "getProcess", { id: 0 });
  const process = await client.wait(packet => packet.from === "root", "the root process descriptor");
  const descriptor = str(process, "processDescriptor.actor");
  if (!descriptor) {
    throw new HirozenError("E_UNKNOWN", `getProcess returned no process descriptor: ${JSON.stringify(process)}`);
  }

  client.send(descriptor, "getTarget");
  const target = await client.wait(packet => packet.from === descriptor, "the parent process target");
  const consoleActor = str(target, "process.consoleActor");
  if (!consoleActor) {
    throw new HirozenError("E_UNKNOWN", `getTarget returned no console actor: ${JSON.stringify(target)}`);
  }

  client.send(consoleActor, "evaluateJSAsync", { text: script });
  const reported = await client
    .wait(
      packet => packet.from === consoleActor && packet.type === "evaluationResult",
      "the evaluation result",
      EVAL_REPLY_MS,
    )
    .then(parseEvaluation, () => null);
  client.close();

  const reportedLoader = reported?.loader;
  if (typeof reportedLoader === "string" && reportedLoader.startsWith("refused")) {
    throw new HirozenError(
      "E_STALE_LOADER",
      `the running Zen refused the loader hash (${reportedLoader}); the installed loader is not the pinned one - ` +
        `run /hirozen-install and then /hirozen-attach again`,
    );
  }

  const hashes = await waitForAttach(profileDir, pins, attachStart, deadline, reported);
  return {
    port,
    mode: "attach",
    loaderSha256: hashes.loader,
    childSha256: hashes.child,
    parentSha256: hashes.parent,
  };
}
