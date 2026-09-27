// The omp side of the Hirozen loader link: a single-use loopback WebSocket server.
//
// Flow (doc §6.4; the handshake is byte-compatible with loader/loader.sys.mjs):
//   1. connect() refuses when another session already owns the loader (E_IN_USE), then listens on
//      127.0.0.1:0 and writes hirozen-handoff.json {port, nonce, pid, cwd, expiry} into the profile.
//   2. The dormant loader polls the profile, reads + deletes the handoff, and connects OUT to /hirozen.
//   3. Handshake (HMAC key = the handoff nonce, hex):
//        omp    -> {type:"challenge", challenge}
//        loader -> {type:"auth", mac: HMAC(nonce, "loader:"+challenge), challenge: <loader's own>}
//        omp    -> {type:"auth", mac: HMAC(nonce, "omp:"+loaderChallenge)}
//        loader -> {type:"ready", loaderVersion, loaderSha256, zenVersion, platformVersion, zenPid}
//   4. Requests {id, method, params} are answered with {id, result} or {id, error: {code, message}};
//      loader events arrive as {type: "event", name, data}.
//   5. Exactly one authenticated connection: any further upgrade is closed with 4009, a pre-auth message
//      that is not auth with 4002, a bad proof with 4003, and Zen's Stop button closes with 4010.
//
// The listener is loopback-only on an ephemeral port and the handoff file is deleted on every path out
// of connect(), so a crashed session cannot leave a phantom owner behind.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Server, ServerWebSocket } from "bun";

/** One-shot handoff file the loader polls for; written by connect(), deleted after use. */
export const HANDOFF_FILE = "hirozen-handoff.json";
/** Status file the loader keeps in the profile; read here to detect another live owner. */
export const STATUS_FILE = "hirozen-status.json";

const PATH = "/hirozen";
/** The loader polls every 2 s, so the handoff must outlive a slow Zen start. */
const HANDOFF_TTL_MS = 60_000;
/** How long connect() waits for the loader's `ready` frame by default. */
const CONNECT_TIMEOUT_MS = 90_000;
/** Default per-command budget; the extension lowers it once BiDi runs (see the wire contract). */
const CALL_TIMEOUT_MS = 150_000;

/**
 * Error carrying a wire code from the loader (`{error: {code, message}}`) or a link-local one:
 * `E_AUTH` (the peer failed the loader proof / sent a pre-auth message that is not auth),
 * `E_UNKNOWN` (a reply that does not match the contract), `E_TIMEOUT`, `E_STOPPED`.
 */
export class HirozenError extends Error {
  readonly code: string;
  /** Set for E_IN_USE: the pid already holding the link (another omp, or Zen's pid). */
  readonly pid?: number;

  constructor(code: string, message: string, options: { pid?: number } = {}) {
    super(message);
    this.name = "HirozenError";
    this.code = code;
    if (options.pid !== undefined) this.pid = options.pid;
  }
}

/** The loader's `ready` frame, sent once the handshake completes. */
export type ReadyFrame = {
  type: "ready";
  loaderVersion: string;
  loaderSha256: string;
  zenVersion: string;
  platformVersion: string;
  zenPid: number;
};

/** `hirozen-handoff.json`: how the loader finds this listener. */
export type HandoffFile = {
  port: number;
  nonce: string;
  pid: number;
  cwd: string;
  expiry: number;
};

/** `hirozen-status.json` as written by the loader (every field optional: it may be read mid-write). */
export type ZenStatus = {
  version?: string;
  loaderSha256?: string;
  zenPid?: number;
  state?: "dormant" | "authenticating" | "connected" | "stopping";
  mode?: "startup" | "attach";
  updated?: string;
  lastHandoff?: { pid?: number; cwd?: string; at?: string };
  bidi?: { state?: "off" | "starting" | "running"; port?: number; sessionId?: string };
  lastClose?: string;
  lastStopError?: string;
};

export type LoaderEvent = { name: string; data?: unknown };

export type LinkCloseInfo = {
  code: number;
  reason: string;
  /** Zen's Stop button closes the link with 4010: the user ended the session. */
  stoppedByUser: boolean;
};

export type ZenLinkOptions = {
  onEvent?: (event: LoaderEvent) => void;
  onClose?: (info: LinkCloseInfo) => void;
};

export type ConnectOptions = {
  /** How long to wait for the loader's `ready` frame. Default 90 s. */
  timeoutMs?: number;
};

export type CallOptions = {
  /** Command budget. Default 150 s (the loader's own upload/start window). */
  timeoutMs?: number;
  /** Cancels the call; the loader keeps working on it (a retry joins its single-flight start). */
  signal?: AbortSignal;
};

type PendingCall = {
  /** JSON replies are untyped: call() applies the caller's T to `result`. */
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  cleanup: () => void;
};

/** A frame from the loader, narrowed field by field before use. */
type Frame = {
  type?: unknown;
  id?: unknown;
  result?: unknown;
  error?: unknown;
  name?: unknown;
  data?: unknown;
  mac?: unknown;
  challenge?: unknown;
};

/** Per-connect handshake state (the loader never re-handshakes on a live socket). */
type Session = {
  nonce: string;
  challenge: string;
  authed: boolean;
  socket: ServerWebSocket<undefined> | null;
  ready: PromiseWithResolvers<ReadyFrame>;
};

function hmacHex(key: string, message: string): string {
  return createHmac("sha256", key).update(message).digest("hex");
}

/** Constant-time mac comparison; a length (or hex validity) mismatch fails before any compare. */
function sameHex(a: string, b: string): boolean {
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  if (left.length === 0 || left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Reading a JSON file that may not exist, be mid-write or be malformed: absent is the answer.
 * The parsed shape is only claimed by the generic; every field is runtime-checked by its caller.
 */
function readJson<T>(path: string): T | null {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return null;
  }
}

export function readStatusFile(profileDir: string): ZenStatus | null {
  return readJson<ZenStatus>(join(profileDir, STATUS_FILE));
}

/** `process.kill(pid, 0)` as a liveness probe; EPERM still means the process exists. */
function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** The single-owner pre-check: another omp's unexpired handoff, or a live loader session. */
function findOwner(profileDir: string): { pid?: number; message: string } | null {
  const handoff = readJson<HandoffFile>(join(profileDir, HANDOFF_FILE));
  if (handoff && typeof handoff.expiry === "number" && handoff.expiry > Date.now()) {
    return {
      pid: handoff.pid,
      message: `another omp session (pid ${handoff.pid}) is waiting for the loader: ${HANDOFF_FILE} is unexpired`,
    };
  }
  const status = readStatusFile(profileDir);
  if (
    (status?.state === "connected" || status?.state === "authenticating") &&
    typeof status.zenPid === "number" &&
    pidAlive(status.zenPid)
  ) {
    return { pid: status.zenPid, message: `Zen (pid ${status.zenPid}) is ${status.state} to another omp session` };
  }
  return null;
}

export class ZenLink {
  /** Called for every loader event frame; set before connect() or pass via the constructor. */
  onEvent?: (event: LoaderEvent) => void;
  /** Called once when the authenticated loader connection closes (never for refused upgrades). */
  onClose?: (info: LinkCloseInfo) => void;

  #server: Server<undefined> | null = null;
  #session: Session | null = null;
  /** The connection that completed the handshake; calls are only allowed while it is set. */
  #client: ServerWebSocket<undefined> | null = null;
  #ready: ReadyFrame | null = null;
  #closing = false;
  #pending = new Map<number, PendingCall>();
  #nextId = 1;

  constructor(options: ZenLinkOptions = {}) {
    this.onEvent = options.onEvent;
    this.onClose = options.onClose;
  }

  /**
   * Offers the loader a one-shot handoff and resolves with its `ready` frame.
   * Throws E_IN_USE when another session owns the loader, E_TIMEOUT when the loader never shows up,
   * E_AUTH when the connection fails the handshake.
   */
  async connect(profileDir: string, options: ConnectOptions = {}): Promise<ReadyFrame> {
    if (this.#server) throw new HirozenError("E_IN_USE", "this ZenLink is already connected; call close() first");
    const owner = findOwner(profileDir);
    if (owner) throw new HirozenError("E_IN_USE", owner.message, { pid: owner.pid });

    const session: Session = {
      nonce: randomBytes(32).toString("hex"),
      challenge: randomBytes(32).toString("hex"),
      authed: false,
      socket: null,
      ready: Promise.withResolvers<ReadyFrame>(),
    };
    const handoffPath = join(profileDir, HANDOFF_FILE);
    let wroteHandoff = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    this.#session = session;
    this.#closing = false;
    const server = Bun.serve<undefined>({
      hostname: "127.0.0.1",
      port: 0,
      fetch: (request, srv) => {
        if (new URL(request.url).pathname === PATH && srv.upgrade(request)) return;
        return new Response("hirozen: not found", { status: 404 });
      },
      websocket: {
        open: ws => this.#accept(session, ws),
        message: (ws, raw) => this.#receive(session, ws, raw),
        close: (ws, code, reason) => this.#disconnect(session, ws, code, reason),
      },
    });
    this.#server = server;

    try {
      writeFileSync(
        handoffPath,
        JSON.stringify({
          port: server.port,
          nonce: session.nonce,
          pid: process.pid,
          cwd: process.cwd(),
          expiry: Date.now() + HANDOFF_TTL_MS,
        }),
      );
      wroteHandoff = true;
      const timeoutMs = options.timeoutMs ?? CONNECT_TIMEOUT_MS;
      timer = setTimeout(
        () =>
          session.ready.reject(
            new HirozenError("E_TIMEOUT", `the Zen loader did not connect within ${timeoutMs} ms`),
          ),
        timeoutMs,
      );
      const ready = await session.ready.promise;
      this.#ready = ready;
      return ready;
    } finally {
      clearTimeout(timer);
      // Single use: the loader deletes it too, but a failed/aborted connect must not leave it behind.
      if (wroteHandoff) rmSync(handoffPath, { force: true });
      if (!this.#ready) this.#teardown();
    }
  }

  /** Sends one request; resolves with `result` or throws the loader's `{code, message}`. */
  async call<T = unknown>(method: string, params: unknown = {}, options: CallOptions = {}): Promise<T> {
    const socket = this.#client;
    if (!socket) throw new HirozenError("E_STOPPED", "the Hirozen link is not connected");
    const signal = options.signal;
    if (signal?.aborted) throw new HirozenError("E_STOPPED", `${method} was cancelled before it was sent`);

    const timeoutMs = options.timeoutMs ?? CALL_TIMEOUT_MS;
    const id = this.#nextId++;
    const { promise, resolve, reject } = Promise.withResolvers<T>();
    const timer = setTimeout(() => {
      this.#take(id)?.reject(new HirozenError("E_TIMEOUT", `${method} timed out after ${timeoutMs} ms`));
    }, timeoutMs);
    const onAbort = () => {
      this.#take(id)?.reject(new HirozenError("E_STOPPED", `${method} was cancelled`));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    this.#pending.set(id, {
      resolve: value => resolve(value as T),
      reject,
      timer,
      cleanup: () => signal?.removeEventListener("abort", onAbort),
    });
    socket.send(JSON.stringify({ id, method, params }));
    return promise;
  }

  /**
   * Ends the session: the loader closes with 1000 and tears down BiDi; pending calls get E_STOPPED.
   * Safe to call at any time, including before connect() and more than once.
   */
  close(): void {
    const socket = this.#session?.socket;
    if (this.#closing || !socket) {
      this.#teardown();
      return;
    }
    // Let the close frame land before the server goes away; #disconnect() finishes the teardown.
    this.#closing = true;
    socket.close(1000, "done");
  }

  #accept(session: Session, ws: ServerWebSocket<undefined>): void {
    if (session !== this.#session || session.socket) {
      ws.close(4009, "second connection");
      return;
    }
    session.socket = ws;
    ws.send(JSON.stringify({ type: "challenge", challenge: session.challenge }));
  }

  #receive(session: Session, ws: ServerWebSocket<undefined>, raw: string | Buffer): void {
    if (session !== this.#session || ws !== session.socket) return;
    let frame: Frame;
    try {
      frame = JSON.parse(String(raw)) as Frame;
    } catch {
      if (!session.authed) this.#refuse(session, 4002, "unexpected message before authentication");
      return;
    }

    if (!session.authed) {
      if (frame.type !== "auth") {
        this.#refuse(session, 4002, "unexpected message before authentication");
        return;
      }
      if (typeof frame.mac !== "string" || !sameHex(frame.mac, hmacHex(session.nonce, `loader:${session.challenge}`))) {
        this.#refuse(session, 4003, "loader proof mismatch");
        return;
      }
      if (typeof frame.challenge !== "string" || frame.challenge === "") {
        this.#refuse(session, 4003, "loader challenge missing");
        return;
      }
      session.authed = true;
      ws.send(JSON.stringify({ type: "auth", mac: hmacHex(session.nonce, `omp:${frame.challenge}`) }));
      return;
    }

    if (frame.type === "ready") {
      // The payload is the loader's identity, which the extension validates by hash; the link only routes it.
      const ready = frame as unknown as ReadyFrame;
      this.#client = ws;
      this.#ready = ready;
      session.ready.resolve(ready);
      return;
    }
    if (frame.type === "event") {
      if (typeof frame.name === "string") this.onEvent?.({ name: frame.name, data: frame.data });
      return;
    }
    if (typeof frame.id === "number") {
      const pending = this.#take(frame.id);
      if (!pending) return;
      const error = frame.error;
      if (error && typeof error === "object") {
        const code = "code" in error ? error.code : undefined;
        const message = "message" in error ? error.message : undefined;
        pending.reject(
          new HirozenError(
            typeof code === "string" ? code : "E_UNKNOWN",
            typeof message === "string" ? message : JSON.stringify(error),
          ),
        );
      } else if (typeof error === "string") {
        // Pre-contract loader: it answered with a bare string instead of {code, message}.
        pending.reject(new HirozenError("E_UNKNOWN", error));
      } else {
        pending.resolve(frame.result);
      }
    }
  }

  #disconnect(session: Session, ws: ServerWebSocket<undefined>, code: number, reason: string): void {
    if (session !== this.#session || ws !== session.socket) return;
    const authed = session.authed;
    session.socket = null;
    if (!authed) {
      // connect()'s finally tears the listener down once this rejection reaches its awaiter.
      const why = code === 4003 ? "loader proof mismatch" : code === 4002 ? "unexpected message before authentication" : `disconnected (${code} ${reason})`;
      session.ready.reject(new HirozenError("E_AUTH", `loader authentication failed: ${why}`));
      return;
    }
    this.#teardown();
    this.onClose?.({ code, reason, stoppedByUser: code === 4010 });
  }

  /** Closes a connection without authenticating it: 4002 (protocol) or 4003 (bad proof). */
  #refuse(session: Session, code: number, reason: string): void {
    session.socket?.close(code, reason);
  }

  #take(id: number): PendingCall | undefined {
    const pending = this.#pending.get(id);
    if (!pending) return undefined;
    this.#pending.delete(id);
    clearTimeout(pending.timer);
    pending.cleanup();
    return pending;
  }

  #failAll(error: Error): void {
    for (const id of [...this.#pending.keys()]) this.#take(id)?.reject(error);
  }

  /** Stops the listener and drops all state; a later connect() starts a fresh handshake. */
  #teardown(): void {
    const session = this.#session;
    this.#session = null;
    this.#client = null;
    this.#ready = null;
    this.#closing = false;
    session?.socket?.close(1000, "done");
    // stop(false): stopping with force truncates a close frame that is still in flight, which would
    // turn a deliberate 4002/4003/1000 into an abnormal 1006 at the loader. Every path here has just
    // closed its connection (or never had one), so the graceful stop cannot hang.
    this.#server?.stop(false);
    this.#server = null;
    this.#failAll(new HirozenError("E_STOPPED", "the Hirozen link is closed"));
  }
}
