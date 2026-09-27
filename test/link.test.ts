// Link server tests. A real WebSocket client plays the loader (loader/loader.sys.mjs) and follows
// omp-sim's handshake from the loader side, so the mac bytes and close codes are exercised end to end.
import { afterEach, expect, test } from "bun:test";
import { createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HANDOFF_FILE, HirozenError, STATUS_FILE, ZenLink } from "../src/link";
import type { HandoffFile, LoaderEvent, ReadyFrame } from "../src/link";

const READY_FRAME: ReadyFrame = {
  type: "ready",
  loaderVersion: "1.0.0-test",
  loaderSha256: "0".repeat(64),
  zenVersion: "1.22.3b",
  platformVersion: "142.0",
  zenPid: 4242,
};

const hmacHex = (key: string, message: string) => createHmac("sha256", key).update(message).digest("hex");
const hex = () => randomBytes(32).toString("hex");

type Frame = Record<string, unknown>;

const sockets: LoaderSocket[] = [];
const links: ZenLink[] = [];
const dirs: string[] = [];

/** The loader's end of the link: queues frames so none of them can be missed. */
class LoaderSocket {
  readonly ws: WebSocket;
  readonly closed: Promise<{ code: number; reason: string }>;
  #frames: Frame[] = [];
  #waiters: ((frame: Frame) => void)[] = [];

  constructor(port: number) {
    this.ws = new WebSocket(`ws://127.0.0.1:${port}/hirozen`);
    const { promise, resolve } = Promise.withResolvers<{ code: number; reason: string }>();
    this.closed = promise;
    this.ws.addEventListener("message", event => {
      const frame = JSON.parse(String(event.data)) as Frame;
      const waiter = this.#waiters.shift();
      if (waiter) waiter(frame);
      else this.#frames.push(frame);
    });
    this.ws.addEventListener("close", event => resolve({ code: event.code, reason: event.reason }), { once: true });
    sockets.push(this);
  }

  next(timeoutMs = 2_000): Promise<Frame> {
    const queued = this.#frames.shift();
    if (queued) return Promise.resolve(queued);
    const { promise, resolve, reject } = Promise.withResolvers<Frame>();
    const timer = setTimeout(() => reject(new Error("the link sent no frame in time")), timeoutMs);
    this.#waiters.push(frame => {
      clearTimeout(timer);
      resolve(frame);
    });
    return promise;
  }

  send(frame: unknown): void {
    this.ws.send(JSON.stringify(frame));
  }

  close(): void {
    if (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN) this.ws.close();
  }
}

function makeProfileDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "hirozen-link-"));
  dirs.push(dir);
  return dir;
}

function useLink(link: ZenLink): ZenLink {
  links.push(link);
  return link;
}

function delay(ms: number): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, ms);
  return promise;
}

/**
 * Poll for the side effect connect() makes in the profile directory. Both helpers wait for the real
 * condition (the file / the queue draining) instead of a fixed duration, so the poll interval is only
 * how often the condition is re-checked.
 */
async function waitFor(condition: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("condition was never met");
    await delay(5);
  }
}

/** connect() writes the handoff before it can resolve, so poll for it while the connect is pending. */
async function waitForHandoff(dir: string, timeoutMs = 3_000): Promise<HandoffFile> {
  const path = join(dir, HANDOFF_FILE);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      return JSON.parse(readFileSync(path, "utf8")) as HandoffFile;
    } catch {
      // not written yet (or caught mid-write): keep polling until the deadline
    }
    if (Date.now() > deadline) throw new Error("connect() never wrote the handoff file");
    await delay(10);
  }
}

/** Connect like the loader does and read the challenge omp sends on open. */
async function connectAsLoader(dir: string): Promise<{ socket: LoaderSocket; handoff: HandoffFile; challenge: string }> {
  const handoff = await waitForHandoff(dir);
  const socket = new LoaderSocket(handoff.port);
  const frame = await socket.next();
  if (typeof frame.challenge !== "string") throw new Error("expected a challenge frame");
  return { socket, handoff, challenge: frame.challenge };
}

/** Completes the handshake up to (not including) the ready frame. */
async function authenticate(socket: LoaderSocket, nonce: string, challenge: string): Promise<void> {
  const myChallenge = hex();
  socket.send({ type: "auth", mac: hmacHex(nonce, `loader:${challenge}`), challenge: myChallenge });
  const auth = await socket.next();
  expect(auth.type).toBe("auth");
  expect(auth.mac).toBe(hmacHex(nonce, `omp:${myChallenge}`));
}

afterEach(async () => {
  const open = sockets.splice(0);
  for (const socket of open) socket.close();
  await Promise.all(open.map(socket => socket.closed)); // the real close signal, not a guessed wait
  for (const link of links.splice(0)) link.close();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

test("correct loader proof completes the handshake", async () => {
  const dir = makeProfileDir();
  const link = useLink(new ZenLink());
  const events: LoaderEvent[] = [];
  link.onEvent = event => events.push(event);

  const connecting = link.connect(dir, { timeoutMs: 5_000 });
  const { socket, handoff, challenge } = await connectAsLoader(dir);
  await authenticate(socket, handoff.nonce, challenge);

  socket.send(READY_FRAME);
  expect(await connecting).toEqual(READY_FRAME);

  // the authenticated connection carries requests both ways
  const inventory = link.call<{ windowId: number }[]>("zen.inventory", {});
  const request = await socket.next();
  expect(request.method).toBe("zen.inventory");
  socket.send({ id: request.id, result: [{ windowId: 1 }] });
  expect(await inventory).toEqual([{ windowId: 1 }]);

  const stop = link.call("bidi.stop", {});
  const refusal = await socket.next();
  socket.send({ id: refusal.id, error: { code: "E_UNKNOWN_METHOD", message: "bidi.stop is not exposed" } });
  const error = await stop.then(
    () => null,
    (reason: unknown) => reason,
  );
  expect(error).toBeInstanceOf(HirozenError);
  expect((error as HirozenError).code).toBe("E_UNKNOWN_METHOD");
  expect((error as HirozenError).message).toBe("bidi.stop is not exposed");

  socket.send({ type: "event", name: "bidi.starting", data: { phase: "start" } });
  await waitFor(() => events.length === 1);
  expect(events[0]).toEqual({ name: "bidi.starting", data: { phase: "start" } });

  expect(existsSync(join(dir, HANDOFF_FILE))).toBe(false); // consumed, never left behind
});

test("a wrong loader proof is refused with 4003", async () => {
  const dir = makeProfileDir();
  const link = useLink(new ZenLink());
  const connecting = link.connect(dir, { timeoutMs: 5_000 });
  // Consume the refusal up front: an unhandled rejection would abort the test before the client can
  // observe the close code it was refused with.
  const settled = connecting.then(
    () => null,
    (reason: unknown) => reason,
  );
  const { socket, challenge } = await connectAsLoader(dir);
  socket.send({ type: "auth", mac: hmacHex(hex(), `loader:${challenge}`), challenge: hex() });

  expect(await socket.closed).toEqual({ code: 4003, reason: "loader proof mismatch" });
  const error = await settled;
  expect(error).toBeInstanceOf(HirozenError);
  expect((error as HirozenError).code).toBe("E_AUTH");
});

test("a message before auth is refused with 4002", async () => {
  const dir = makeProfileDir();
  const link = useLink(new ZenLink());
  const connecting = link.connect(dir, { timeoutMs: 5_000 });
  const settled = connecting.then(
    () => null,
    (reason: unknown) => reason,
  );
  const { socket } = await connectAsLoader(dir);
  socket.send({ id: 1, method: "zen.inventory", params: {} });

  expect(await socket.closed).toEqual({ code: 4002, reason: "unexpected message before authentication" });
  const error = await settled;
  expect(error).toBeInstanceOf(HirozenError);
  expect((error as HirozenError).code).toBe("E_AUTH");
});

test("a second connection after auth is refused with 4009", async () => {
  const dir = makeProfileDir();
  const link = useLink(new ZenLink());

  const connecting = link.connect(dir, { timeoutMs: 5_000 });
  const { socket, handoff, challenge } = await connectAsLoader(dir);
  await authenticate(socket, handoff.nonce, challenge);
  socket.send(READY_FRAME);
  expect(await connecting).toEqual(READY_FRAME);

  const intruder = new LoaderSocket(handoff.port);
  expect(await intruder.closed).toEqual({ code: 4009, reason: "second connection" });
  expect(socket.ws.readyState).toBe(WebSocket.OPEN); // the owner keeps its connection
});

test("an existing unexpired handoff is refused with E_IN_USE", async () => {
  const dir = makeProfileDir();
  const foreign: HandoffFile = { port: 39421, nonce: hex(), pid: process.pid, cwd: dir, expiry: Date.now() + 60_000 };
  writeFileSync(join(dir, HANDOFF_FILE), JSON.stringify(foreign));

  const link = useLink(new ZenLink());
  const refused = await link.connect(dir, { timeoutMs: 500 }).then(
    () => null,
    (reason: unknown) => reason,
  );
  expect(refused).toBeInstanceOf(HirozenError);
  expect((refused as HirozenError).code).toBe("E_IN_USE");
  expect((refused as HirozenError).pid).toBe(process.pid);
  // the other session's handoff is not ours to delete
  expect(JSON.parse(readFileSync(join(dir, HANDOFF_FILE), "utf8"))).toEqual(foreign);

  // same rule while a loader session is live: hirozen-status.json connected, pid alive
  const busyDir = makeProfileDir();
  writeFileSync(
    join(busyDir, STATUS_FILE),
    JSON.stringify({ version: "1", state: "connected", zenPid: process.pid, updated: new Date().toISOString() }),
  );
  const busy = useLink(new ZenLink());
  const rejected = await busy.connect(busyDir, { timeoutMs: 500 }).then(
    () => null,
    (reason: unknown) => reason,
  );
  expect(rejected).toBeInstanceOf(HirozenError);
  expect((rejected as HirozenError).code).toBe("E_IN_USE");
  expect((rejected as HirozenError).pid).toBe(process.pid);
});
