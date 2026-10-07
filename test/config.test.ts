// Config tests: the precedence table (env > plugin settings > unconfigured), the project override
// path that shadows a saved key, and the read probe that keeps a corrupt lockfile from being
// rewritten with hirozen's settings alone. No test reaches the real settings writer: every deps
// object here is a fake, and the repo .env sets HIROZEN_* (bun loads it), so the settings cases
// delete both vars first and restore them afterwards.
import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { clearConfig, readProjectOverride, resolveConfig, saveConfig } from "../src/config";
import type { ConfigDeps, HirozenConfig, ResolveConfigResult, SettingsReader, SettingsSnapshot } from "../src/config";

const ZEN_ENV = "HIROZEN_ZEN_DIR";
const PROFILE_ENV = "HIROZEN_PROFILE";

const tempDirs: string[] = [];
let savedEnv: { zen: string | undefined; profile: string | undefined };

beforeEach(() => {
  savedEnv = { zen: process.env[ZEN_ENV], profile: process.env[PROFILE_ENV] };
  delete process.env[ZEN_ENV];
  delete process.env[PROFILE_ENV];
});

afterEach(() => {
  for (const [key, value] of [
    [ZEN_ENV, savedEnv.zen],
    [PROFILE_ENV, savedEnv.profile],
  ] as const) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "hirozen-config-"));
  tempDirs.push(dir);
  return dir;
}

/** A settings reader that answers with `snapshot` and records every cwd it was asked about. */
function fakeReader(snapshot: SettingsSnapshot): { read: SettingsReader; calls: string[] } {
  const calls: string[] = [];
  return {
    read: async cwd => {
      calls.push(cwd);
      return snapshot;
    },
    calls,
  };
}

/** Fake deps for the writer: nothing here can touch the real lockfile. */
function fakeDeps(): {
  deps: ConfigDeps;
  reads: string[];
  saves: Array<[string, HirozenConfig]>;
  clears: string[];
} {
  const reads: string[] = [];
  const saves: Array<[string, HirozenConfig]> = [];
  const clears: string[] = [];
  return {
    deps: {
      read: async cwd => {
        reads.push(cwd);
        return { values: {} };
      },
      save: async (cwd, values) => {
        saves.push([cwd, values]);
      },
      clear: async cwd => {
        clears.push(cwd);
      },
    },
    reads,
    saves,
    clears,
  };
}

/** Deps whose probe fails the way a corrupt lockfile does (PluginManager would swallow this). */
function failingDeps(): { deps: ConfigDeps; saves: unknown[]; clears: unknown[] } {
  const saves: unknown[] = [];
  const clears: unknown[] = [];
  return {
    deps: {
      read: async () => {
        throw new Error("Unexpected token } in JSON at position 3");
      },
      save: async (...args) => {
        saves.push(args);
      },
      clear: async (...args) => {
        clears.push(args);
      },
    },
    saves,
    clears,
  };
}

/** `problem` of a failed resolve, with the narrowing done once. */
function problemOf(result: ResolveConfigResult): string {
  return result.ok ? "" : result.problem;
}

// ---------------------------------------------------------------------------------------------
// Precedence
// ---------------------------------------------------------------------------------------------

test("both env vars win over saved settings, trimmed", async () => {
  process.env[ZEN_ENV] = " D:\\env-zen ";
  process.env[PROFILE_ENV] = "D:\\env-profile";
  const { read, calls } = fakeReader({ values: { zenDir: "D:\\saved-zen", profileDir: "D:\\saved-profile" } });

  expect(await resolveConfig("D:\\proj", read)).toEqual({
    ok: true,
    config: { zenDir: "D:\\env-zen", profileDir: "D:\\env-profile" },
    source: "env",
  });
  expect(calls).toEqual([]);
});

test("an install without a profile env var is refused, never mixing sources", async () => {
  process.env[ZEN_ENV] = "D:\\env-zen";
  const { read, calls } = fakeReader({ values: { zenDir: "D:\\saved-zen", profileDir: "D:\\saved-profile" } });

  const result = await resolveConfig("D:\\proj", read);

  expect(result.ok).toBe(false);
  expect(problemOf(result)).toContain(PROFILE_ENV);
  expect(calls).toEqual([]);
});

test("a profile without an install env var names the missing install var", async () => {
  process.env[PROFILE_ENV] = "D:\\env-profile";
  const { read } = fakeReader({ values: { zenDir: "D:\\saved-zen", profileDir: "D:\\saved-profile" } });

  const result = await resolveConfig("D:\\proj", read);

  expect(result.ok).toBe(false);
  expect(problemOf(result)).toContain(ZEN_ENV);
});

test("saved settings are used when the env is unset", async () => {
  const { read } = fakeReader({ values: { zenDir: "D:\\saved-zen", profileDir: "D:\\saved-profile" } });

  expect(await resolveConfig("D:\\proj", read)).toEqual({
    ok: true,
    config: { zenDir: "D:\\saved-zen", profileDir: "D:\\saved-profile" },
    source: "settings",
  });
});

test("a saved pair with one key missing asks for setup", async () => {
  const { read } = fakeReader({ values: { zenDir: "D:\\saved-zen" } });

  const result = await resolveConfig("D:\\proj", read);

  expect(result.ok).toBe(false);
  expect(problemOf(result)).toContain("profileDir");
  expect(problemOf(result)).toContain("/hirozen-setup");
});

test("a non-string or blank setting does not count as a saved path", async () => {
  const { read } = fakeReader({ values: { zenDir: 42, profileDir: "   " } });

  const result = await resolveConfig("D:\\proj", read);

  expect(result.ok).toBe(false);
  expect(problemOf(result)).toContain("/hirozen-setup");
});

test("nothing set anywhere asks for setup and mentions both env vars", async () => {
  const { read } = fakeReader({ values: {} });

  expect(await resolveConfig("D:\\proj", read)).toEqual({
    ok: false,
    problem: "Hirozen is not set up: run /hirozen-setup (or set HIROZEN_ZEN_DIR and HIROZEN_PROFILE).",
  });
});

test("a settings read failure names the lockfile and the env escape hatch", async () => {
  const broken: SettingsReader = async () => {
    throw new Error("Unexpected token } in JSON at position 3");
  };

  const result = await resolveConfig("D:\\proj", broken);

  expect(problemOf(result)).toBe(
    "cannot read omp plugin settings (Unexpected token } in JSON at position 3); set " +
      "HIROZEN_ZEN_DIR and HIROZEN_PROFILE, or fix ~/.omp/plugins/omp-plugins.lock.json",
  );
});

test("an env var still answers when the settings read fails", async () => {
  process.env[ZEN_ENV] = "D:\\env-zen";
  process.env[PROFILE_ENV] = "D:\\env-profile";
  const broken: SettingsReader = async () => {
    throw new Error("corrupt");
  };

  expect(await resolveConfig("D:\\proj", broken)).toEqual({
    ok: true,
    config: { zenDir: "D:\\env-zen", profileDir: "D:\\env-profile" },
    source: "env",
  });
});

test("a project override that supplies a key is reported with its path", async () => {
  const { read } = fakeReader({
    values: { zenDir: "D:\\saved-zen", profileDir: "D:\\saved-profile" },
    override: { path: "D:\\proj\\.omp\\plugin-overrides.json", values: { zenDir: "" } },
  });

  expect(await resolveConfig("D:\\proj", read)).toEqual({
    ok: true,
    config: { zenDir: "D:\\saved-zen", profileDir: "D:\\saved-profile" },
    source: "settings",
    overridePath: "D:\\proj\\.omp\\plugin-overrides.json",
  });
});

test("an override without a hirozen path key is not reported", async () => {
  const { read } = fakeReader({
    values: { zenDir: "D:\\saved-zen", profileDir: "D:\\saved-profile" },
    override: { path: "D:\\proj\\.omp\\plugin-overrides.json", values: { unrelated: true } },
  });

  expect(await resolveConfig("D:\\proj", read)).toEqual({
    ok: true,
    config: { zenDir: "D:\\saved-zen", profileDir: "D:\\saved-profile" },
    source: "settings",
  });
});

// ---------------------------------------------------------------------------------------------
// Project override discovery
// ---------------------------------------------------------------------------------------------

test("readProjectOverride reads the first override omp would read", async () => {
  const cwd = tempDir();
  mkdirSync(join(cwd, ".omp"), { recursive: true });
  writeFileSync(join(cwd, ".omp", "plugin-overrides.json"), "not json at all");
  mkdirSync(join(cwd, ".codex"), { recursive: true });
  const codex = join(cwd, ".codex", "plugin-overrides.json");
  writeFileSync(codex, JSON.stringify({ settings: { hirozen: { zenDir: "D:\\saved-zen" } } }));

  expect(await readProjectOverride(cwd)).toEqual({ path: codex, values: { zenDir: "D:\\saved-zen" } });
});

test("readProjectOverride is undefined when the project has no override file", async () => {
  expect(await readProjectOverride(tempDir())).toBeUndefined();
});

// ---------------------------------------------------------------------------------------------
// Writes (probe first)
// ---------------------------------------------------------------------------------------------

test("saveConfig writes both keys after a successful read probe", async () => {
  const { deps, reads, saves } = fakeDeps();

  await saveConfig("D:\\proj", { zenDir: "D:\\new-zen", profileDir: "D:\\new-profile" }, deps);

  expect(reads).toEqual(["D:\\proj"]);
  expect(saves).toEqual([["D:\\proj", { zenDir: "D:\\new-zen", profileDir: "D:\\new-profile" }]]);
});

test("saveConfig refuses to write when the read probe fails", async () => {
  const { deps, saves } = failingDeps();

  const failure = await saveConfig("D:\\proj", { zenDir: "D:\\zen", profileDir: "D:\\profile" }, deps).then(
    () => null,
    (error: Error) => error,
  );

  expect(failure?.message).toBe(
    "cannot read omp plugin settings (Unexpected token } in JSON at position 3); nothing was saved",
  );
  expect(saves).toEqual([]);
});

test("clearConfig removes both keys after a successful read probe", async () => {
  const { deps, reads, clears } = fakeDeps();

  await clearConfig("D:\\proj", deps);

  expect(reads).toEqual(["D:\\proj"]);
  expect(clears).toEqual(["D:\\proj"]);
});

test("clearConfig refuses to remove when the read probe fails", async () => {
  const { deps, clears } = failingDeps();

  const failure = await clearConfig("D:\\proj", deps).then(
    () => null,
    (error: Error) => error,
  );

  expect(failure?.message).toContain("nothing was saved");
  expect(clears).toEqual([]);
});
