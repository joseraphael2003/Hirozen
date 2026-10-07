// Hirozen's configuration: the one place that reads HIROZEN_* and omp's plugin settings.
//
// Precedence is env (both vars) > plugin settings > unconfigured. A half-set env or a half-set saved
// pair is never completed from the other source: a mixed pair would point at two different installs.
// omp applies no defaults and no validation of its own, so everything a caller needs to know about a
// stored value is decided here.
//
// The omp plugin API is internal and undocumented. It is imported with `await import("<literal>")`
// rather than a static import for three reasons: omp rewrites literal `@oh-my-pi/*` imports in
// extensions to its own bundled copy (legacy-pi-compat.ts), the package therefore stays in
// devDependencies, and the import must not run until a caller actually needs settings (unit tests
// inject their own reader and never load the plugin manager). This is the only module in src/ that
// may import it.
import { readFileSync } from "node:fs";
import { join } from "node:path";

const PLUGIN_NAME = "hirozen";

/** Project override directories omp reads, in omp's own priority order (`config.ts` priorityList). */
const PROJECT_OVERRIDE_DIRS = [".omp", ".claude", ".codex", ".gemini"];

/** The lockfile a corrupt read leaves behind: named in the problem so the user can fix it. */
const LOCKFILE = "~/.omp/plugins/omp-plugins.lock.json";

export interface HirozenConfig {
  zenDir: string;
  profileDir: string;
}

/** The project plugin-overrides.json omp would merge, plus its hirozen block. */
export interface ProjectOverride {
  path: string;
  values: Record<string, unknown>;
}

export interface SettingsSnapshot {
  /** Merged settings: the user lockfile with the project override winning per key. */
  values: Record<string, unknown>;
  /** The project override omp reads for this cwd, when one exists. */
  override?: ProjectOverride;
}

/** Reads the merged plugin settings. Injectable so unit tests never load omp's plugin manager. */
export type SettingsReader = (cwd: string) => Promise<SettingsSnapshot>;

export interface ConfigDeps {
  read: SettingsReader;
  /** Saves both keys with one fresh PluginManager. */
  save(cwd: string, values: HirozenConfig): Promise<void>;
  /** Deletes both keys with one fresh PluginManager. */
  clear(cwd: string): Promise<void>;
}

export type ResolveConfigResult =
  | { ok: true; config: HirozenConfig; source: "env" | "settings"; overridePath?: string }
  | { ok: false; problem: string };

const NOT_SET_UP = "Hirozen is not set up: run /hirozen-setup (or set HIROZEN_ZEN_DIR and HIROZEN_PROFILE).";

/** A stored value counts only as a non-empty string: omp stores whatever a caller passed. */
function setting(values: Record<string, unknown>, key: keyof HirozenConfig): string | undefined {
  const value = values[key];
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

/**
 * The project plugin-overrides.json omp reads for `cwd`: the first one that parses wins, exactly as
 * omp's own loader skips missing and malformed files. Hirozen never writes one.
 */
export async function readProjectOverride(cwd: string): Promise<ProjectOverride | undefined> {
  for (const dir of PROJECT_OVERRIDE_DIRS) {
    const path = join(cwd, dir, "plugin-overrides.json");
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      continue;
    }
    const settings = (parsed as { settings?: Record<string, unknown> } | null)?.settings;
    const hirozen = settings?.[PLUGIN_NAME];
    const values = typeof hirozen === "object" && hirozen !== null ? (hirozen as Record<string, unknown>) : {};
    return { path, values };
  }
  return undefined;
}

async function readPluginSettings(cwd: string): Promise<SettingsSnapshot> {
  const { getPluginSettings } = await import("@oh-my-pi/pi-coding-agent/extensibility/plugins");
  const values = await getPluginSettings(PLUGIN_NAME, cwd);
  const override = await readProjectOverride(cwd);
  return override === undefined ? { values } : { values, override };
}

/**
 * The real writer. A fresh PluginManager per call (it caches the lockfile it read at construction),
 * and nothing else in src/ imports the plugin internals.
 */
export function pluginDeps(): ConfigDeps {
  return {
    read: readPluginSettings,
    save: async (cwd, values) => {
      const { PluginManager } = await import("@oh-my-pi/pi-coding-agent/extensibility/plugins");
      const manager = new PluginManager(cwd);
      await manager.setPluginSetting(PLUGIN_NAME, "zenDir", values.zenDir);
      await manager.setPluginSetting(PLUGIN_NAME, "profileDir", values.profileDir);
    },
    clear: async cwd => {
      const { PluginManager } = await import("@oh-my-pi/pi-coding-agent/extensibility/plugins");
      const manager = new PluginManager(cwd);
      await manager.deletePluginSetting(PLUGIN_NAME, "zenDir");
      await manager.deletePluginSetting(PLUGIN_NAME, "profileDir");
    },
  };
}

/**
 * Where Hirozen should attach: both env vars (an override for QA and power users) beat the saved
 * pair, and a value set in only one of the two sources is a problem, never half a config.
 */
export async function resolveConfig(cwd: string, read: SettingsReader = readPluginSettings): Promise<ResolveConfigResult> {
  const envZen = (process.env.HIROZEN_ZEN_DIR ?? "").trim();
  const envProfile = (process.env.HIROZEN_PROFILE ?? "").trim();
  if (envZen !== "" && envProfile !== "") {
    return { ok: true, config: { zenDir: envZen, profileDir: envProfile }, source: "env" };
  }
  if (envZen !== "" || envProfile !== "") {
    return {
      ok: false,
      problem:
        envZen !== ""
          ? "HIROZEN_PROFILE is not set; set it to the Zen profile directory (there is no default)."
          : "HIROZEN_ZEN_DIR is not set; set it to the Zen install directory (there is no default).",
    };
  }

  let snapshot: SettingsSnapshot;
  try {
    snapshot = await read(cwd);
  } catch (error) {
    return {
      ok: false,
      problem:
        `cannot read omp plugin settings (${error instanceof Error ? error.message : String(error)}); set ` +
        `HIROZEN_ZEN_DIR and HIROZEN_PROFILE, or fix ${LOCKFILE}`,
    };
  }

  const zenDir = setting(snapshot.values, "zenDir");
  const profileDir = setting(snapshot.values, "profileDir");
  if (zenDir === undefined || profileDir === undefined) {
    if (zenDir === undefined && profileDir === undefined) return { ok: false, problem: NOT_SET_UP };
    const missing = zenDir === undefined ? "zenDir" : "profileDir";
    return { ok: false, problem: `Hirozen is not set up: the ${missing} setting is not saved — run /hirozen-setup.` };
  }
  // An override that names either key is reported even when its value is empty: it still shadows the
  // user's saved one, and the user needs to know which file to edit.
  const override = snapshot.override;
  return override !== undefined && ("zenDir" in override.values || "profileDir" in override.values)
    ? { ok: true, config: { zenDir, profileDir }, source: "settings", overridePath: override.path }
    : { ok: true, config: { zenDir, profileDir }, source: "settings" };
}

/**
 * Reads before writing and refuses on failure. PluginManager treats an unreadable lockfile as an
 * empty one, so a write after a failed read would drop every other plugin's entries.
 */
async function probe(cwd: string, deps: ConfigDeps): Promise<void> {
  try {
    await deps.read(cwd);
  } catch (error) {
    throw new Error(
      `cannot read omp plugin settings (${error instanceof Error ? error.message : String(error)}); nothing was saved`,
    );
  }
}

/** Stores the confirmed pair as given: setup normalized the paths before asking the user to confirm. */
export async function saveConfig(cwd: string, values: HirozenConfig, deps: ConfigDeps = pluginDeps()): Promise<void> {
  await probe(cwd, deps);
  await deps.save(cwd, values);
}

/** Forgets the pair, leaving Hirozen unconfigured until the next /hirozen-setup. */
export async function clearConfig(cwd: string, deps: ConfigDeps = pluginDeps()): Promise<void> {
  await probe(cwd, deps);
  await deps.clear(cwd);
}
