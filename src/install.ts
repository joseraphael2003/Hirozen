// Installs (or verifies/removes) the Hirozen autoconfig + hash-pinned modules into a Zen install folder.
//
// Layout written into the Zen install directory:
//   defaults/pref/hirozen-prefs.js   -> general.config.filename = "hirozen.cfg"
//   hirozen.cfg                      -> autoconfig entry point (loader/hirozen.cfg.template, hashes substituted)
//   hirozen/loader.sys.mjs           -> copy of this repo's loader/loader.sys.mjs
//   hirozen/HirozenChild.sys.mjs     -> copy of this repo's loader/HirozenChild.sys.mjs
//   hirozen/HirozenParent.sys.mjs    -> copy of this repo's loader/HirozenParent.sys.mjs
//
// No default Zen directory: every function requires an explicit path so nothing can ever touch a
// real installation by accident.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The three files the loader needs at startup: the loader plus the actor pair it registers. */
export const MODULE_FILES = {
  loader: "loader.sys.mjs",
  child: "HirozenChild.sys.mjs",
  parent: "HirozenParent.sys.mjs",
} as const;

/** `loader` is the module the cfg imports; `child`/`parent` are the actor pair it registers. */
export type ModuleRole = keyof typeof MODULE_FILES;

/** One hex sha256 per module, keyed by role. */
export type ModuleHashes = { loader: string; child: string; parent: string };

/** Every pin the template must carry, exactly once, before install() may write anything. */
export const MODULE_PLACEHOLDERS: Record<ModuleRole, string> = {
  loader: "@@LOADER_SHA256@@",
  child: "@@CHILD_SHA256@@",
  parent: "@@PARENT_SHA256@@",
};

const MODULE_ROLES: ModuleRole[] = ["loader", "child", "parent"];

export type InstallOptions = {
  /** Modules to install. Default to this repo's loader/*.sys.mjs. Overridable for tests. */
  loaderSource?: string;
  childSource?: string;
  parentSource?: string;
};

export type VerifyResult = {
  ok: boolean;
  reason: string;
  /** The artifact a hash came from: a module file, the generated cfg, or null when nothing mismatched. */
  mismatch: (typeof MODULE_FILES)[ModuleRole] | "hirozen.cfg" | null;
  /** Hashes of the installed modules; null unless all three files are there. */
  installed: ModuleHashes | null;
  /** Hashes of this checkout's modules; null unless all three sources are there. */
  source: ModuleHashes | null;
  /** `/hirozen-status` compat: the installed loader hash (= installed.loader). */
  installedSha: string | null;
  /** `/hirozen-status` compat: this checkout's loader hash (= source.loader). */
  sourceSha: string | null;
};

const DEFAULT_SOURCES: Record<ModuleRole, string> = {
  loader: fileURLToPath(new URL("../loader/loader.sys.mjs", import.meta.url)),
  child: fileURLToPath(new URL("../loader/HirozenChild.sys.mjs", import.meta.url)),
  parent: fileURLToPath(new URL("../loader/HirozenParent.sys.mjs", import.meta.url)),
};
const CFG_TEMPLATE = fileURLToPath(new URL("../loader/hirozen.cfg.template", import.meta.url));

const PREFS_FILE = "hirozen-prefs.js";
const CFG_FILE = "hirozen.cfg";
const LOADER_DIR = "hirozen";

const PREFS_JS = [
  "// Hirozen: load hirozen.cfg (plain text, privileged) at startup.",
  'pref("general.config.filename", "hirozen.cfg");',
  'pref("general.config.obscure_value", 0);',
  'pref("general.config.sandbox_enabled", false);',
  "",
].join("\n");

/** Sanity check: an empty or missing path would otherwise resolve to the current directory. */
function requireZenDir(zenDir: string): string {
  if (typeof zenDir !== "string" || zenDir.trim() === "") {
    throw new Error("zenDir is required: pass the Zen install directory explicitly (there is no default)");
  }
  return resolve(zenDir);
}

/** SHA-256 of a file, hex. Also used by the extension to compare loader copies. */
export function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** Per-role hex sha256 (`null` when the file is not there yet, so verify can name it) plus the set. */
function hashModules(paths: Record<ModuleRole, string>): {
  hashes: Record<ModuleRole, string | null>;
  all: ModuleHashes | null;
} {
  const hashes = {} as Record<ModuleRole, string | null>;
  for (const role of MODULE_ROLES) hashes[role] = existsSync(paths[role]) ? sha256File(paths[role]) : null;
  const { loader, child, parent } = hashes;
  return { hashes, all: loader && child && parent ? { loader, child, parent } : null };
}

/** Every pin must appear exactly once: a second copy would leave an unpinned expansion behind. */
function substitutePin(template: string, placeholder: string, value: string): string {
  const count = template.split(placeholder).length - 1;
  if (count !== 1) {
    throw new Error(`${CFG_TEMPLATE} must contain exactly one ${placeholder} (found ${count}); refusing to install`);
  }
  return template.replace(placeholder, value);
}

/** First defaults/pref/*.js other than ours that mentions general.config.filename, if any. */
function foreignAutoconfig(prefDir: string): string | null {
  if (!existsSync(prefDir)) return null;
  for (const entry of readdirSync(prefDir, { withFileTypes: true })) {
    if (!entry.isFile() || entry.name === PREFS_FILE) continue;
    if (!entry.name.toLowerCase().endsWith(".js")) continue;
    // Loose match on purpose: a comment that mentions the pref also refuses, which is safer
    // than parsing the file and risking a miss.
    if (/general\.config\.filename/.test(readFileSync(join(prefDir, entry.name), "utf8"))) return entry.name;
  }
  return null;
}

/**
 * Write the autoconfig files and the three modules. Refuses (writing nothing) if another autoconfig
 * already claims general.config.filename, or if a source is unreadable or the cfg lacks a pin.
 */
export function install(
  zenDir: string,
  options: InstallOptions = {},
): { loaderSha256: string; childSha256: string; parentSha256: string } {
  const dir = requireZenDir(zenDir);
  if (!existsSync(join(dir, "zen.exe"))) throw new Error(`not a Zen install (no zen.exe): ${dir}`);

  const prefDir = join(dir, "defaults", "pref");
  const foreign = foreignAutoconfig(prefDir);
  if (foreign) {
    throw new Error(
      `another autoconfig is installed (${foreign} sets general.config.filename); refusing to touch ${dir}`,
    );
  }

  const sources: Record<ModuleRole, string> = {
    loader: options.loaderSource ?? DEFAULT_SOURCES.loader,
    child: options.childSource ?? DEFAULT_SOURCES.child,
    parent: options.parentSource ?? DEFAULT_SOURCES.parent,
  };
  const pin = {} as ModuleHashes;
  // Read everything before writing anything: a failure here must leave the install untouched.
  const modules = {} as Record<ModuleRole, Buffer>;
  for (const role of MODULE_ROLES) {
    modules[role] = readFileSync(sources[role]);
    pin[role] = createHash("sha256").update(modules[role]).digest("hex");
  }
  let cfg = readFileSync(CFG_TEMPLATE, "utf8");
  for (const role of MODULE_ROLES) cfg = substitutePin(cfg, MODULE_PLACEHOLDERS[role], pin[role]);

  mkdirSync(join(dir, LOADER_DIR), { recursive: true });
  for (const role of MODULE_ROLES) writeFileSync(join(dir, LOADER_DIR, MODULE_FILES[role]), modules[role]);
  writeFileSync(join(dir, CFG_FILE), cfg);
  mkdirSync(prefDir, { recursive: true });
  writeFileSync(join(prefDir, PREFS_FILE), PREFS_JS);
  return { loaderSha256: pin.loader, childSha256: pin.child, parentSha256: pin.parent };
}

/**
 * Read-only check that every piece is present, each installed module matches this checkout's copy and
 * the installed cfg pins all three. The first failure names the artifact it came from.
 */
export function verify(zenDir: string, options: InstallOptions = {}): VerifyResult {
  const dir = requireZenDir(zenDir);
  const sources: Record<ModuleRole, string> = {
    loader: options.loaderSource ?? DEFAULT_SOURCES.loader,
    child: options.childSource ?? DEFAULT_SOURCES.child,
    parent: options.parentSource ?? DEFAULT_SOURCES.parent,
  };
  const installedPaths = {} as Record<ModuleRole, string>;
  for (const role of MODULE_ROLES) installedPaths[role] = join(dir, LOADER_DIR, MODULE_FILES[role]);

  const installedModules = hashModules(installedPaths);
  const sourceModules = hashModules(sources);
  const installedSha = installedModules.hashes.loader;
  const sourceSha = sourceModules.hashes.loader;
  const installedHashes = installedModules.hashes;
  const sourceHashes = sourceModules.hashes;
  const failure = (reason: string, mismatch: VerifyResult["mismatch"]): VerifyResult => ({
    ok: false,
    reason,
    mismatch,
    installed: installedModules.all,
    source: sourceModules.all,
    installedSha,
    sourceSha,
  });

  const artifacts: [string, boolean][] = [
    ...MODULE_ROLES.map((role): [string, boolean] => [`${LOADER_DIR}/${MODULE_FILES[role]}`, installedHashes[role] !== null]),
    [CFG_FILE, existsSync(join(dir, CFG_FILE))],
    [`defaults/pref/${PREFS_FILE}`, existsSync(join(dir, "defaults", "pref", PREFS_FILE))],
  ];
  for (const [name, present] of artifacts) {
    if (!present) return failure(`${name} is not installed in ${dir}`, null);
  }
  const noSource = MODULE_ROLES.find(role => sourceHashes[role] === null);
  if (noSource) return failure(`${MODULE_FILES[noSource]} source not found: ${sources[noSource]}`, null);

  for (const role of MODULE_ROLES) {
    if (installedHashes[role] !== sourceHashes[role]) {
      return failure(
        `installed ${MODULE_FILES[role]} ${installedHashes[role]} does not match the plugin ${MODULE_FILES[role]} ` +
          `${sourceHashes[role]}; run /hirozen-install and restart Zen`,
        MODULE_FILES[role],
      );
    }
  }
  const cfg = readFileSync(join(dir, CFG_FILE), "utf8");
  for (const role of MODULE_ROLES) {
    if (!cfg.includes(installedHashes[role] as string)) {
      return failure(
        `installed ${CFG_FILE} does not pin ${MODULE_FILES[role]} (${installedHashes[role]}); ` +
          `run /hirozen-install and restart Zen`,
        CFG_FILE,
      );
    }
  }
  return {
    ok: true,
    reason: "installed loader and actor modules match the plugin loader",
    mismatch: null,
    installed: installedModules.all,
    source: sourceModules.all,
    installedSha,
    sourceSha,
  };
}

/** Remove exactly the things install() writes; never anything else in the install directory. */
export function uninstall(zenDir: string): void {
  const dir = requireZenDir(zenDir);
  for (const target of [join(dir, LOADER_DIR), join(dir, CFG_FILE), join(dir, "defaults", "pref", PREFS_FILE)]) {
    rmSync(target, { recursive: true, force: true });
  }
}
