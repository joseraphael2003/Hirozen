// Installs (or verifies/removes) the Hirozen autoconfig + hash-pinned loader into a Zen install folder.
//
// Layout written into the Zen install directory:
//   defaults/pref/hirozen-prefs.js  -> general.config.filename = "hirozen.cfg"
//   hirozen.cfg                     -> autoconfig entry point (loader/hirozen.cfg.template, hash substituted)
//   hirozen/loader.sys.mjs          -> copy of this repo's loader/loader.sys.mjs
//
// No default Zen directory: every function requires an explicit path so nothing can ever touch a
// real installation by accident.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export type InstallOptions = {
  /** Loader module to install. Defaults to this repo's loader/loader.sys.mjs. Overridable for tests. */
  loaderSource?: string;
};

export type VerifyResult = {
  ok: boolean;
  installedSha: string | null;
  sourceSha: string | null;
  reason: string;
};

const DEFAULT_LOADER_SOURCE = fileURLToPath(new URL("../loader/loader.sys.mjs", import.meta.url));
const CFG_TEMPLATE = fileURLToPath(new URL("../loader/hirozen.cfg.template", import.meta.url));

const PREFS_FILE = "hirozen-prefs.js";
const CFG_FILE = "hirozen.cfg";
const LOADER_DIR = "hirozen";
const LOADER_FILE = "loader.sys.mjs";
const SHA_PLACEHOLDER = "@@LOADER_SHA256@@";

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
 * Write the autoconfig files and the loader. Refuses (writing nothing) if another autoconfig
 * already claims general.config.filename.
 */
export function install(zenDir: string, options: InstallOptions = {}): { loaderSha256: string } {
  const dir = requireZenDir(zenDir);
  if (!existsSync(join(dir, "zen.exe"))) throw new Error(`not a Zen install (no zen.exe): ${dir}`);

  const prefDir = join(dir, "defaults", "pref");
  const foreign = foreignAutoconfig(prefDir);
  if (foreign) {
    throw new Error(
      `another autoconfig is installed (${foreign} sets general.config.filename); refusing to touch ${dir}`,
    );
  }

  const loaderSource = options.loaderSource ?? DEFAULT_LOADER_SOURCE;
  // Read everything before writing anything: a failure here must leave the install untouched.
  const loader = readFileSync(loaderSource);
  const template = readFileSync(CFG_TEMPLATE, "utf8");
  if (!template.includes(SHA_PLACEHOLDER)) {
    throw new Error(`${CFG_TEMPLATE} lacks ${SHA_PLACEHOLDER}; refusing to install an unpinned loader`);
  }
  const loaderSha256 = createHash("sha256").update(loader).digest("hex");

  mkdirSync(join(dir, LOADER_DIR), { recursive: true });
  writeFileSync(join(dir, LOADER_DIR, LOADER_FILE), loader);
  writeFileSync(join(dir, CFG_FILE), template.replace(SHA_PLACEHOLDER, loaderSha256));
  mkdirSync(prefDir, { recursive: true });
  writeFileSync(join(prefDir, PREFS_FILE), PREFS_JS);
  return { loaderSha256 };
}

/** Read-only check that all three pieces are present and the installed loader matches the source. */
export function verify(zenDir: string, options: InstallOptions = {}): VerifyResult {
  const dir = requireZenDir(zenDir);
  const sourcePath = options.loaderSource ?? DEFAULT_LOADER_SOURCE;
  const installedPath = join(dir, LOADER_DIR, LOADER_FILE);

  const sourceSha = existsSync(sourcePath) ? sha256File(sourcePath) : null;
  const installedSha = existsSync(installedPath) ? sha256File(installedPath) : null;

  const artifacts: [string, boolean][] = [
    [`${LOADER_DIR}/${LOADER_FILE}`, installedSha !== null],
    [CFG_FILE, existsSync(join(dir, CFG_FILE))],
    [`defaults/pref/${PREFS_FILE}`, existsSync(join(dir, "defaults", "pref", PREFS_FILE))],
  ];
  for (const [name, present] of artifacts) {
    if (!present) return { ok: false, installedSha, sourceSha, reason: `${name} is not installed in ${dir}` };
  }
  if (!sourceSha) {
    return { ok: false, installedSha, sourceSha, reason: `loader source not found: ${sourcePath}` };
  }
  if (installedSha !== sourceSha) {
    return {
      ok: false,
      installedSha,
      sourceSha,
      reason: `installed loader ${installedSha} does not match the plugin loader ${sourceSha}; run /hirozen-install and restart Zen`,
    };
  }
  return { ok: true, installedSha, sourceSha, reason: "installed loader matches the plugin loader" };
}

/** Remove exactly the three things install() writes; never anything else in the install directory. */
export function uninstall(zenDir: string): void {
  const dir = requireZenDir(zenDir);
  for (const target of [join(dir, LOADER_DIR), join(dir, CFG_FILE), join(dir, "defaults", "pref", PREFS_FILE)]) {
    rmSync(target, { recursive: true, force: true });
  }
}
