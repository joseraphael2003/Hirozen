// Discovery: find the Zen installs and profiles this machine already has, so /hirozen-setup can offer
// them instead of asking the user to set HIROZEN_ZEN_DIR and HIROZEN_PROFILE (those are an override).
//
// Nothing here is acted on: discovery only *proposes* pairs and the user confirms one - the same
// "never guess the browser" rule the tools follow. Both reads are read-only.
//
//   * `<appData>/zen/profiles.ini`: every `[ProfileN]` section names a profile. The install a profile
//     last ran from is `LastPlatformDir` in that profile's compatibility.ini (never `LastAppDir`,
//     which is the `browser/` subfolder); the pair only counts while `<zenDir>/zen.exe` still exists,
//     so an install the user removed drops out. A profile that never started has no compatibility.ini
//     and is skipped silently.
//   * the live zen.exe processes (attach.listZenProcesses): a main process with an explicit
//     `--profile <dir>` adds a pair profiles.ini does not know about.
import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, join, resolve, win32 } from "node:path";
import { normalizePath, profileArg, type ZenProcess } from "./attach";

/** One pair setup can offer; `source` says which read produced it, `running` comes from the lock probe. */
export type Candidate = {
  zenDir: string;
  profileDir: string;
  /** profiles.ini `Name=` for a profile pair, the profile folder's basename for a process pair. */
  profileName: string;
  /** `LastVersion` up to the first `_` (e.g. `1.23.1b`); null for a process pair or a partial file. */
  zenVersion: string | null;
  running: boolean;
  source: "profile" | "process";
};

export type DiscoverOptions = {
  /** The roaming app data folder (`%APPDATA%`); the Zen root is `<appData>/zen`. */
  appData: string;
  processes: ZenProcess[];
  isLocked: (profileDir: string) => Promise<boolean>;
  /** Only Windows has this layout; injectable so tests can exercise both branches anywhere. */
  platform?: NodeJS.Platform;
};

/** `[Section]` -> key/value; the first `=` splits. A UTF-8 BOM and CRLF line endings are tolerated. */
function iniSections(source: string): Map<string, Map<string, string>> {
  const sections = new Map<string, Map<string, string>>();
  let current: Map<string, string> | null = null;
  for (const line of source.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      current = new Map();
      sections.set(header[1], current);
      continue;
    }
    if (!current) continue;
    const entry = /^([^=]+)=(.*)$/.exec(line);
    if (entry) current.set(entry[1].trim(), entry[2].trim());
  }
  return sections;
}

/** `LastPlatformDir` (the install folder) and `LastVersion` (`1.23.1b_2026…` -> `1.23.1b`), or null. */
export function readCompatibility(profileDir: string): { lastPlatformDir: string; zenVersion: string | null } | null {
  const path = join(profileDir, "compatibility.ini");
  if (!existsSync(path)) return null;
  let source: string;
  try {
    source = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  const section = iniSections(source).get("Compatibility");
  const lastPlatformDir = section?.get("LastPlatformDir");
  if (!lastPlatformDir) return null;
  const lastVersion = section?.get("LastVersion");
  return { lastPlatformDir: resolve(lastPlatformDir), zenVersion: lastVersion ? lastVersion.split("_")[0] : null };
}

/**
 * A path typed into setup: trimmed, unquoted, and only accepted as an absolute Windows path
 * (`win32`, since Zen installs and profiles are Windows paths). The result is stored resolved and is
 * never resolved against omp's cwd; null means "refuse this input".
 */
export function normalizeManualPath(value: string): string | null {
  const trimmed = value.trim().replace(/^(["'])(.*)\1$/, "$2").trim();
  if (!win32.isAbsolute(trimmed)) return null;
  return win32.resolve(trimmed);
}

/**
 * The pairs this machine can offer, running ones first. Pairs come from profiles.ini and from live
 * `--profile` processes; duplicates are dropped by normalized (zenDir, profileDir), and the profiles.ini
 * entry wins because it carries the profile's name and Zen version.
 */
export async function discoverZen(options: DiscoverOptions): Promise<Candidate[]> {
  if ((options.platform ?? process.platform) !== "win32") return [];

  const zenRoot = join(options.appData, "zen");
  const candidates: Candidate[] = [];
  const seen = new Set<string>();
  const add = (candidate: Candidate): void => {
    const key = `${normalizePath(candidate.zenDir)}\n${normalizePath(candidate.profileDir)}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push(candidate);
  };

  const profilesPath = join(zenRoot, "profiles.ini");
  if (existsSync(profilesPath)) {
    for (const [name, section] of iniSections(readFileSync(profilesPath, "utf8"))) {
      if (!/^Profile\d+$/i.test(name)) continue;
      const rawPath = section.get("Path");
      if (!rawPath) continue;
      const profileDir = resolve(section.get("IsRelative") === "0" ? rawPath : join(zenRoot, rawPath));
      const compatibility = readCompatibility(profileDir);
      if (!compatibility) continue; // never started: there is nothing to point Hirozen at
      if (!existsSync(join(compatibility.lastPlatformDir, "zen.exe"))) continue; // the install is gone
      add({
        zenDir: compatibility.lastPlatformDir,
        profileDir,
        profileName: section.get("Name") || basename(profileDir),
        zenVersion: compatibility.zenVersion,
        running: false,
        source: "profile",
      });
    }
  }

  for (const { executablePath, commandLine } of options.processes) {
    if (!executablePath) continue;
    if (/--?backgroundtask|contentproc/i.test(commandLine)) continue;
    const value = profileArg(commandLine);
    if (!value) continue;
    const zenDir = dirname(executablePath);
    if (zenDir === ".") continue;
    const profileDir = resolve(value);
    add({
      zenDir,
      profileDir,
      profileName: basename(profileDir),
      zenVersion: null,
      running: false,
      source: "process",
    });
  }

  for (const candidate of candidates) candidate.running = await options.isLocked(candidate.profileDir);
  return candidates.sort((a, b) => Number(b.running) - Number(a.running));
}
