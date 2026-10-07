// Discovery tests. The fixture machine mirrors this one: a `%APPDATA%/zen` with a BOM + CRLF
// profiles.ini carrying [Install…]/[General]/[BackgroundTasksProfiles] sections, one valid pair, a
// profile whose install folder is gone, a profile with no compatibility.ini, and a profile whose Path
// is absolute. The filesystem is real (temp dirs) because discoverZen reads profiles.ini and proves
// `<zenDir>/zen.exe` exists; the process list and the lock probe are injected.
import { afterEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { parseZenProcesses, profileArg, type ZenProcess } from "../src/attach";
import { discoverZen, normalizeManualPath, readCompatibility } from "../src/discover";

const tempRoots: string[] = [];

afterEach(() => {
  for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function tempRoot(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  tempRoots.push(root);
  return root;
}

/** A Zen install folder with the `zen.exe` marker discoverZen insists on. */
function installAt(root: string, name: string): string {
  const zenDir = join(root, name);
  mkdirSync(zenDir, { recursive: true });
  writeFileSync(join(zenDir, "zen.exe"), "dummy executable\n");
  return zenDir;
}

/** One profile folder with a compatibility.ini; `lastVersion` may be omitted (a partial file). */
function profileAt(zenRoot: string, folder: string, lastPlatformDir: string, lastVersion?: string): string {
  const profileDir = join(zenRoot, "Profiles", folder);
  mkdirSync(profileDir, { recursive: true });
  const version = lastVersion === undefined ? "" : `LastVersion=${lastVersion}\r\n`;
  writeFileSync(
    join(profileDir, "compatibility.ini"),
    `[Compatibility]\r\n${version}LastOSABI=WINNT_x86_64-msvc\r\nLastPlatformDir=${lastPlatformDir}\r\nLastAppDir=${lastPlatformDir}/browser\r\n`,
  );
  return profileDir;
}

type Machine = {
  appData: string;
  /** D:\PROGRAMS: the install the daily profile last ran from. */
  install: string;
  /** A second live install, used by the profile whose Path is absolute. */
  other: string;
  /** D:\ProgramFiles\Zen: removed, so the sjbtc113 profile has no zen.exe. */
  gone: string;
  dailyProfile: string;
  staleProfile: string;
  unusedProfile: string;
  absProfile: string;
  /** A profile folder no profiles.ini section mentions, for the process candidates. */
  extraProfile: string;
  dashProfile: string;
};

function makeMachine(): Machine {
  const root = tempRoot("hirozen-discover-");
  const appData = join(root, "AppData", "Roaming");
  const zenRoot = join(appData, "zen");
  const install = installAt(root, "PROGRAMS");
  const other = installAt(root, "Other");
  const gone = join(root, "ProgramFiles", "Zen");
  const dailyProfile = profileAt(zenRoot, "txwpgy8w.Default (release)-1", install, "1.23.1b_20261006042626/20261006042626");
  const staleProfile = profileAt(zenRoot, "sjbtc113.Default (release)", gone, "1.19.13b_20260514074226/20260514074226");
  const absProfile = profileAt(zenRoot, "absc1xyz.Absolute Profile", other, "1.22.3b_20260101000000/20260101000000");
  // wp46hrwo: Default=1 in profiles.ini, never started, so it has no compatibility.ini at all.
  const unusedProfile = join(zenRoot, "Profiles", "wp46hrwo.Default Profile");
  mkdirSync(unusedProfile, { recursive: true });
  writeFileSync(join(unusedProfile, "times.json"), "{}\n");
  const extraProfile = join(root, "Elsewhere", "extra1.Some Profile");
  const dashProfile = join(root, "Elsewhere", "dash1.Other");

  // The real file, section for section: [ProfileN] sections only, `/` separators, BOM and CRLF.
  const ini =
    "\uFEFF" +
    "[Profile2]\r\nName=Default (release)-1\r\nIsRelative=1\r\nPath=Profiles/txwpgy8w.Default (release)-1\r\n\r\n" +
    "[Profile1]\r\nName=Default Profile\r\nIsRelative=1\r\nPath=Profiles/wp46hrwo.Default Profile\r\nDefault=1\r\n\r\n" +
    "[Install803FE4F559876FB3]\r\nDefault=Profiles/sjbtc113.Default (release)\r\nLocked=1\r\n\r\n" +
    "[Profile0]\r\nName=Default (release)\r\nIsRelative=1\r\nPath=Profiles/sjbtc113.Default (release)\r\n\r\n" +
    `[Profile3]\r\nName=Absolute Profile\r\nIsRelative=0\r\nPath=${absProfile}\r\n\r\n` +
    "[Install5E6DAC7B34B70C28]\r\nDefault=Profiles/txwpgy8w.Default (release)-1\r\nLocked=1\r\n\r\n" +
    "[General]\r\nStartWithLastProfile=1\r\nVersion=2\r\n\r\n" +
    "[BackgroundTasksProfiles]\r\n" +
    "MozillaBackgroundTask-803FE4F559876FB3-defaultagent=i22z0tot.MozillaBackgroundTask-803FE4F559876FB3-defaultagent\r\n";
  writeFileSync(join(zenRoot, "profiles.ini"), ini);

  return {
    appData,
    install,
    other,
    gone,
    dailyProfile,
    staleProfile,
    unusedProfile,
    absProfile,
    extraProfile,
    dashProfile,
  };
}

test("readCompatibility reads LastPlatformDir and LastVersion, never LastAppDir", () => {
  const m = makeMachine();
  expect(readCompatibility(m.dailyProfile)).toEqual({ lastPlatformDir: m.install, zenVersion: "1.23.1b" });

  const root = tempRoot("hirozen-compat-");
  const appOnly = join(root, "apponly");
  mkdirSync(appOnly, { recursive: true });
  writeFileSync(join(appOnly, "compatibility.ini"), `[Compatibility]\r\nLastAppDir=${join(root, "install", "browser")}\r\n`);
  expect(readCompatibility(appOnly)).toBeNull();

  const partial = join(root, "partial");
  mkdirSync(partial, { recursive: true });
  writeFileSync(join(partial, "compatibility.ini"), `[Compatibility]\r\nLastPlatformDir=${m.install}\r\n`);
  expect(readCompatibility(partial)).toEqual({ lastPlatformDir: m.install, zenVersion: null });

  expect(readCompatibility(m.unusedProfile)).toBeNull();
  expect(readCompatibility(join(root, "missing"))).toBeNull();
});

test("discoverZen keeps only [ProfileN] pairs whose install still has zen.exe", async () => {
  const m = makeMachine();
  const candidates = await discoverZen({ appData: m.appData, processes: [], isLocked: async () => false, platform: "win32" });

  expect(candidates).toEqual([
    {
      zenDir: m.install,
      profileDir: m.dailyProfile,
      profileName: "Default (release)-1",
      zenVersion: "1.23.1b",
      running: false,
      source: "profile",
    },
    {
      zenDir: m.other,
      profileDir: m.absProfile,
      profileName: "Absolute Profile",
      zenVersion: "1.22.3b",
      running: false,
      source: "profile",
    },
  ]);
});

test("running candidates come first and the flag is the lock probe, not the process list", async () => {
  const m = makeMachine();
  const processes: ZenProcess[] = [
    { pid: 2376, executablePath: join(m.install, "zen.exe"), commandLine: `"${join(m.install, "zen.exe")}"` },
  ];
  const candidates = await discoverZen({
    appData: m.appData,
    processes,
    isLocked: async profileDir => profileDir === m.absProfile,
    platform: "win32",
  });

  expect(candidates.map(c => [c.profileName, c.running])).toEqual([
    ["Absolute Profile", true],
    ["Default (release)-1", false],
  ]);
});

test("a --profile process adds a candidate; content and background-task rows do not; pairs are deduped", async () => {
  const m = makeMachine();
  const exe = join(m.other, "zen.exe");
  const processes: ZenProcess[] = [
    // The daily main process carries no --profile (it uses the default profile): no candidate.
    { pid: 2376, executablePath: join(m.install, "zen.exe"), commandLine: `"${join(m.install, "zen.exe")}"` },
    // Same pair as the absolute-Path profile in profiles.ini: deduped, and the profile wins.
    { pid: 4000, executablePath: exe, commandLine: `"${exe}" --profile "${m.absProfile}"` },
    { pid: 4001, executablePath: exe, commandLine: `"${exe}" -contentproc -parentPid 2376` },
    { pid: 4002, executablePath: exe, commandLine: `"${exe}" --backgroundtask backgroundupdate` },
    { pid: 4003, executablePath: exe, commandLine: `"${exe}" --profile "${m.extraProfile}"` },
    { pid: 4004, executablePath: exe, commandLine: `"${exe}" -profile "${m.dashProfile}"` },
  ];
  const candidates = await discoverZen({ appData: m.appData, processes, isLocked: async () => false, platform: "win32" });

  expect(candidates).toEqual([
    {
      zenDir: m.install,
      profileDir: m.dailyProfile,
      profileName: "Default (release)-1",
      zenVersion: "1.23.1b",
      running: false,
      source: "profile",
    },
    {
      zenDir: m.other,
      profileDir: m.absProfile,
      profileName: "Absolute Profile",
      zenVersion: "1.22.3b",
      running: false,
      source: "profile",
    },
    {
      zenDir: dirname(exe),
      profileDir: m.extraProfile,
      profileName: "extra1.Some Profile",
      zenVersion: null,
      running: false,
      source: "process",
    },
    {
      zenDir: dirname(exe),
      profileDir: m.dashProfile,
      profileName: "dash1.Other",
      zenVersion: null,
      running: false,
      source: "process",
    },
  ]);
});

test("no discovery off Windows: manual entry is the only way in", async () => {
  const m = makeMachine();
  const processes: ZenProcess[] = [
    { pid: 4003, executablePath: join(m.other, "zen.exe"), commandLine: `"${join(m.other, "zen.exe")}" --profile "${m.extraProfile}"` },
  ];
  expect(await discoverZen({ appData: m.appData, processes, isLocked: async () => false, platform: "linux" })).toEqual([]);
});

test("manual paths are trimmed, unquoted, must be win32-absolute, and keep their resolved form", () => {
  expect(normalizeManualPath('  "D:\\PROGRAMS"  ')).toBe("D:\\PROGRAMS");
  expect(normalizeManualPath("'D:\\PROGRAMS\\'")).toBe("D:\\PROGRAMS");
  expect(normalizeManualPath("D:/PROGRAMS")).toBe("D:\\PROGRAMS");
  expect(normalizeManualPath("\\\\server\\share\\Zen")).toBe("\\\\server\\share\\Zen");
  // Drive-relative: win32.resolve would take the drive from omp's cwd, so these are refused.
  expect(normalizeManualPath("\\PROGRAMS")).toBeNull();
  expect(normalizeManualPath("/PROGRAMS")).toBeNull();
  expect(normalizeManualPath("D:")).toBeNull();
  expect(normalizeManualPath("Profiles/txwpgy8w.Default (release)-1")).toBeNull();
  expect(normalizeManualPath("   ")).toBeNull();
});

test("the --profile argument is read quoted or bare, and -profile works too", () => {
  expect(profileArg('"C:\\zen\\zen.exe" --profile "C:\\p\\A B"')).toBe("C:\\p\\A B");
  expect(profileArg("C:\\zen\\zen.exe --profile C:\\p\\Plain")).toBe("C:\\p\\Plain");
  expect(profileArg("C:\\zen\\zen.exe -profile 'C:\\p\\Single'")).toBe("C:\\p\\Single");
  expect(profileArg('"C:\\zen\\zen.exe" --noprofile')).toBeNull();
  expect(profileArg('"C:\\zen\\zen.exe"')).toBeNull();
});

test("the three-column process rows parse into pid / executable / command line", () => {
  const output = [
    "2376\tD:\\PROGRAMS\\zen.exe\t\"D:\\PROGRAMS\\zen.exe\"",
    "4000\tD:\\Other\\zen.exe\t\"D:\\Other\\zen.exe\" --profile \"C:\\p\\Profiles\\x\"",
    "7\t\t--backgroundtask x",
    "",
    "notapid\ta\tb",
    "8\tC:\\x\\zen.exe",
  ].join("\r\n");

  expect(parseZenProcesses(output)).toEqual([
    { pid: 2376, executablePath: "D:\\PROGRAMS\\zen.exe", commandLine: "\"D:\\PROGRAMS\\zen.exe\"" },
    {
      pid: 4000,
      executablePath: "D:\\Other\\zen.exe",
      commandLine: "\"D:\\Other\\zen.exe\" --profile \"C:\\p\\Profiles\\x\"",
    },
    { pid: 7, executablePath: "", commandLine: "--backgroundtask x" },
  ]);
});
