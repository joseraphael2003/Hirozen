// Installer tests. The loader and actor sources are throwaway files: these tests must not depend on
// the contents of the real loader/*.sys.mjs (T2 owns the actor modules).
import { afterEach, expect, test } from "bun:test";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { attachScript } from "../src/attach";
import { install, sha256File, uninstall, verify } from "../src/install";

const FAKE_LOADER = "// fake hirozen loader for tests\nglobalThis.HirozenLoader = { init: () => \"ok\" };\n";
const FAKE_CHILD = "// fake hirozen actor child for tests\nexport class HirozenChild {}\n";
const FAKE_PARENT = "// fake hirozen actor parent for tests\nexport class HirozenParent {}\n";

const tempRoots: string[] = [];

afterEach(() => {
  for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

/** The three module sources one fake install reads from. */
type Sources = { loaderSource: string; childSource: string; parentSource: string };

/** A fake Zen install (dummy zen.exe, channel-prefs.js) plus the three fake sources next to it. */
function makeZenDir(): { zenDir: string } & Sources {
  const root = mkdtempSync(join(tmpdir(), "hirozen-install-"));
  tempRoots.push(root);
  const zenDir = join(root, "zen");
  const prefDir = join(zenDir, "defaults", "pref");
  mkdirSync(prefDir, { recursive: true });
  writeFileSync(join(zenDir, "zen.exe"), "dummy executable\n");
  writeFileSync(join(prefDir, "channel-prefs.js"), 'pref("app.update.channel", "release");\n');
  const loaderSource = join(root, "loader.sys.mjs");
  const childSource = join(root, "HirozenChild.sys.mjs");
  const parentSource = join(root, "HirozenParent.sys.mjs");
  writeFileSync(loaderSource, FAKE_LOADER);
  writeFileSync(childSource, FAKE_CHILD);
  writeFileSync(parentSource, FAKE_PARENT);
  return { zenDir, loaderSource, childSource, parentSource };
}

/** The install()/verify() options for one fake install. */
function sources(fake: Sources): Sources {
  const { loaderSource, childSource, parentSource } = fake;
  return { loaderSource, childSource, parentSource };
}

test("refuses to install when another defaults/pref/*.js sets general.config.filename", () => {
  const fake = makeZenDir();
  const foreign = join(fake.zenDir, "defaults", "pref", "sine-prefs.js");
  writeFileSync(foreign, 'pref("general.config.filename", "sine.cfg");\n');

  expect(() => install(fake.zenDir, sources(fake))).toThrow(/autoconfig/i);

  expect(existsSync(join(fake.zenDir, "hirozen.cfg"))).toBe(false);
  expect(existsSync(join(fake.zenDir, "hirozen"))).toBe(false);
  expect(existsSync(join(fake.zenDir, "defaults", "pref", "hirozen-prefs.js"))).toBe(false);
  expect(existsSync(foreign)).toBe(true);
  expect(readFileSync(foreign, "utf8")).toBe('pref("general.config.filename", "sine.cfg");\n');
});

test("install pins all three modules and returns their hashes", () => {
  const fake = makeZenDir();

  const written = install(fake.zenDir, sources(fake));

  expect(written).toEqual({
    loaderSha256: sha256File(fake.loaderSource),
    childSha256: sha256File(fake.childSource),
    parentSha256: sha256File(fake.parentSource),
  });
  const cfg = readFileSync(join(fake.zenDir, "hirozen.cfg"), "utf8");
  for (const sha of Object.values(written)) expect(cfg).toContain(sha);
});

test("verify reports a loader mismatch by module name", () => {
  const fake = makeZenDir();
  install(fake.zenDir, sources(fake));

  expect(verify(fake.zenDir, sources(fake))).toMatchObject({ ok: true, mismatch: null });

  appendFileSync(join(fake.zenDir, "hirozen", "loader.sys.mjs"), "// tampered with while installed\n");
  const result = verify(fake.zenDir, sources(fake));

  expect(result.ok).toBe(false);
  expect(result.mismatch).toBe("loader.sys.mjs");
  expect(result.reason).toContain("loader.sys.mjs");
  expect(result.installedSha).not.toBe(result.sourceSha);
  expect(result.sourceSha).not.toBeNull();
  // installedSha/sourceSha stay as loader aliases for /hirozen-status; null pairs with a null group.
  expect(result.installed?.loader).toBe(result.installedSha ?? undefined);
  expect(result.source?.loader).toBe(result.sourceSha ?? undefined);
});

test("verify names the actor child when it is tampered with", () => {
  const fake = makeZenDir();
  install(fake.zenDir, sources(fake));

  appendFileSync(join(fake.zenDir, "hirozen", "HirozenChild.sys.mjs"), "// tampered with while installed\n");
  const result = verify(fake.zenDir, sources(fake));

  expect(result.ok).toBe(false);
  expect(result.mismatch).toBe("HirozenChild.sys.mjs");
  expect(result.reason).toContain("HirozenChild.sys.mjs");
  expect(result.installed?.child).not.toEqual(result.source?.child);
  expect(result.installedSha).toEqual(result.sourceSha);
});

test("verify rejects an installed hirozen.cfg that does not pin every module", () => {
  const fake = makeZenDir();
  install(fake.zenDir, sources(fake));
  const cfg = join(fake.zenDir, "hirozen.cfg");
  writeFileSync(cfg, readFileSync(cfg, "utf8").replace(sha256File(fake.childSource), "0".repeat(64)));

  const result = verify(fake.zenDir, sources(fake));

  expect(result.ok).toBe(false);
  expect(result.mismatch).toBe("hirozen.cfg");
  expect(result.reason).toContain("HirozenChild.sys.mjs");
});

test("attachScript substitutes all three pins and leaves no placeholder behind", () => {
  const script = attachScript({ loader: "a".repeat(64), child: "b".repeat(64), parent: "f".repeat(64) });

  expect(script).not.toContain("@@");
  expect(script).toContain("a".repeat(64));
  expect(script).toContain("b".repeat(64));
  expect(script).toContain("f".repeat(64));
});

test("attachScript refuses a non-hex pin", () => {
  expect(() => attachScript({ loader: "a".repeat(64), child: "not-hex", parent: "f".repeat(64) })).toThrow(/non-hex/);
  expect(() => attachScript({ loader: "a".repeat(64), child: "b".repeat(64), parent: "f".repeat(64) })).not.toThrow();
});

test("uninstall removes only hirozen files", () => {
  const fake = makeZenDir();
  install(fake.zenDir, sources(fake));
  const channel = join(fake.zenDir, "defaults", "pref", "channel-prefs.js");
  const untouched = join(fake.zenDir, "browser", "application.ini");
  mkdirSync(join(fake.zenDir, "browser"), { recursive: true });
  writeFileSync(untouched, "[App]\nVendor=zen\n");

  uninstall(fake.zenDir);

  for (const artifact of [
    "hirozen.cfg",
    "hirozen",
    "hirozen/loader.sys.mjs",
    "hirozen/HirozenChild.sys.mjs",
    "hirozen/HirozenParent.sys.mjs",
    "defaults/pref/hirozen-prefs.js",
  ]) {
    expect(existsSync(join(fake.zenDir, artifact))).toBe(false);
  }
  expect(existsSync(channel)).toBe(true);
  expect(readFileSync(channel, "utf8")).toBe('pref("app.update.channel", "release");\n');
  expect(existsSync(join(fake.zenDir, "zen.exe"))).toBe(true);
  expect(readFileSync(untouched, "utf8")).toBe("[App]\nVendor=zen\n");
});
