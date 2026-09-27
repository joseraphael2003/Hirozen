// Installer tests. The loader source is a throwaway file: these tests must not depend on
// the contents of the real loader/loader.sys.mjs (T2 owns it).
import { afterEach, expect, test } from "bun:test";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { install, uninstall, verify } from "../src/install";

const FAKE_LOADER = "// fake hirozen loader for tests\nglobalThis.HirozenLoader = { init: () => \"ok\" };\n";

const tempRoots: string[] = [];

afterEach(() => {
  for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

/** A fake Zen install (dummy zen.exe, channel-prefs.js) plus a fake loader source next to it. */
function makeZenDir(): { zenDir: string; loaderSource: string } {
  const root = mkdtempSync(join(tmpdir(), "hirozen-install-"));
  tempRoots.push(root);
  const zenDir = join(root, "zen");
  const prefDir = join(zenDir, "defaults", "pref");
  mkdirSync(prefDir, { recursive: true });
  writeFileSync(join(zenDir, "zen.exe"), "dummy executable\n");
  writeFileSync(join(prefDir, "channel-prefs.js"), 'pref("app.update.channel", "release");\n');
  const loaderSource = join(root, "loader.sys.mjs");
  writeFileSync(loaderSource, FAKE_LOADER);
  return { zenDir, loaderSource };
}

test("refuses to install when another defaults/pref/*.js sets general.config.filename", () => {
  const { zenDir, loaderSource } = makeZenDir();
  const foreign = join(zenDir, "defaults", "pref", "sine-prefs.js");
  writeFileSync(foreign, 'pref("general.config.filename", "sine.cfg");\n');

  expect(() => install(zenDir, { loaderSource })).toThrow(/autoconfig/i);

  expect(existsSync(join(zenDir, "hirozen.cfg"))).toBe(false);
  expect(existsSync(join(zenDir, "hirozen"))).toBe(false);
  expect(existsSync(join(zenDir, "defaults", "pref", "hirozen-prefs.js"))).toBe(false);
  expect(existsSync(foreign)).toBe(true);
  expect(readFileSync(foreign, "utf8")).toBe('pref("general.config.filename", "sine.cfg");\n');
});

test("verify reports a mismatch after the installed loader is edited", () => {
  const { zenDir, loaderSource } = makeZenDir();
  install(zenDir, { loaderSource });

  expect(verify(zenDir, { loaderSource }).ok).toBe(true);

  const installed = join(zenDir, "hirozen", "loader.sys.mjs");
  appendFileSync(installed, "// tampered with while installed\n");
  const result = verify(zenDir, { loaderSource });

  expect(result.ok).toBe(false);
  expect(result.installedSha).not.toBe(result.sourceSha);
  expect(result.sourceSha).not.toBeNull();
});

test("uninstall removes only hirozen files", () => {
  const { zenDir, loaderSource } = makeZenDir();
  install(zenDir, { loaderSource });
  const channel = join(zenDir, "defaults", "pref", "channel-prefs.js");
  const untouched = join(zenDir, "browser", "application.ini");
  mkdirSync(join(zenDir, "browser"), { recursive: true });
  writeFileSync(untouched, "[App]\nVendor=zen\n");

  uninstall(zenDir);

  expect(existsSync(join(zenDir, "hirozen.cfg"))).toBe(false);
  expect(existsSync(join(zenDir, "hirozen"))).toBe(false);
  expect(existsSync(join(zenDir, "defaults", "pref", "hirozen-prefs.js"))).toBe(false);
  expect(existsSync(channel)).toBe(true);
  expect(readFileSync(channel, "utf8")).toBe('pref("app.update.channel", "release");\n');
  expect(existsSync(join(zenDir, "zen.exe"))).toBe(true);
  expect(readFileSync(untouched, "utf8")).toBe("[App]\nVendor=zen\n");
});
