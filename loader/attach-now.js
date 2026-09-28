// Evaluated once over the one-shot RDP connection in the running Zen's parent process.
// Verifies the three pinned module hashes, loads the loader, turns the DevTools prefs back off, then
// closes the RDP listener last (closing it kills this connection, so the close is dispatched after the
// result is returned).
//
// Refusals and errors are appended to <profile>/hirozen-autoconfig.txt - the same log the startup
// autoconfig writes - so a failed attach can still be diagnosed once the RDP connection is gone.
(() => {
  // [role the loader's init() expects, file under hirozen/, pinned hex]
  const MODULES = [
    ["loader", "loader.sys.mjs", "@@LOADER_SHA256@@"],
    ["child", "HirozenChild.sys.mjs", "@@CHILD_SHA256@@"],
    ["parent", "HirozenParent.sys.mjs", "@@PARENT_SHA256@@"],
  ];
  const { classes: Cc, interfaces: Ci } = Components;

  const report = text => {
    try {
      const f = Services.dirsvc.get("ProfD", Ci.nsIFile);
      f.append("hirozen-autoconfig.txt");
      const out = Cc["@mozilla.org/network/file-output-stream;1"].createInstance(Ci.nsIFileOutputStream);
      out.init(f, 0x02 | 0x08 | 0x20, 0o600, 0);
      const line = `${new Date().toISOString()} attach-now: ${text}\n`;
      out.write(line, line.length);
      out.close();
    } catch {
      // Best-effort diagnostics: a failed log line must never keep the DevTools prefs on.
    }
  };

  // Hex SHA-256 of one file in the hirozen directory; an unreadable file throws and is reported below.
  const hashFile = (dir, name) => {
    const file = dir.clone();
    file.append(name);
    const stream = Cc["@mozilla.org/network/file-input-stream;1"].createInstance(Ci.nsIFileInputStream);
    stream.init(file, 0x01, 0, 0);
    const hasher = Cc["@mozilla.org/security/hash;1"].createInstance(Ci.nsICryptoHash);
    hasher.init(Ci.nsICryptoHash.SHA256);
    hasher.updateFromStream(stream, 0xffffffff);
    stream.close();
    return Array.from(hasher.finish(false), c => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  };

  const result = { hashes: null, loader: null, prefsAfter: null };
  try {
    const dir = Services.dirsvc.get("GreD", Ci.nsIFile);
    dir.append("hirozen");
    const hashes = {};
    const refused = [];
    for (const [role, name, pinned] of MODULES) {
      hashes[role] = hashFile(dir, name);
      if (hashes[role] !== pinned) refused.push(`${name} hash ${hashes[role]} != pinned ${pinned}`);
    }
    result.hashes = hashes;
    if (refused.length > 0) {
      result.loader = "refused: hash mismatch";
      report(`refused: ${refused.join("; ")}`);
    } else {
      Services.io.getProtocolHandler("resource").QueryInterface(Ci.nsIResProtocolHandler)
        .setSubstitution("hirozen", Services.io.newFileURI(dir));
      const { HirozenLoader } = ChromeUtils.importESModule("resource://hirozen/loader.sys.mjs");
      result.loader = HirozenLoader.init("attach", hashes);
      report(`loaded (loader ${hashes.loader}): ${result.loader}`);
    }
  } catch (e) {
    result.loader = `error: ${e}`;
    report(`error: ${e}`);
  }

  // Fail closed on every path above: the DevTools prefs and the listener never outlive this eval.
  Services.prefs.setBoolPref("devtools.debugger.remote-enabled", false);
  Services.prefs.setBoolPref("devtools.chrome.enabled", false);
  result.prefsAfter = {
    remoteEnabled: Services.prefs.getBoolPref("devtools.debugger.remote-enabled"),
    chromeEnabled: Services.prefs.getBoolPref("devtools.chrome.enabled"),
  };
  Services.tm.dispatchToMainThread(() => {
    const { useDistinctSystemPrincipalLoader, releaseDistinctSystemPrincipalLoader } = ChromeUtils.importESModule(
      "resource://devtools/shared/loader/DistinctSystemPrincipalLoader.sys.mjs"
    );
    // The same shared loader DevToolsStartup used for the flag-started listener, so this closes
    // exactly that listener (and drops this RDP connection).
    const holder = {};
    const loader = useDistinctSystemPrincipalLoader(holder);
    const { DevToolsServer } = loader.require("resource://devtools/server/devtools-server.js");
    DevToolsServer.closeAllSocketListeners();
    releaseDistinctSystemPrincipalLoader(holder);
  });
  return JSON.stringify(result);
})()
