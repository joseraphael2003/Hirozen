# Changelog

All notable changes to Hirozen are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-09-27

First release: read-only access to a running Zen browser from omp. Verified on Zen 1.22.3b (Gecko 156.0.1), Windows.

### Added

- **omp plugin** (`src/index.ts`), root interactive session only:
  - Tools `zen_tabs`, `zen_spaces`, `browser_read` (page text, 40,000-char cap), `browser_screenshot` (PNG).
  - Commands `/hirozen-install`, `/hirozen-attach`, `/hirozen-connect`, `/hirozen-status`.
  - Configured by `HIROZEN_ZEN_DIR` and `HIROZEN_PROFILE`; there is no default install path.
- **Hash-pinned loader** (`loader/`): a dormant chrome-scope module started by a Hirozen-only autoconfig. It loads only if its SHA-256 matches the pin, never listens on a port, and connects out to omp.
- **Authenticated link** (`src/link.ts`): loopback-only WebSocket with a single-use handoff file, HMAC challenge in both directions, and a single owner per Zen (`E_IN_USE`).
- **Attach without restart** (`src/attach.ts`): one-shot debugger handoff into an already-running Zen. It checks the DevTools prefs and the profile lock first, switches both DevTools prefs back off, and closes the listener last.
- **Safety rules:**
  - WebDriver BiDi starts only in non-automation mode, after a 9222 preflight, with automation prefs disabled.
  - Consent comes from Zen's own "Allow remote control?" prompt. Deny returns `E_DENIED`; a pre-existing session returns `E_COMPROMISE` with a warning in Zen.
  - Private windows are never exposed. Tabs are never loaded, activated or closed.
  - The in-Zen notice has a Stop button that works in every window; the session stays stopped until you reconnect.
  - If port 9222 is busy or reserved by Windows, `zen_*` keep working and `browser_*` return `E_PORT_BUSY`; Zen is never killed.

### Known issues

- A Windows WinNAT/HNS reserved port range can cover 9222. Check with `netsh int ipv4 show excludedportrange protocol=tcp`; fix with `net stop winnat`, `netsh int ipv4 add excludedportrange protocol=tcp startport=9222 numberofports=1`, `net start winnat`.
- Two one-off results could not be reproduced: a Deny that returned an uncaptured code, and a transient `E_IN_USE` on an immediate reconnect.
- Not yet validated on a daily profile. Click, type, navigation and Zen layout actions are planned for V2.

[0.1.0]: https://github.com/joseraphael2003/Hirozen/commits/main
