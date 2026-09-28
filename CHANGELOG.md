# Changelog

All notable changes to Hirozen are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.2.0] - 2026-09-28

The agent can act in Zen. Verified on Zen 1.22.3b (Gecko 156.0.1), Windows, on a test install. Three files are installed now, so run `/hirozen-install` and restart Zen.

### Added

- Tools `browser_snapshot`, `browser_act` (click, type, press, scroll, navigate), `browser_upload`, `browser_dialog`, `zen_open`, `zen_move`, `zen_split`, `zen_unsplit` and `zen_glance`. Actions ask for omp approval with the tab and target in the details.
- Hirozen's own Allow/Deny prompt in Zen, with two levels ("read pages", "read and act on pages"), a terminal hint while it waits, and a 120 s timeout.
- A content actor (`HirozenChild.sys.mjs`) that reads pages and synthesizes trusted input; the install pins the loader, the actor child and the actor parent by hash.
- A "Hirozen Agent" space for `zen_open`; popups from its tabs stay in it, and your space and selected tab are kept.
- Per-request deadlines: the loader does nothing once omp has given up (`E_DEADLINE`).

### Changed

- WebDriver BiDi is no longer used. Reads, screenshots, uploads and page dialogs run inside Hirozen, so there is no port 9222, no Firefox "Allow remote control?" dialog and no remote-control banner. BiDi could not reach tabs in inactive Zen spaces.
- Reads are consented by Hirozen's prompt instead of Firefox's dialog.

### Removed

- Codes `E_PORT_BUSY`, `E_COMPROMISE`, `E_DISABLED_IN_ZEN`, `E_BIDI_LOST`, `E_UNSAFE_START`, `E_SYSTEM_ACCESS`, `E_STOP_FAILED`; close code 4011; the BiDi lines in `/hirozen-status`.

### Known issues

- Not yet validated on a daily profile.
- A navigate that only adds a `#fragment` to the current URL waits 12 s and reports `E_TIMEOUT`, although the page scrolled.
- `E_DENIED` repeats its reason; upload and dialog results do not show the page's URL or title.

## [0.1.2] - 2026-09-28

Follow-ups from the V1.1 final wave. Verified on Zen 1.22.3b (Gecko 156.0.1), Windows, on a test install. The loader changed, so run `/hirozen-install` and restart Zen.

### Fixed

- Reconnecting within seconds of Firefox stopping a session that was still waiting for consent no longer reports a false `E_COMPROMISE`: the loader waits out a stop that is still in flight before its rogue check.
- The sticky stop text names both Firefox buttons - "remote control was turned off in Zen (Disconnect / Turn off remote control)" - instead of only Disconnect, because the loader cannot tell the two apart.
- A call in flight when the link closes with a sticky stop (Zen's Stop, or remote control turned off) gets that stop's text; the generic "retry, or run `/hirozen-connect`" gloss remains only where retrying actually works.
- The `link.ts` error-code comment lists the V1.1 loader codes (`E_BIDI_LOST`, `E_READ_FAILED`, `E_STOP_FAILED`, `E_INTERNAL`, `E_DISABLED_IN_ZEN`) and close codes 4010/4011/4012.

### Changed

- README: the roadmap describes the planned V2 design (loader-first, WebDriver BiDi started only for features that need it), and the safety notes cover Firefox's own remote-control buttons.

## [0.1.1] - 2026-09-28

Hardening from live QA. Verified on Zen 1.22.3b (Gecko 156.0.1), Windows. The loader changed, so run `/hirozen-install` and restart Zen.

### Added

- **Heartbeat:** the loader pings omp every 5 s and drops a silent omp after 15 s (close 4012). This is not a sticky stop, so the next call reconnects.
- **Firefox's own remote-control buttons are respected:**
  - "Disconnect" and "Turn off remote control" end the session (close 4011). It stays stopped until `/hirozen-connect`, the same as Hirozen's Stop.
  - "Disable remote control permanently" is remembered across restarts: `browser_*` return `E_DISABLED_IN_ZEN` until you re-enable `remote.experimental.dynamicstart.enabled` in about:config.
- **More specific errors:** `E_BIDI_LOST`, `E_READ_FAILED`, `E_STOP_FAILED` and `E_INTERNAL`. `/hirozen-status` shows the last failed start (`lastStartError`).
- The terminal reminder to answer Zen's consent dialog repeats every 60 s.

### Changed

- **In-Zen notice:** it has no ✕ and also appears in windows opened while it is shown.
- **Hirozen resets `remote.experimental.dynamicstart.enabled` only if it set it,** so a value you set yourself is kept.

### Fixed

- omp could lock itself out with `E_IN_USE` naming its own session after a session restart during a connect.
- The owner check briefly re-reads Zen's status before refusing, so an immediate reconnect after a drop no longer fails.
- After Firefox's Disconnect, Hirozen no longer reports BiDi as still running or its own stop as failed.

### Known issues

- Firefox's "Turn off" and "Disable permanently" buttons are greyed out while the "Allow remote control?" dialog is open, so they can rarely be clicked.
- Reconnecting within seconds of Firefox stopping a session that was still waiting for consent can report a false `E_COMPROMISE`.
- Not yet checked on Firefox 158.0b1 (expected 2026-10-08). On newer Firefox, remote control creates a permanent red "remote-control-container".

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

[0.2.0]: https://github.com/joseraphael2003/Hirozen/compare/1e071bc...main
[0.1.2]: https://github.com/joseraphael2003/Hirozen/compare/21eaaec...1e071bc
[0.1.1]: https://github.com/joseraphael2003/Hirozen/compare/aeb80e4...21eaaec
[0.1.0]: https://github.com/joseraphael2003/Hirozen/commits/main
