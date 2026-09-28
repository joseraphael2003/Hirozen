# Hirozen

An [oh-my-pi](https://github.com/can1357/oh-my-pi) (omp) plugin that gives the omp agent read-only access to your running [Zen](https://github.com/zen-browser/desktop) browser. Think "Gemini in Chrome", but for Zen and driven by the models you already use in omp.

The agent can list your tabs and spaces, read page text and take screenshots of the tabs you choose. It cannot click, type or navigate yet; that is planned for V2.

> **Status:** 0.1.2. Verified on Zen 1.22.3b (Gecko 156.0.1) on Windows, on a test install only. See [CHANGELOG.md](CHANGELOG.md).

## How it works

```
omp + Hirozen plugin  <── authenticated loopback WebSocket ──  Hirozen loader (inside Zen)
                                                                   │
                                                                   └─ WebDriver BiDi, started at runtime
```

- **Loader.** A small privileged module in Zen's install folder, loaded by an autoconfig file. It loads only if its SHA-256 matches the pinned hash, never opens a listening port, and connects out to omp.
- **Link.** omp listens on `127.0.0.1` and writes a single-use handoff file into the profile. Each side proves it knows the shared secret (HMAC challenge in both directions). Only one omp session can own Zen at a time.
- **BiDi on demand.** The first `browser_*` call starts Firefox's WebDriver BiDi in non-automation mode. Sites still see `navigator.webdriver === false`. Zen asks you with its own **"Allow remote control?"** prompt first, and BiDi stops again when omp disconnects.

## Tools

| Tool | What it does |
|---|---|
| `zen_tabs` | Lists tabs in every window and space, without loading unloaded tabs. |
| `zen_spaces` | Lists your spaces and which one is active. |
| `browser_read` | Returns the readable text of a tab, capped at 40,000 characters. |
| `browser_screenshot` | Takes a PNG screenshot of a tab. |

Tools run only in the interactive root omp session. Subagents and headless runs are refused.

## Commands

| Command | Purpose |
|---|---|
| `/hirozen-install` | Installs or verifies the autoconfig and loader in `HIROZEN_ZEN_DIR`. Restart Zen once afterwards. |
| `/hirozen-attach` | Loads the loader into an already-running Zen without a restart, through a one-time debugger connection. |
| `/hirozen-connect` | Reconnects after you pressed Stop in Zen. |
| `/hirozen-status` | Shows install, link and BiDi state. |

## Setup

Requirements: omp, [Bun](https://bun.sh) and a Zen install you can write to.

```sh
git clone https://github.com/joseraphael2003/Hirozen.git
cd Hirozen
bun install
omp plugin link .
```

Set both environment variables. There are no defaults:

```sh
HIROZEN_ZEN_DIR=<folder containing zen.exe>
HIROZEN_PROFILE=<full path to the Zen profile folder>
```

Then run `/hirozen-install` in omp and restart Zen once. Alternatively, use `/hirozen-attach` to skip the restart (it needs the two DevTools remote-debugging prefs switched on temporarily; the command explains how).

> Back up your profile before trying Hirozen on your everyday Zen. It has only been validated on a separate portable install so far.

## Safety

- **Consent.** Nothing reads your pages until you click Allow in Zen. Deny returns `E_DENIED`.
- **Visible.** While connected, every Zen window shows a notice naming the omp process, with a **Stop** button. Stop is sticky until you run `/hirozen-connect`.
- **Private windows are never exposed.** Tabs are never loaded, activated or closed.
- **Compromise detection.** If another client already controls Zen's Remote Agent, Hirozen stops it, warns you in Zen and refuses to continue (`E_COMPROMISE`).
- **Firefox's own controls win.** Firefox's "Disconnect" or "Turn off remote control" ends the session until `/hirozen-connect`. "Disable remote control permanently" is remembered: `browser_*` return `E_DISABLED_IN_ZEN` until you re-enable `remote.experimental.dynamicstart.enabled` in about:config.
- **Never kills Zen.** It checks port 9222 before starting BiDi. If the port is busy, `zen_*` keep working and `browser_*` return `E_PORT_BUSY`.
- **Tamper check.** A modified loader is refused at Zen startup and reported by omp as `E_STALE_LOADER`.

## Troubleshooting

**`E_PORT_BUSY` while nothing is using 9222.** Windows (WinNAT/HNS, used by WSL2, Hyper-V and Docker) may have reserved a port range covering it. Check with:

```sh
netsh int ipv4 show excludedportrange protocol=tcp
```

To reserve 9222 for yourself, run this in an admin terminal (it briefly interrupts WSL/Docker networking):

```sh
net stop winnat
netsh int ipv4 add excludedportrange protocol=tcp startport=9222 numberofports=1
net start winnat
```

## Development

```sh
bun test
bunx tsc --noEmit
node --check loader/loader.sys.mjs
```

Changing `loader/loader.sys.mjs` changes its hash, so run `/hirozen-install` again afterwards.

## Roadmap

- **V2 (planned design: loader-first, BiDi on demand):** reading, screenshots and page input move into the Hirozen loader itself, so everyday use needs no port 9222 and no Firefox remote-control dialog; Hirozen shows its own Allow/Deny prompt in Zen instead. WebDriver BiDi is started only for features that need it (file uploads, network inspection, page dialogs). On top of that: clicking, typing and navigation behind omp approvals, a page element snapshot, and Zen layout actions (glance, split view, moving tabs).
- **Later:** background research tasks in a dedicated space, and support for sites that publish WebMCP tools.

## License

No license has been chosen yet.
