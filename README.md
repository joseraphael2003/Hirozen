# Hirozen

An [oh-my-pi](https://github.com/can1357/oh-my-pi) (omp) plugin that lets the omp agent work in your running [Zen](https://github.com/zen-browser/desktop) browser. Think "Gemini in Chrome", but for Zen and driven by the models you already use in omp.

The agent can list your tabs and spaces, read pages, take screenshots, click, type, navigate, upload files, answer page dialogs, and arrange tabs with Zen's own layout features (spaces, split view, glance).

> **Status:** 0.2.0. Verified on Zen 1.22.3b (Gecko 156.0.1) on Windows, on a test install only. See [CHANGELOG.md](CHANGELOG.md).

## How it works

```
omp + Hirozen plugin  <── authenticated loopback WebSocket ──  Hirozen loader (inside Zen)
                                                                   │
                                                                   └─ Hirozen content actor (in each page)
```

- **Loader.** A small privileged module in Zen's install folder, loaded by an autoconfig file, together with a content actor that reads and acts inside pages. All three files load only if their SHA-256 hashes match the pinned ones. The loader never opens a listening port; it connects out to omp.
- **Link.** omp listens on `127.0.0.1` and writes a single-use handoff file into the profile. Each side proves it knows the shared secret (HMAC challenge in both directions). Only one omp session can own Zen at a time.
- **No remote protocol.** Hirozen does not use WebDriver BiDi, CDP or port 9222. Clicks and key presses are real browser input events (`isTrusted`), so pages treat them like yours.

## Tools

| Tool | What it does |
|---|---|
| `zen_tabs` | Lists tabs in every window and space, without loading unloaded tabs. |
| `zen_spaces` | Lists your spaces and which one is active. |
| `browser_read` | Returns the readable text of a tab, capped at 40,000 characters. |
| `browser_screenshot` | Takes a PNG screenshot of a tab. |
| `browser_snapshot` | Lists a tab's clickable and typeable elements with short refs (up to 400). |
| `browser_act` | Clicks, types, presses a key, scrolls or navigates (http/https only). |
| `browser_upload` | Sets local files on a page's file input. |
| `browser_dialog` | Accepts or dismisses a page's `alert`/`confirm`/`prompt` (with optional text). |
| `zen_open` | Opens a URL in the background in a "Hirozen Agent" space, without switching your space. |
| `zen_move` | Moves a tab to another space. |
| `zen_split` / `zen_unsplit` | Puts tabs in a split view, or takes one out. Never includes your selected tab. |
| `zen_glance` | Opens an http(s) URL in a glance. |

Every tool except `zen_tabs`, `zen_spaces`, `browser_read`, `browser_screenshot` and `browser_snapshot` asks for omp approval first, showing the tab and the target (for example `button "Save"`). Tools run only in the interactive root omp session. Subagents and headless runs are refused.

## Commands

| Command | Purpose |
|---|---|
| `/hirozen-install` | Installs or verifies the autoconfig, loader and actor in `HIROZEN_ZEN_DIR`. Restart Zen once afterwards. |
| `/hirozen-attach` | Loads Hirozen into an already-running Zen without a restart, through a one-time debugger connection. |
| `/hirozen-connect` | Reconnects after you pressed Stop in Zen. |
| `/hirozen-status` | Shows install, link and consent state. |

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

Then run `/hirozen-install` in omp and restart Zen once. Alternatively, use `/hirozen-attach` to skip the restart (it needs the two DevTools remote-debugging prefs switched on temporarily, and you click OK on Zen's "Incoming Connection" prompt; the command explains how).

> Back up your profile before trying Hirozen on your everyday Zen. It has only been validated on a separate portable install so far.

## Safety

- **Consent in Zen.** The first read asks in Zen: "omp pid … wants to read pages". Acting (clicks, typing, uploads, dialogs, layout) asks again for "read and act". Deny returns `E_DENIED`, and an unanswered prompt is denied after 120 s. The terminal tells you when Zen is waiting for you.
- **Approval in omp.** Each action is also approved in omp, with the tab and target shown.
- **Visible.** While connected, every Zen window shows a notice naming the omp process and what it may do, with a **Stop** button. Stop is sticky until you run `/hirozen-connect`.
- **Your view stays yours.** `zen_open` works in the "Hirozen Agent" space; popups from agent tabs stay there, and your space and selected tab are restored.
- **Private windows and privileged pages are never exposed** (`E_PRIVATE`, `E_PRIVILEGED_PAGE`). Tabs in your other inactive spaces are refused (`E_TAB_INACTIVE_SPACE`); tabs in the agent space are not.
- **No late actions.** Each request carries omp's deadline; if Zen is still waiting when omp gives up, the loader does nothing (`E_DEADLINE`).
- **Tamper check.** A modified loader or actor is refused at Zen startup and reported by omp as `E_STALE_LOADER`.

## Development

```sh
bun test
bunx tsc --noEmit
node --check loader/loader.sys.mjs
node --check loader/HirozenChild.sys.mjs
```

Changing any file in `loader/` changes its hash, so run `/hirozen-install` again afterwards.

## Roadmap

- **Later:** background research tasks in the agent space, network inspection, and support for sites that publish WebMCP tools.

## License

No license has been chosen yet.
