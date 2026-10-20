# Hirozen

An [oh-my-pi](https://github.com/can1357/oh-my-pi) (omp) plugin that lets the omp agent work in your running [Zen](https://github.com/zen-browser/desktop) browser. Think "Gemini in Chrome", but for Zen and driven by the models you already use in omp.

The agent can list your tabs and spaces, read pages (or just the article), take screenshots, click, type, hover, navigate, load unloaded tabs, upload files, read cookies, storage, downloads and request headers, answer page dialogs, and arrange tabs with Zen's own layout features (spaces, split view, glance).

> **Status:** 0.3.1 (compact-mode and cancellation fixes on top of the 0.3.0 build verified on Windows with Zen 1.22.3b and 1.23.3b). See [CHANGELOG.md](CHANGELOG.md).

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
| `browser_read` | Returns the readable text of a tab, capped at 40,000 characters; `mode:"article"` returns the reader-mode article instead. |
| `browser_screenshot` | Takes a PNG screenshot of a tab. |
| `browser_snapshot` | Lists a tab's clickable and typeable elements with short refs (up to 400), including inside open and closed shadow roots. |
| `browser_act` | Clicks, types, presses a key, scrolls, hovers or navigates (http/https only). |
| `browser_upload` | Sets local files on a page's file input. |
| `browser_dialog` | Accepts or dismisses a page's `alert`/`confirm`/`prompt` (with optional text). |
| `zen_open` | Opens a URL in the background in a "Hirozen Agent" space, without switching your space. |
| `zen_move` | Moves a tab to another space. |
| `zen_split` / `zen_unsplit` | Puts tabs in a split view, or takes one out. Never includes your selected tab. |
| `zen_glance` | Opens an http(s) URL in a glance. |
| `zen_load_tab` | Loads an unloaded tab in the background through Zen's own restore, without selecting it. |
| `browser_cookies` / `browser_storage` | Reads a tab's cookies, or its local/session storage or IndexedDB names. Values are hidden unless you approve `reveal:true`. |
| `browser_downloads` | Lists recent downloads. |
| `browser_network_start` / `_read` / `_stop` | Records one tab's requests (URL, status, timing, headers; cookie and auth headers redacted). |

These run without an omp prompt: `zen_tabs`, `zen_spaces`, `browser_read`, `browser_screenshot`, `browser_snapshot`, `browser_downloads`, `browser_network_read` and `browser_network_stop`, plus `browser_cookies` and `browser_storage` unless `reveal:true`. `browser_act` clicks, typing, keys, scrolling and hover skip the prompt while a `/hirozen-grant` covers them. Every other call asks for omp approval first, showing the tab and the target (for example `button "Save"`). All of them still need the matching permission in Zen. Tools run only in the interactive root omp session. Subagents and headless runs are refused.

## Commands

| Command | Purpose |
|---|---|
| `/hirozen-setup` | Finds the Zen installs and profiles on this machine; you pick one and confirm, and it is saved in omp's plugin settings. `/hirozen-setup clear` forgets it. |
| `/hirozen-install` | Installs or verifies the autoconfig, loader and actor in the configured Zen install. Restart Zen once afterwards. |
| `/hirozen-attach` | Loads Hirozen into an already-running Zen without a restart, through a one-time debugger connection. |
| `/hirozen-connect` | Reconnects after you pressed Stop in Zen. |
| `/hirozen-grant` | `/hirozen-grant <tabKey|origin> <minutes 1-60>` lets clicks, typing, keys, scrolling and hover run without omp prompts: a tabKey covers that one tab while it stays on the site it was on, an origin covers every tab on that site; `/hirozen-grant clear` ends it. Navigation and everything else still ask. |
| `/hirozen-status` | Shows the configured Zen and where that setting came from, plus install, link, consent, active grants and any Zen internals the loader could not find. |

## Setup

Requirements: omp, [Bun](https://bun.sh) and a Zen install you can write to.

```sh
git clone https://github.com/joseraphael2003/Hirozen.git
cd Hirozen
bun install
omp plugin link .
```

Then, in omp (from any folder):

1. `/hirozen-setup`: pick your Zen and its profile from the list and confirm. Hirozen never guesses: nothing is saved without your confirmation, and you can enter paths manually instead.
2. `/hirozen-install`, then restart Zen once. Alternatively, use `/hirozen-attach` to skip the restart (it needs the two DevTools remote-debugging prefs switched on temporarily, and you click OK on Zen's "Incoming Connection" prompt; the command explains how).

The choice is stored in omp's plugin settings (`omp plugin config list hirozen`), per omp profile. A project's `.omp/plugin-overrides.json` can override it, and `/hirozen-status` says which one is in use.

**Zen updates** replace Zen's install folder and remove Hirozen. At the next omp start Hirozen notices and offers to reinstall; restart Zen afterwards.

**Overrides.** When both environment variables are set they win over the saved setting (useful for a second, test Zen):

```sh
HIROZEN_ZEN_DIR=<folder containing zen.exe>
HIROZEN_PROFILE=<full path to the Zen profile folder>
```

> Back up your profile before trying Hirozen on your everyday Zen.

## Safety

- **Consent in Zen.** Permissions are asked separately in Zen: read pages, act on pages (clicks, typing, uploads, dialogs, layout, tab loading; includes read), and network data (cookies, storage, downloads, request headers). A call asks only for what is not granted yet. Deny returns `E_DENIED`, and an unanswered prompt is denied after 120 s. The terminal tells you when Zen is waiting for you.
- **Approval in omp.** Each action is also approved in omp, with the tab and target shown, unless a `/hirozen-grant` you gave covers that tab or site. A grant stops covering a tab that has moved to another site (`E_GRANT_STALE`).
- **Network data is redacted.** Cookie and storage values and cookie/authorization headers are hidden unless you approve a reveal. No response bodies, no blocking.
- **Visible.** While connected, every Zen window shows a notice naming the omp process and what it may do, with a **Stop** button. Stop is sticky until you run `/hirozen-connect`.
- **Your view stays yours.** `zen_open` works in the "Hirozen Agent" space; popups from agent tabs stay there, and your space and selected tab are restored.
- **Private windows and privileged pages are never exposed** (`E_PRIVATE`, `E_PRIVILEGED_PAGE`). Loaded tabs in your other spaces can be read, snapshotted and screenshotted, but actions there are refused (`E_TAB_INACTIVE_SPACE`); tabs in the agent space are not.
- **No late actions.** Each request carries omp's deadline; if Zen is still waiting when omp gives up, the loader does nothing (`E_DEADLINE`).
- **Tamper check.** A modified loader or actor is refused at Zen startup and reported by omp as `E_STALE_LOADER`.

## Development

```sh
bun test
bunx tsc --noEmit
node --check loader/loader.sys.mjs
node --check loader/HirozenChild.sys.mjs
node --check loader/HirozenParent.sys.mjs
```

Changing any file in `loader/` changes its hash, so run `/hirozen-install` again afterwards.

## Roadmap

- **Later:** response bodies and request blocking, JS in the page, iframes, drag and drop, background research tasks, and sites that publish WebMCP tools.

## License

No license has been chosen yet.
