// The process-local, time-limited grants behind /hirozen-grant (T12).
//
// A grant is the one thing that lets a browser_act run without an omp approval prompt: for a few
// minutes, clicks and the other act actions on the granted tab (or on every tab of the granted site)
// are returned to omp as `{tier:"write", policy:"allow"}` instead of `{tier:"exec", policy:"prompt"}`.
// The in-Zen permissions are unchanged by a grant, and nothing outside the act actions is ever
// covered: navigate can leave the site, and upload/dialog/zen_*/network/reveal are not page clicks.
//
// Coverage is decided from the tab's last known URL (the plugin's tab cache), so a grant is anchored
// to an origin: a tab that left the granted site is not covered any more. The plugin's cache can be
// stale, which is why a covered act also sends `grantOrigin` and the loader refuses with
// E_GRANT_STALE (carrying the tab's live URL) when the tab really is elsewhere.
//
// Grants live in this process only, are dropped when the link goes away (teardown, Zen Stop), and are
// listed by /hirozen-status.
export type GrantKind = "tab" | "origin";
/** One grant: `key` is the tabKey (kind "tab") or the origin (kind "origin"), `until` an epoch ms. */
export type Grant = { kind: GrantKind; key: string; origin: string; until: number };

export const GRANT_MINUTES_MIN = 1;
export const GRANT_MINUTES_MAX = 60;

/** The browser_act actions a grant can cover. `navigate` is never one: it can leave the site. */
const GRANTED_ACTIONS: Record<string, true> = {
  click: true,
  type: true,
  press: true,
  scroll: true,
  hover: true,
};

/** The origin of an http(s) URL, or null for anything a grant cannot be anchored to (about:, data:,
 *  file:, chrome:, an empty or unparseable URL). */
export function originOf(url: string | undefined | null): string | null {
  if (typeof url !== "string" || url === "") return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.origin : null;
  } catch {
    return null;
  }
}

/** `/hirozen-grant`'s minutes argument: a whole 1 to 60, or null when it is anything else. */
export function parseGrantMinutes(text: string): number | null {
  const trimmed = text.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const minutes = Number(trimmed);
  return minutes >= GRANT_MINUTES_MIN && minutes <= GRANT_MINUTES_MAX ? minutes : null;
}

export class GrantStore {
  #grants: Grant[] = [];

  /** Add a grant, replacing any earlier one for the same target so deadlines never stack up. */
  grant(kind: GrantKind, key: string, origin: string, minutes: number, now = Date.now()): Grant {
    const grant: Grant = { kind, key, origin, until: now + minutes * 60_000 };
    this.#grants = this.#grants.filter(existing => existing.kind !== kind || existing.key !== key);
    this.#grants.push(grant);
    return grant;
  }

  /** The unexpired grant that covers this act on this tab right now, or null. */
  coveringAct(tabKey: string, url: string | undefined | null, action: string, now = Date.now()): Grant | null {
    if (GRANTED_ACTIONS[action] !== true) return null;
    const origin = originOf(url);
    if (origin === null) return null;
    return (
      this.#grants.find(
        grant => grant.until > now && grant.origin === origin && (grant.kind === "origin" || grant.key === tabKey),
      ) ?? null
    );
  }

  /** Every unexpired grant, oldest first; expired ones are dropped here. */
  list(now = Date.now()): Grant[] {
    this.#grants = this.#grants.filter(grant => grant.until > now);
    return [...this.#grants];
  }

  /** Drop every grant (link teardown, Zen Stop, /hirozen-grant clear); answers how many went. */
  clear(): number {
    const dropped = this.#grants.length;
    this.#grants = [];
    return dropped;
  }
}
