// Unit tests for src/grant.ts: the time-limited, process-local grants behind /hirozen-grant.
//
// A grant is what lets browser_act click/type/press/scroll/hover on a tab without an omp prompt for a
// few minutes (T12). The rules that matter are the coverage rules - which call a grant covers, and
// which it never can - plus expiry and clear.
import { expect, test } from "bun:test";

import { GrantStore, GRANT_MINUTES_MAX, GRANT_MINUTES_MIN, originOf, parseGrantMinutes } from "../src/grant";

const TAB = "1759000000000-aaaa";
const OTHER_TAB = "1759000000000-bbbb";
const SITE = "https://example.com";
const PAGE = "https://example.com/account?q=1";

test("originOf keeps the origin of http(s) URLs and refuses everything else", () => {
  expect(originOf(PAGE)).toBe(SITE);
  expect(originOf("http://localhost:3000/deep/path")).toBe("http://localhost:3000");
  expect(originOf("https://sub.example.com/")).toBe("https://sub.example.com");
  // A page Hirozen may not name an origin for is not one a grant can cover.
  expect(originOf("about:blank")).toBeNull();
  expect(originOf("data:text/html,<p>hi")).toBeNull();
  expect(originOf("file:///C:/tmp/page.html")).toBeNull();
  expect(originOf("chrome://browser/content/browser.xhtml")).toBeNull();
  expect(originOf("")).toBeNull();
  expect(originOf("not a url")).toBeNull();
  expect(originOf(undefined)).toBeNull();
});

test("parseGrantMinutes accepts 1 to 60 and refuses anything else", () => {
  expect(parseGrantMinutes("1")).toBe(GRANT_MINUTES_MIN);
  expect(parseGrantMinutes("60")).toBe(GRANT_MINUTES_MAX);
  expect(parseGrantMinutes(" 5 ")).toBe(5);
  for (const bad of ["0", "61", "-5", "5.5", "5m", "", " ", "abc", "1e3", "0x10"]) {
    expect(parseGrantMinutes(bad)).toBeNull();
  }
});

test("a tab grant covers only its own tab, and only while that tab is still on the granted site", () => {
  const grants = new GrantStore();
  const grant = grants.grant("tab", TAB, SITE, 5, 1_000);
  expect(grant).toEqual({ kind: "tab", key: TAB, origin: SITE, until: 1_000 + 5 * 60_000 });

  expect(grants.coveringAct(TAB, PAGE, "click", 2_000)).not.toBeNull();
  // Another tab on the same site is not covered: that tab was never granted.
  expect(grants.coveringAct(OTHER_TAB, PAGE, "click", 2_000)).toBeNull();
  // The granted tab left the site (the plugin's tab cache is what it goes by).
  expect(grants.coveringAct(TAB, "https://elsewhere.example/", "click", 2_000)).toBeNull();
  // A page with no usable origin (about:blank, a privileged page) is never covered.
  expect(grants.coveringAct(TAB, "about:blank", "click", 2_000)).toBeNull();
});

test("an origin grant covers every tab on that origin", () => {
  const grants = new GrantStore();
  grants.grant("origin", SITE, SITE, 10, 1_000);
  expect(grants.coveringAct(TAB, PAGE, "type", 2_000)).not.toBeNull();
  expect(grants.coveringAct(OTHER_TAB, `${SITE}/other`, "hover", 2_000)).not.toBeNull();
  expect(grants.coveringAct(OTHER_TAB, "https://elsewhere.example/", "hover", 2_000)).toBeNull();
});

test("navigate is never covered, whatever the grant is", () => {
  const grants = new GrantStore();
  grants.grant("tab", TAB, SITE, 5, 1_000);
  grants.grant("origin", SITE, SITE, 5, 1_000);
  for (const action of ["navigate", "upload", "dialog", "", "CLICK"]) {
    expect(grants.coveringAct(TAB, PAGE, action, 2_000)).toBeNull();
  }
  for (const action of ["click", "type", "press", "scroll", "hover"]) {
    expect(grants.coveringAct(TAB, PAGE, action, 2_000)).not.toBeNull();
  }
});

test("a grant stops covering when it expires, and list drops it", () => {
  const grants = new GrantStore();
  grants.grant("tab", TAB, SITE, 1, 1_000);
  expect(grants.coveringAct(TAB, PAGE, "click", 1_000 + 60_000 - 1)).not.toBeNull();
  expect(grants.coveringAct(TAB, PAGE, "click", 1_000 + 60_000)).toBeNull();
  expect(grants.list(1_000 + 60_000)).toEqual([]);
});

test("granting the same target again replaces the deadline instead of stacking up", () => {
  const grants = new GrantStore();
  grants.grant("tab", TAB, SITE, 1, 1_000);
  grants.grant("tab", TAB, SITE, 30, 2_000);
  const listed = grants.list(2_000);
  expect(listed.length).toBe(1);
  expect(listed[0]?.until).toBe(2_000 + 30 * 60_000);
  // A different target is a separate grant.
  grants.grant("origin", SITE, SITE, 5, 2_000);
  expect(grants.list(2_000).length).toBe(2);
});

test("clear drops every grant and reports how many it dropped", () => {
  const grants = new GrantStore();
  grants.grant("tab", TAB, SITE, 5, 1_000);
  grants.grant("origin", "https://other.example", "https://other.example", 5, 1_000);
  expect(grants.clear()).toBe(2);
  expect(grants.list(1_000)).toEqual([]);
  expect(grants.coveringAct(TAB, PAGE, "click", 1_000)).toBeNull();
  expect(grants.clear()).toBe(0);
});
