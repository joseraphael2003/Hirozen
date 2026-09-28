/* Hirozen actor child: the content-process half of the loader-owned "Hirozen" JSWindowActor.
 *
 * The loader drives it with five messages and nothing else. The surface is deliberately tiny: this
 * code runs in every content process with the system principal (doc 15.7).
 *   read     -> {json, fullLength}              the V1 page extraction, as literal module code
 *   viewport -> {x, y, width, height, dpr}      the rectangle the parent feeds to drawSnapshot
 *   snapshot -> {url, title, elements, truncated} visible interactive elements with stable refs
 *   act      -> {ok, url, title}                trusted click/type/press/scroll
 *   setFiles -> {ok, count}                     File objects onto a ref'd <input type=file>
 *
 * Gecko facts this file depends on (checked against Zen 1.22.3b / Gecko 156.0.1):
 *  - A JSWindowActor child class must be named <ActorName>Child, or sendQuery never settles
 *    (S1 F4: no rejection, no error - it just hangs).
 *  - The actor realm inherits the page's CSP, so eval/`new Function` is refused ("call to Function()
 *    blocked by CSP", S4 F5): the extraction has to be literal module code, which is why V1's
 *    READ_FUNCTION moved into this file instead of staying a string in the loader.
 *  - Input is synthesized exactly the way BiDi's input module does it, through the shipped
 *    remote-agent modules (Event.sys.mjs / KeyData.sys.mjs) that drive
 *    Window.synthesizeMouseEvent and nsITextInputProcessor: isTrusted events, user activation and
 *    unblocked popups, identical to input.performActions (S1 verdict). No other module is imported.
 *  - This actor exists for top-level documents only (the loader registers it with allFrames:false).
 *
 * Errors never cross as raw exceptions: every handler answers {error: {code, message}} using the
 * codes the loader's contract knows (E_TAB_UNLOADED, E_READ_FAILED, E_REF_STALE, E_BAD_PARAMS,
 * E_NOT_INTERACTABLE, E_INTERNAL). A raw throw would surface as an opaque sendQuery rejection.
 */

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  event: "chrome://remote/content/shared/webdriver/Event.sys.mjs",
  keyData: "chrome://remote/content/shared/webdriver/KeyData.sys.mjs",
});

// The same cap V1's extraction used in the loader (TEXT_CAP): the two must agree, the marker text
// below is part of what browser.read returns to the agent.
const TEXT_CAP = 40_000;
// Cap on the snapshot, and on what the agent sees of any one element.
const MAX_ELEMENTS = 400;
const MAX_NAME_CHARS = 80;
const MAX_TYPE_CHARS = 2_000;
const MAX_DY = 10_000;
const REF_TOKEN_CHARS = 6;
const REF_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
const REF_PATTERN = /^[a-z0-9]{6}\.e\d+$/;

// The interactive elements a snapshot reports. `[contenteditable]` is spelled out for both of its
// "true" values, so contenteditable="false" stays out.
const ELEMENT_SELECTOR = [
  "a[href]",
  "button",
  "input",
  "select",
  "textarea",
  "summary",
  "[role]",
  "[tabindex]",
  '[contenteditable=""]',
  "[contenteditable=true]",
  "[onclick]",
  "label[for]",
].join(", ");

// An unexpected Gecko throw inside a read is a read failure ("no usable page data"); anywhere else it
// is an internal error. Both codes are part of the loader's contract.
const FALLBACK_CODE = {
  read: "E_READ_FAILED",
  viewport: "E_READ_FAILED",
  snapshot: "E_READ_FAILED",
  act: "E_INTERNAL",
  setFiles: "E_INTERNAL",
};

// The keys `press` accepts, as WebDriver key codepoints. sendSingleKey needs the codepoint: passing
// the plain name would make KeyData treat "Enter" as a printable key and type the text instead.
const KEY_CODEPOINTS = {
  Enter: "\uE006",
  Tab: "\uE004",
  Escape: "\uE00C",
  Backspace: "\uE003",
  ArrowLeft: "\uE012",
  ArrowUp: "\uE013",
  ArrowRight: "\uE014",
  ArrowDown: "\uE015",
  PageUp: "\uE00E",
  PageDown: "\uE00F",
  End: "\uE010",
  Home: "\uE011",
};

class HirozenError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "HirozenError";
    this.code = code;
  }
}

// Refs are per document: `<token>.e<n>`, where the token is 6 random base36 characters minted when a
// document is first touched. A navigation produces a new Document (and so a new token), which is how
// "refs reset when the document changes" happens without any code that watches for it.
// `back` keeps one ref per element for the life of the document, so a second snapshot reuses the
// refs of elements it saw before; `map` is the ref -> element side (weak, so a detached element can
// be collected - the lookup also checks isConnected).
const DOC_STATE = new WeakMap();

function docState(doc) {
  let state = DOC_STATE.get(doc);
  if (!state) {
    state = { token: randomToken(), n: 0, map: new Map(), back: new WeakMap() };
    DOC_STATE.set(doc, state);
  }
  return state;
}

function randomToken() {
  const bytes = new Uint8Array(REF_TOKEN_CHARS);
  // Math.random is the fallback only so a missing WebCrypto global can never break a snapshot;
  // the token is a version tag, not a secret (only the loader ever sends refs back here).
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes, byte => REF_TOKEN_ALPHABET[byte % REF_TOKEN_ALPHABET.length]).join("");
}

// V1's extraction (loader/loader.sys.mjs READ_FUNCTION), moved here verbatim as module code. The
// only change is the `document` parameter: the actor cannot eval the loader's string (page CSP), and
// a module function cannot read the page's `document` as a global. S4 proved the output is
// byte-identical to what V1's BiDi sandbox produced.
function extractPage(doc) {
  const body = doc.body;
  const full = body ? body.innerText : "";
  const cap = TEXT_CAP;
  const omitted = full.length - cap;
  const text = omitted > 0 ? full.slice(0, cap) + "\n\n[hirozen: truncated - " + omitted + " more characters]" : full;
  return JSON.stringify({ url: doc.location.href, title: doc.title, text, truncated: omitted > 0 });
}

export class HirozenChild extends JSWindowActorChild {
  receiveMessage({ name, data }) {
    return this.#dispatch(name, data ?? {});
  }

  async #dispatch(name, data) {
    try {
      switch (name) {
        case "read":
          return this.#read();
        case "viewport":
          return this.#viewport();
        case "snapshot":
          return this.#snapshot();
        case "act":
          return await this.#act(data);
        case "setFiles":
          return this.#setFiles(data);
        default:
          // The loader only ever sends the five above; anything else is a bug on the parent side.
          throw new HirozenError("E_INTERNAL", `HirozenChild: unknown message ${name}`);
      }
    } catch (e) {
      return {
        error: {
          code: e instanceof HirozenError ? e.code : FALLBACK_CODE[name] ?? "E_INTERNAL",
          message: String(e?.message ?? e),
        },
      };
    }
  }

  // A child actor whose document is gone (loading, navigating away, closing) has nothing to read or
  // act on; E_TAB_UNLOADED is the contract's name for that state.
  #window() {
    const win = this.contentWindow;
    const doc = this.document;
    if (!win || !doc) {
      throw new HirozenError("E_TAB_UNLOADED", "the tab has no document (it may be loading, navigating or closing)");
    }
    return win;
  }

  #read() {
    this.#window();
    const doc = this.document;
    // Two innerText reads, exactly like the S4 spike (json for the loader, fullLength for its log);
    // innerText forces layout, so fullLength is the only extra cost the actor adds over V1.
    const json = extractPage(doc);
    const body = doc.body;
    return { json, fullLength: body ? body.innerText.length : 0 };
  }

  // The rectangle BiDi's browsingContext.captureScreenshot uses for origin=viewport, clip=null
  // (#getOriginRectangle): visualViewport.pageLeft/pageTop plus rounded innerWidth/Height.
  #viewport() {
    const win = this.#window();
    const vv = win.visualViewport;
    return {
      x: vv ? vv.pageLeft : win.scrollX,
      y: vv ? vv.pageTop : win.scrollY,
      width: Math.round(win.innerWidth),
      height: Math.round(win.innerHeight),
      dpr: win.devicePixelRatio,
    };
  }

  #snapshot() {
    const win = this.#window();
    const doc = this.document;
    const state = docState(doc);
    const elements = [];
    let truncated = false;
    let labels = null; // id of a labelled control -> the label element, built once per snapshot

    for (const el of doc.querySelectorAll(ELEMENT_SELECTOR)) {
      if (elements.length >= MAX_ELEMENTS) {
        // More candidates behind the cap: the list is reported as truncated without walking the
        // rest of the DOM.
        truncated = true;
        break;
      }
      const rect = el.getBoundingClientRect();
      // "Non-zero": a zero-width or zero-height element cannot be pointed at, and the same test
      // makes it E_NOT_INTERACTABLE for act.
      if (!(rect.width > 0) || !(rect.height > 0)) continue;
      if (!el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) continue;

      if (labels === null) {
        labels = new Map();
        for (const label of doc.querySelectorAll("label[for]")) {
          // getAttribute, not the IDL reflection: `label[for]` also matches a plain Element in a
          // non-HTML document, where HTMLLabelElement.htmlFor does not exist.
          const forId = label.getAttribute("for");
          if (forId) labels.set(forId, label);
        }
      }

      elements.push({
        ref: refFor(state, el),
        role: roleOf(el),
        name: nameOf(el, labels),
        tag: el.localName,
        rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
      });
    }

    return { url: win.location.href, title: doc.title, elements, truncated };
  }

  async #act(data) {
    const win = this.#window();
    switch (data.action) {
      case "click":
        await this.#click(win, this.#interactable(this.#element(data.ref)));
        break;
      case "type": {
        if (typeof data.text !== "string" || data.text.length > MAX_TYPE_CHARS) {
          throw new HirozenError("E_BAD_PARAMS", `type needs text of at most ${MAX_TYPE_CHARS} characters`);
        }
        await this.#type(win, this.#interactable(this.#element(data.ref)), data.text);
        break;
      }
      case "press": {
        const codepoint = KEY_CODEPOINTS[data.key];
        if (!codepoint) {
          throw new HirozenError("E_BAD_PARAMS", `press needs one of ${Object.keys(KEY_CODEPOINTS).join(", ")}`);
        }
        if (data.ref !== undefined) await this.#click(win, this.#interactable(this.#element(data.ref)));
        this.#key(win, codepoint);
        break;
      }
      case "scroll": {
        if (data.ref !== undefined) {
          const el = this.#interactable(this.#element(data.ref));
          el.scrollIntoView({ block: "center" });
        } else {
          if (!Number.isInteger(data.dy) || Math.abs(data.dy) > MAX_DY) {
            throw new HirozenError("E_BAD_PARAMS", `scroll needs a ref, or an integer dy with |dy| <= ${MAX_DY}`);
          }
          win.scrollBy(0, data.dy);
        }
        break;
      }
      default:
        throw new HirozenError("E_BAD_PARAMS", `unknown action ${JSON.stringify(data.action)}`);
    }
    // Read after the action, so a navigation the action triggered shows up here. An action that tore
    // the document down (a click that closed the tab) still reports the action as done.
    const doc = this.document;
    return { ok: true, url: doc ? doc.location.href : "", title: doc ? doc.title : "" };
  }

  // The upload path, without BiDi: the loader makes the File objects in the parent process (they
  // cross sendQuery by structured clone) and this puts them on the ref'd <input type=file> the way
  // the shipped input.setFiles does (chrome/remote/.../modules/input.sys.mjs): validate, then
  // mozSetFileArray plus the two bubbling events, so the page's own input/change handlers run.
  #setFiles(data) {
    this.#window();
    if (!Array.isArray(data.files) || !data.files.length) {
      throw new HirozenError("E_BAD_PARAMS", "setFiles needs a non-empty list of File objects");
    }
    const el = this.#element(data.ref);
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (el.localName !== "input" || type !== "file" || el.disabled) {
      throw new HirozenError("E_NOT_INTERACTABLE", "that element is not an enabled <input type=file>");
    }
    if (data.files.length > 1 && !el.hasAttribute("multiple")) {
      throw new HirozenError("E_NOT_INTERACTABLE", "that <input type=file> does not accept multiple files");
    }
    el.mozSetFileArray(data.files);
    lazy.event.input(el);
    lazy.event.change(el);
    return { ok: true, count: data.files.length };
  }

  // A ref resolves against the state of the *current* document: a foreign token (the page navigated,
  // or the agent is reusing a ref from before a navigation) and a detached element are both stale.
  #element(ref) {
    if (typeof ref !== "string" || !ref) {
      throw new HirozenError("E_BAD_PARAMS", "a ref from browser_snapshot is required");
    }
    const doc = this.document;
    if (!doc) throw new HirozenError("E_TAB_UNLOADED", "the tab has no document (it may be loading, navigating or closing)");
    const state = docState(doc);
    const el = REF_PATTERN.test(ref) && ref.startsWith(`${state.token}.`) ? state.map.get(ref)?.deref() : null;
    if (!el || !el.isConnected) {
      throw new HirozenError("E_REF_STALE", `ref ${ref} is not part of the current page; take a new snapshot`);
    }
    return el;
  }

  // Every action that resolves a ref goes through this: a disabled or zero-size element has nothing
  // to click, type into or scroll to. `:disabled` covers controls inside a disabled fieldset too.
  #interactable(el) {
    if (el.matches(":disabled") || el.getAttribute("aria-disabled") === "true") {
      throw new HirozenError("E_NOT_INTERACTABLE", "that element is disabled");
    }
    const rect = el.getBoundingClientRect();
    if (!(rect.width > 0) || !(rect.height > 0)) {
      throw new HirozenError("E_NOT_INTERACTABLE", "that element has no size on the page");
    }
    return el;
  }

  // S1's click recipe: scroll the element to the middle, then a synthesized mousedown + mouseup at
  // its centre, with the event data BiDi's MousePointer builds (minus pointer state). This is the
  // path that gave the page isTrusted events, user activation and an unblocked window.open.
  async #click(win, el) {
    el.scrollIntoView({ block: "center", inline: "center" });
    const rect = el.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    await lazy.event.synthesizeMouseAtPoint(x, y, { type: "mousedown", button: 0, buttons: 0, clickCount: 1, inputSource: 1 }, win);
    await lazy.event.synthesizeMouseAtPoint(x, y, { type: "mouseup", button: 0, buttons: 0, clickCount: 1, inputSource: 1 }, win);
  }

  // A trusted click first, so the field is focused the way a user focuses it, then one
  // sendSingleKey per character (S1: the value ends up exactly as asked, keys isTrusted).
  async #type(win, el, text) {
    await this.#click(win, el);
    for (const ch of text) this.#key(win, ch);
  }

  #key(win, ch) {
    const data = {
      ...lazy.keyData.getData(ch),
      shiftKey: false,
      ctrlKey: false,
      altKey: false,
      metaKey: false,
      repeat: false,
    };
    lazy.event.sendSingleKey(data, win);
  }
}

// One ref per element for the life of the document: a later snapshot reuses it instead of minting a
// new one, so refs the agent already holds keep working.
function refFor(state, el) {
  const known = state.back.get(el);
  if (known) return known;
  const ref = `${state.token}.e${++state.n}`;
  state.back.set(el, ref);
  state.map.set(ref, new WeakRef(el));
  return ref;
}

// The plan's role rule: an explicit role attribute wins, then the element's own semantics, and
// anything else is generic (no a11y engine is consulted).
function roleOf(el) {
  const explicit = el.getAttribute("role");
  if (explicit && explicit.trim()) return explicit.trim().split(/\s+/)[0];
  const tag = el.localName;
  if (tag === "a") return "link";
  if (tag === "button" || tag === "summary") return "button";
  if (tag === "select") return "combobox";
  if (tag === "textarea" || el.hasAttribute("contenteditable")) return "textbox";
  if (tag === "input") {
    switch ((el.getAttribute("type") || "text").toLowerCase()) {
      case "checkbox":
        return "checkbox";
      case "radio":
        return "radio";
      case "button":
      case "submit":
      case "reset":
        return "button";
      case "file":
        return "file";
      default:
        return "textbox";
    }
  }
  return "generic";
}

// The plan's name rule: aria-label -> aria-labelledby -> label[for] -> alt/placeholder/value ->
// trimmed textContent. Whatever the source, the result is capped so a page cannot hand the agent
// megabytes of label text through one element.
function nameOf(el, labels) {
  const ariaLabel = el.getAttribute("aria-label");
  if (ariaLabel && ariaLabel.trim()) return capName(ariaLabel);

  const labelledBy = el.getAttribute("aria-labelledby");
  if (labelledBy) {
    const parts = [];
    for (const id of labelledBy.trim().split(/\s+/)) {
      const target = el.ownerDocument.getElementById(id);
      const text = target ? (target.textContent || "").trim() : "";
      if (text) parts.push(text);
    }
    if (parts.length) return capName(parts.join(" "));
  }

  const label = el.id ? labels.get(el.id) : null;
  const labelText = label ? (label.textContent || "").trim() : "";
  if (labelText) return capName(labelText);

  const alt = el.getAttribute("alt");
  if (alt && alt.trim()) return capName(alt);
  const placeholder = el.getAttribute("placeholder");
  if (placeholder && placeholder.trim()) return capName(placeholder);
  const value = typeof el.value === "string" ? el.value.trim() : "";
  if (value) return capName(value);

  return capName(el.textContent || "");
}

function capName(text) {
  return text.trim().slice(0, MAX_NAME_CHARS);
}
