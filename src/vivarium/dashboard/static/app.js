/* Vivarium status dashboard — VSCode-style RE browser (read-only, display-only).
 *
 * SECURITY (ADR-005): every binary-derived value arrives tagged {value, untrusted:true}. This
 * script renders ALL such content — including inside the syntax colorizer and every cross-link —
 * ONLY via textContent (never innerHTML / insertAdjacentHTML / any DOM-string sink), so hostile
 * bytes appear verbatim and inert. Links carry a SAFE address id in a data-* attribute and a
 * textContent label; clicking navigates by id. The strict, inline-free CSP is the defense-in-depth
 * backstop. All DOM is built with createElement + textContent.
 */
"use strict";

/* ------------------------------------------------------------------ DOM helpers */

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

/** Render one value inert: a tagged {value, untrusted} object → textContent span; scalar → text. */
function renderValue(v) {
  if (v && typeof v === "object" && "value" in v && "untrusted" in v) {
    const span = el("span", v.untrusted ? "u" : "s");
    span.textContent = String(v.value);
    if (v.untrusted) span.title = "binary-derived (untrusted) — shown inert";
    return span;
  }
  return document.createTextNode(v === null || v === undefined ? "" : String(v));
}

function plain(v) {
  if (v && typeof v === "object" && "value" in v) return String(v.value);
  return v === null || v === undefined ? "" : String(v);
}

/** The bearer token the viewer entered (per-viewer, localStorage) — required only for commands. */
function authToken() {
  try {
    return localStorage.getItem("vivarium.dashboard.token") || "";
  } catch (_) {
    return "";
  }
}

/** Headers for a command POST: JSON + the bearer token when the viewer has entered one. */
function cmdHeaders() {
  const h = { "content-type": "application/json" };
  const t = authToken();
  if (t) h["authorization"] = "Bearer " + t;
  return h;
}

/** Create an SVG element with attributes (SVG uses createElementNS + setAttribute for class). */
const SVGNS = "http://www.w3.org/2000/svg";
function svg(tag, attrs) {
  const n = document.createElementNS(SVGNS, tag);
  if (attrs) for (const k in attrs) n.setAttribute(k, attrs[k]);
  return n;
}

/* ------------------------------------------------------------------ graph preferences (per viewer) */

// User preference: initial node layout for the interactive graph — persisted in localStorage
// (a per-viewer convenience; wrapped in try/catch per topic-web-frontend, safe if storage is blocked).
const graphPrefs = { layout: "layered", depth: 1 };
(function loadGraphPrefs() {
  try {
    const raw = localStorage.getItem("vivarium.graph");
    if (raw) {
      const p = JSON.parse(raw);
      if (["layered", "force", "radial"].includes(p.layout)) graphPrefs.layout = p.layout;
      if (Number.isInteger(p.depth) && p.depth >= 1 && p.depth <= 3) graphPrefs.depth = p.depth;
    }
  } catch (_) {
    /* storage blocked/absent — use defaults */
  }
})();
function saveGraphPrefs() {
  try {
    localStorage.setItem("vivarium.graph", JSON.stringify(graphPrefs));
  } catch (_) {
    /* ignore */
  }
}

// Live graph runtime state (rebuilt when the focus/session changes).
let graphState = null;

/* ------------------------------------------------------------------ custom workflows (per viewer) */

// Custom workflows are authored client-side and saved in localStorage (per-viewer). Phase 1 keeps
// execution out-of-band (the agent runs the emitted spec), so these are author-only artifacts.
function loadCustomWorkflows() {
  try {
    const raw = localStorage.getItem("vivarium.workflows.custom");
    const list = raw ? JSON.parse(raw) : [];
    return Array.isArray(list) ? list : [];
  } catch (_) {
    return [];
  }
}
function saveCustomWorkflows(list) {
  try {
    localStorage.setItem("vivarium.workflows.custom", JSON.stringify(list));
  } catch (_) {
    /* storage blocked — draft stays in memory only */
  }
}

// The in-progress builder draft (module-scoped so it survives view switches within a session).
let builderDraft = { name: "", steps: [] };

/* ------------------------------------------------------------------ collapse state (per viewer) */

// Which explorer groups / sessions / viewer panels the viewer has collapsed, to save viewport space.
// A plain id -> true map persisted in localStorage (per-viewer convenience; safe if storage blocked).
let collapsedState = {};
(function loadCollapse() {
  try {
    const raw = localStorage.getItem("vivarium.dashboard.collapse");
    const obj = raw ? JSON.parse(raw) : {};
    collapsedState = obj && typeof obj === "object" ? obj : {};
  } catch (_) {
    collapsedState = {};
  }
})();
function saveCollapse() {
  try {
    localStorage.setItem("vivarium.dashboard.collapse", JSON.stringify(collapsedState));
  } catch (_) {
    /* storage blocked — collapse state stays in memory for this view only */
  }
}
function isCollapsed(id) {
  return collapsedState[id] === true;
}
function setCollapsed(id, val) {
  if (val) collapsedState[id] = true;
  else delete collapsedState[id];
  saveCollapse();
}

// Make a header element a keyboard-operable collapse toggle for `bodyEl`, persisted under `id`.
// Prepends a caret; the header controls the body's visibility (aria-expanded reflects state).
function wireCollapse(headerEl, bodyEl, id) {
  const caret = el("span", "caret", "");
  caret.setAttribute("aria-hidden", "true");
  headerEl.insertBefore(caret, headerEl.firstChild);
  headerEl.classList.add("is-collapsible");
  headerEl.setAttribute("role", "button");
  headerEl.setAttribute("tabindex", "0");
  const apply = () => {
    const c = isCollapsed(id);
    bodyEl.hidden = c;
    caret.textContent = c ? "▸" : "▾"; // ▸ / ▾
    headerEl.setAttribute("aria-expanded", String(!c));
  };
  const toggle = () => {
    setCollapsed(id, !isCollapsed(id));
    apply();
  };
  headerEl.addEventListener("click", toggle);
  headerEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggle();
    }
  });
  apply();
}

// After a view renders, turn every panel (a <section> led by an h2/h3/h4 header) into a
// collapsible element so the viewer can hide any panel to save space. Idempotent per render.
function enhanceViewerCollapsibles(root, viewKey) {
  root.querySelectorAll("section").forEach((sec, i) => {
    const header = sec.firstElementChild;
    if (!header || !/^H[2-4]$/.test(header.tagName)) return;
    if (sec.dataset.collapsibleReady) return;
    sec.dataset.collapsibleReady = "1";
    const body = el("div", "panel-body");
    while (header.nextSibling) body.appendChild(header.nextSibling);
    sec.appendChild(body);
    const label = (header.textContent || "panel").slice(0, 48);
    wireCollapse(header, body, "panel:" + viewKey + ":" + i + ":" + label);
  });
}

/** A cross-link: a button labelled inert by name, navigating by SAFE id. `ref` = {id, name, ...}. */
function xlink(sessionId, ref, extraClass) {
  const b = el("button", "xlink" + (extraClass ? " " + extraClass : ""));
  b.type = "button";
  b.dataset.id = ref.id || "";
  b.appendChild(renderValue(ref.name)); // inert label
  if (ref.at) {
    const at = el("span", "xat mono", "@" + ref.at);
    b.appendChild(at);
  }
  b.addEventListener("click", () => navigateById(sessionId, ref.id));
  return b;
}

/* ------------------------------------------------------------------ C colorizer */

const C_KEYWORDS = new Set([
  "if", "else", "for", "while", "do", "switch", "case", "default", "goto", "return", "break",
  "continue", "sizeof", "typedef", "struct", "union", "enum", "static", "const", "extern",
  "volatile", "register", "inline",
]);
const C_TYPES = new Set([
  "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool", "byte",
  "uint", "ulong", "ushort", "uchar", "size_t", "ssize_t", "code", "undefined", "undefined1",
  "undefined2", "undefined4", "undefined8", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
  "int8_t", "int16_t", "int32_t", "int64_t", "wchar_t",
]);
const C_TOKEN =
  /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|0[xX][0-9a-fA-F]+|\b\d+\b|[A-Za-z_]\w*/g;

function classifyToken(tok) {
  if (tok.startsWith("/*") || tok.startsWith("//")) return "c-com";
  if (tok[0] === '"' || tok[0] === "'") return "c-str";
  if (/^[0-9]/.test(tok)) return "c-num";
  if (C_KEYWORDS.has(tok)) return "c-kw";
  if (C_TYPES.has(tok)) return "c-ty";
  if (/^(FUN_|LAB_|DAT_|PTR_|UNK_|switchD_|code_)/.test(tok)) return "c-sym";
  return null;
}

/** Colorize one line into `lineEl`. If `resolve(name)` returns a nav target, the identifier becomes
 *  a clickable jump-to link (still textContent-only). */
function colorizeInto(lineEl, line, sessionId, resolve) {
  C_TOKEN.lastIndex = 0;
  let last = 0;
  let m;
  while ((m = C_TOKEN.exec(line)) !== null) {
    if (m.index > last) lineEl.appendChild(document.createTextNode(line.slice(last, m.index)));
    const tok = m[0];
    const cls = classifyToken(tok);
    const target = resolve && /^[A-Za-z_]/.test(tok) ? resolve(tok) : null;
    if (target) {
      const b = el("button", "c-link" + (cls ? " " + cls : ""));
      b.type = "button";
      b.textContent = tok; // INERT
      b.dataset.id = target;
      b.title = "jump to " + tok;
      b.addEventListener("click", () => navigateById(sessionId, target));
      lineEl.appendChild(b);
    } else if (cls) {
      const s = el("span", cls);
      s.textContent = tok; // INERT
      lineEl.appendChild(s);
    } else {
      lineEl.appendChild(document.createTextNode(tok));
    }
    last = m.index + tok.length;
  }
  if (last < line.length) lineEl.appendChild(document.createTextNode(line.slice(last)));
}

/** Colorized code block with a line-number gutter; `text` is untrusted, rendered inert. */
function codeBlock(text, lang, sessionId, resolve) {
  const wrap = el("div", "codeblock");
  if (lang) wrap.dataset.lang = lang;
  String(text)
    .split("\n")
    .forEach((line, i) => {
      wrap.appendChild(el("span", "ln", String(i + 1)));
      const code = el("span", "lc");
      if (lang === "c") colorizeInto(code, line, sessionId, resolve);
      else code.textContent = line;
      wrap.appendChild(code);
    });
  return wrap;
}

/* ------------------------------------------------------------------ state store + index */

const store = { sessions: {}, build: null, catalog: null };
let selection = null; // { kind:"session-view"|"build"|"catalog", sessionId?, view? }
let pendingHighlight = null; // an id to flash after a cross-nav into a table

function ensureSession(id) {
  if (!store.sessions[id]) {
    store.sessions[id] = {
      summary: { session_id: id, state: "?", progress_percent: null },
      metadata: null,
      imports: null,
      exports: null,
      strings: null,
      callgraph: null,
      functions: {}, // id -> merged function context
      timeline: [],
      outputs: [],
      verdict: null,
      workflows: {}, // run id -> merged workflow run
      annotations: {}, // proposal id -> AI-annotation proposal set (apply-transform, propose-first)
      idIndex: {}, // address id -> { kind, view }
      nameIndex: {}, // symbol name -> id (for code jump-to)
    };
  }
  return store.sessions[id];
}

/** Record an address id + optional name so it becomes navigable. */
function indexSymbol(s, id, kind, view, name) {
  if (id) s.idIndex[id] = { kind, view };
  if (name && !(name in s.nameIndex)) s.nameIndex[name] = id;
}

/* ------------------------------------------------------------------ connection / status */

function setConn(text, ok) {
  const c = document.getElementById("conn");
  c.textContent = text;
  c.classList.toggle("ok", !!ok);
  c.classList.toggle("bad", ok === false);
}
function setStatus(text) {
  document.getElementById("status-left").textContent = text;
}

/* ------------------------------------------------------------------ explorer tree */

function treeItem(label, opts) {
  opts = opts || {};
  const btn = el("button", "tw-item");
  btn.type = "button";
  btn.style.setProperty("--depth", String(opts.depth || 0));
  if (opts.icon) btn.appendChild(el("span", "tw-icon " + opts.icon, opts.iconText || ""));
  if (opts.labelNode) btn.appendChild(opts.labelNode);
  else btn.appendChild(el("span", "tw-label", label));
  if (opts.badge !== undefined && opts.badge !== null)
    btn.appendChild(el("span", "tw-badge", String(opts.badge)));
  if (opts.state) btn.appendChild(el("span", "tw-state state-" + opts.state, opts.state));
  if (opts.onClick) btn.addEventListener("click", opts.onClick);
  if (opts.active) btn.classList.add("active");
  return btn;
}

function isActive(kind, sessionId, view) {
  if (!selection) return false;
  if (kind === "build") return selection.kind === "build";
  if (kind === "catalog") return selection.kind === "catalog";
  if (kind === "builder") return selection.kind === "builder";
  return (
    selection.kind === "session-view" &&
    selection.sessionId === sessionId &&
    selection.view === view
  );
}

// A collapsible explorer group: a header that toggles its item container (persisted per viewer).
function explorerGroup(title, id) {
  const wrap = el("div", "tw-group");
  const head = el("div", "tw-group-h", title);
  const body = el("div", "tw-group-body");
  wrap.appendChild(head);
  wrap.appendChild(body);
  wireCollapse(head, body, "grp:" + id);
  return { wrap, body };
}

function buildExplorer() {
  const root = document.getElementById("explorer");
  root.replaceChildren();

  const sg = explorerGroup("Sessions", "sessions");
  const ids = Object.keys(store.sessions);
  if (!ids.length) sg.body.appendChild(el("div", "tw-none", "no active sessions"));

  ids.forEach((id) => {
    const s = store.sessions[id];
    // Each session is its own collapsible block: a head row (caret + nav item) over a kids list.
    const block = el("div", "tw-sess");
    const head = el("div", "tw-sess-head");
    const kids = el("div", "tw-sess-kids");
    const cid = "sess:" + id;
    const caret = el("button", "tw-caret");
    caret.type = "button";
    caret.setAttribute("aria-label", "collapse session " + id);
    const applyCaret = () => {
      const c = isCollapsed(cid);
      kids.hidden = c;
      caret.textContent = c ? "▸" : "▾";
      caret.setAttribute("aria-expanded", String(!c));
    };
    caret.addEventListener("click", () => {
      setCollapsed(cid, !isCollapsed(cid));
      applyCaret();
    });
    head.appendChild(caret);
    head.appendChild(
      treeItem(id, {
        depth: 0,
        icon: "i-sess",
        iconText: "●",
        state: s.summary.state,
        onClick: () => select({ kind: "session-view", sessionId: id, view: "overview" }),
      })
    );
    block.appendChild(head);
    block.appendChild(kids);

    const kid = (label, view, opts) =>
      kids.appendChild(
        treeItem(label, {
          depth: 1,
          icon: (opts && opts.icon) || "i-doc",
          iconText: (opts && opts.iconText) || "▪",
          badge: opts && opts.badge,
          active: isActive("session-view", id, view),
          onClick: () => select({ kind: "session-view", sessionId: id, view }),
        })
      );

    kid("Overview", "overview", { icon: "i-info", iconText: "ⓘ" });

    const fns = Object.values(s.functions);
    if (fns.length) {
      kids.appendChild(el("div", "tw-sub", "Functions · " + fns.length));
      fns.forEach((fn) => {
        const lab = el("span", "tw-label");
        lab.appendChild(renderValue(fn.name)); // inert name
        kids.appendChild(
          treeItem(null, {
            depth: 2,
            icon: "i-fn",
            iconText: "ƒ",
            labelNode: lab,
            active: isActive("session-view", id, "function:" + fn.id),
            onClick: () => select({ kind: "session-view", sessionId: id, view: "function:" + fn.id }),
          })
        );
      });
    }

    if (s.imports) kid("Imports", "imports", { icon: "i-imp", iconText: "↓", badge: s.imports.total });
    if (s.exports) kid("Exports", "exports", { icon: "i-exp", iconText: "↑", badge: s.exports.total });
    if (s.strings) kid("Strings", "strings", { icon: "i-str", iconText: '"', badge: s.strings.total });
    if (s.callgraph) kid("Call graph", "callgraph", { icon: "i-cg", iconText: "⑂" });
    s.outputs.forEach((o, idx) =>
      kid(o.label || "output " + (idx + 1), "output:" + idx, { icon: "i-code", iconText: "{}" })
    );
    if (s.verdict) kid("Verdict", "verdict", { icon: "i-ver", iconText: "✓" });
    const propCount = Object.values(s.annotations).reduce(
      (n, p) => n + (p.items ? p.items.length : 0),
      0
    );
    if (propCount)
      kid("Proposals", "proposals", { icon: "i-prop", iconText: "✎", badge: propCount });
    if (Object.keys(s.workflows).length)
      kid("Runs", "runs", { icon: "i-run", iconText: "▷", badge: Object.keys(s.workflows).length });
    kid("Timeline", "timeline", { icon: "i-time", iconText: "≡" });

    applyCaret();
    sg.body.appendChild(block);
  });
  root.appendChild(sg.wrap);

  const wg = explorerGroup("Workflows", "workflows");
  wg.body.appendChild(
    treeItem("Catalog", {
      depth: 0,
      icon: "i-wf",
      iconText: "▤",
      active: isActive("catalog"),
      onClick: () => select({ kind: "catalog" }),
    })
  );
  wg.body.appendChild(
    treeItem("Builder", {
      depth: 0,
      icon: "i-wf",
      iconText: "+",
      active: isActive("builder"),
      onClick: () => select({ kind: "builder" }),
    })
  );
  root.appendChild(wg.wrap);

  const bg = explorerGroup("Build", "build");
  bg.body.appendChild(
    treeItem("Build & deliverables", {
      depth: 0,
      icon: "i-build",
      iconText: "◆",
      active: isActive("build"),
      onClick: () => select({ kind: "build" }),
    })
  );
  root.appendChild(bg.wrap);
}

/* ------------------------------------------------------------------ selection + navigation */

function select(sel) {
  selection = sel;
  buildExplorer();
  renderViewer();
  closeSidebarOnMobile(); // on a phone, reveal the main pane after picking an artifact
}

/** Navigate to any indexed symbol by its SAFE address id (function detail, or table + highlight). */
function navigateById(sessionId, id) {
  const s = store.sessions[sessionId];
  if (!s || !id) return;
  const hit = s.idIndex[id];
  if (!hit) return;
  if (hit.kind === "function") {
    select({ kind: "session-view", sessionId, view: "function:" + id });
  } else {
    pendingHighlight = id;
    select({ kind: "session-view", sessionId, view: hit.view });
  }
}

function setCrumb(parts) {
  const c = document.getElementById("crumb");
  c.replaceChildren();
  parts.forEach((p, i) => {
    if (i) c.appendChild(el("span", "crumb-sep", "›"));
    if (p && p.nodeType) c.appendChild(p);
    else c.appendChild(el("span", "crumb-part", p));
  });
}

function viewerRoot() {
  const v = document.getElementById("viewer");
  v.replaceChildren();
  return v;
}

function renderViewer() {
  if (!selection) return;
  const v = document.getElementById("viewer");
  const keepScroll = v.scrollTop; // in-place update: preserve scroll
  if (selection.kind === "build") {
    renderBuild();
  } else if (selection.kind === "catalog") {
    renderCatalog();
  } else if (selection.kind === "builder") {
    renderBuilder();
  } else {
    const s = store.sessions[selection.sessionId];
    if (!s) return;
    const view = selection.view;
    setStatus(selection.sessionId + " · " + s.summary.state);
    if (view === "overview") renderOverview(s);
    else if (view === "imports") renderTable(s, s.imports, ["address", "name", "library"], "Imports");
    else if (view === "exports") renderTable(s, s.exports, ["address", "name"], "Exports");
    else if (view === "strings") renderStrings(s);
    else if (view === "callgraph") renderCallgraph(s);
    else if (view === "verdict") renderVerdict(s.verdict);
    else if (view === "timeline") renderTimeline(s);
    else if (view === "runs") renderRuns(s);
    else if (view === "proposals") renderProposals(s);
    else if (view.indexOf("function:") === 0) renderFunction(s, view.slice(9));
    else if (view.indexOf("output:") === 0) renderOutput(s.outputs[+view.slice(7)]);
  }
  const viewKey =
    selection.kind === "session-view"
      ? selection.sessionId + ":" + selection.view
      : selection.kind;
  enhanceViewerCollapsibles(v, viewKey);
  document.getElementById("viewer").scrollTop = keepScroll;
  if (pendingHighlight) {
    const row = document.querySelector('[data-row-id="' + cssEscape(pendingHighlight) + '"]');
    if (row) {
      row.classList.add("flash");
      row.scrollIntoView({ block: "center" });
    }
    pendingHighlight = null;
  }
}

function cssEscape(s) {
  return String(s).replace(/["\\]/g, "\\$&");
}

/* ------------------------------------------------------------------ viewer: shared bits */

function vhead(root, title, sub, badgeUntrusted) {
  const h = el("div", "vh");
  h.appendChild(el("h2", "vh-title", title));
  if (sub) h.appendChild(el("span", "vh-sub", sub));
  if (badgeUntrusted) h.appendChild(el("span", "badge-untrusted", "untrusted"));
  root.appendChild(h);
}

/** Lineage footer: where an artifact came from (source tool + address) — self-documenting. */
function lineage(root, prov, extra) {
  const box = el("div", "lineage");
  box.appendChild(el("span", "lin-h", "lineage"));
  if (prov && prov.tool) box.appendChild(el("span", "lin-item", "source: " + prov.tool));
  if (prov && prov.address) box.appendChild(el("span", "lin-item mono", prov.address));
  (extra || []).forEach((t) => box.appendChild(el("span", "lin-item", t)));
  root.appendChild(box);
}

/** A titled sub-panel of cross-links (callers/callees/xrefs/referenced-by). */
function refPanel(root, title, sessionId, refs, emptyText) {
  const sec = el("section", "refpanel");
  sec.appendChild(el("h3", "refpanel-h", title + " · " + (refs ? refs.length : 0)));
  if (!refs || !refs.length) {
    sec.appendChild(el("div", "muted", emptyText || "none"));
  } else {
    const ul = el("ul", "reflist");
    refs.forEach((r) => {
      const li = el("li", "refrow");
      if (r.kind) li.appendChild(el("span", "reftag", r.kind));
      li.appendChild(xlink(sessionId, r));
      ul.appendChild(li);
    });
    sec.appendChild(ul);
  }
  root.appendChild(sec);
}

/* ------------------------------------------------------------------ viewer: views */

function renderOverview(s) {
  const root = viewerRoot();
  setCrumb([s.summary.session_id, "Overview"]);
  vhead(root, "Overview", s.summary.state);

  const bar = el("div", "ov-bar");
  const fill = el("div", "ov-fill");
  const pct = typeof s.summary.progress_percent === "number" ? s.summary.progress_percent : 0;
  fill.style.width = pct + "%";
  bar.appendChild(fill);
  root.appendChild(bar);
  root.appendChild(el("div", "ov-meta", (s.summary.phase || "—") + " · " + pct + "%"));

  if (s.summary.binary_sha256) {
    const sha = el("div", "kvline");
    sha.appendChild(el("span", "k", "sha256"));
    sha.appendChild(el("span", "v mono", s.summary.binary_sha256));
    root.appendChild(sha);
  }

  if (s.metadata && s.metadata.fields) {
    const card = el("section", "card2");
    card.appendChild(el("h3", "card2-h", "Binary format"));
    const dl = el("dl", "kv");
    s.metadata.fields.forEach((f) => {
      dl.appendChild(el("dt", null, f.k));
      const dd = el("dd", "mono");
      dd.appendChild(renderValue(f.v));
      dl.appendChild(dd);
    });
    card.appendChild(dl);
    root.appendChild(card);
  } else {
    root.appendChild(el("p", "muted", "binary format not yet streamed"));
  }
}

function renderFunction(s, id) {
  const root = viewerRoot();
  const fn = s.functions[id];
  if (!fn) {
    root.appendChild(el("p", "muted", "function not found: " + id));
    return;
  }
  const crumbName = el("span", "crumb-part");
  crumbName.appendChild(renderValue(fn.name));
  setCrumb([s.summary.session_id, "Functions", crumbName]);

  const h = el("div", "vh");
  const title = el("h2", "vh-title");
  title.appendChild(renderValue(fn.name));
  h.appendChild(title);
  h.appendChild(el("span", "vh-sub mono", fn.id));
  const graphBtn = el("button", "gbtn sm", "⑂ show in graph");
  graphBtn.type = "button";
  graphBtn.addEventListener("click", () => {
    graphState = { sessionId: s.summary.session_id, focus: id, pos: {}, extra: new Set() };
    select({ kind: "session-view", sessionId: s.summary.session_id, view: "callgraph" });
  });
  h.appendChild(graphBtn);
  root.appendChild(h);

  if (fn.signature) {
    const sig = el("div", "sig");
    sig.appendChild(renderValue(fn.signature));
    root.appendChild(sig);
  }

  const resolve = (name) => (name in s.nameIndex ? s.nameIndex[name] : null);

  // decompiled code (or a hydration hint)
  if (fn.decompile) {
    const ch = el("div", "vh sub");
    ch.appendChild(el("h3", "vh-sub-title", "Decompiled"));
    ch.appendChild(el("span", "badge-untrusted", "untrusted"));
    root.appendChild(ch);
    root.appendChild(codeBlock(plain(fn.decompile), "c", s.summary.session_id, resolve));
  } else {
    root.appendChild(el("p", "muted", "decompiled code not yet streamed (hydrating…)"));
  }

  // relationships
  const rels = el("div", "relgrid");
  const cA = el("div");
  refPanel(cA, "Callers", s.summary.session_id, fn.callers, "no known callers");
  refPanel(cA, "Callees", s.summary.session_id, fn.callees, "no known callees");
  rels.appendChild(cA);
  const cB = el("div");
  refPanel(cB, "Cross-references", s.summary.session_id, fn.xrefs, "no cross-references");
  rels.appendChild(cB);
  root.appendChild(rels);

  // variables / params
  if (fn.variables && fn.variables.length) {
    const sec = el("section", "refpanel");
    sec.appendChild(el("h3", "refpanel-h", "Variables · " + fn.variables.length));
    const scroll = el("div", "tscroll");
    const table = el("table", "grid");
    const thead = el("thead");
    const hr = el("tr");
    ["kind", "name", "type", "storage"].forEach((c) => hr.appendChild(el("th", null, c)));
    thead.appendChild(hr);
    table.appendChild(thead);
    const tb = el("tbody");
    fn.variables.forEach((v) => {
      const tr = el("tr");
      tr.appendChild(el("td", null, v.kind || ""));
      const ntd = el("td");
      ntd.appendChild(renderValue(v.name));
      tr.appendChild(ntd);
      const ttd = el("td", "mono");
      ttd.appendChild(renderValue(v.type));
      tr.appendChild(ttd);
      tr.appendChild(el("td", "mono", v.storage || ""));
      tb.appendChild(tr);
    });
    table.appendChild(tb);
    scroll.appendChild(table);
    sec.appendChild(scroll);
    root.appendChild(sec);
  }

  lineage(root, fn.provenance, [
    (fn.callers || []).length + " callers",
    (fn.callees || []).length + " callees",
  ]);
}

function renderTable(s, data, cols, title) {
  const root = viewerRoot();
  setCrumb([s.summary.session_id, title]);
  if (!data) {
    root.appendChild(el("p", "muted", "not yet streamed"));
    return;
  }
  vhead(root, title, (data.total || (data.items || []).length) + (data.truncated ? " (truncated)" : ""));
  const scroll = el("div", "tscroll");
  const table = el("table", "grid");
  const thead = el("thead");
  const hr = el("tr");
  cols.forEach((c) => hr.appendChild(el("th", null, c)));
  hr.appendChild(el("th", null, "referenced by"));
  thead.appendChild(hr);
  table.appendChild(thead);
  const tb = el("tbody");
  (data.items || []).forEach((it) => {
    const tr = el("tr");
    if (it.id) tr.dataset.rowId = it.id;
    cols.forEach((c) => {
      const td = el("td", c === "address" ? "mono addr" : null);
      td.appendChild(renderValue(it[c]));
      tr.appendChild(td);
    });
    const rtd = el("td");
    (it.referenced_by || []).forEach((r, i) => {
      if (i) rtd.appendChild(document.createTextNode(" "));
      rtd.appendChild(xlink(s.summary.session_id, r, "sm"));
    });
    tr.appendChild(rtd);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  scroll.appendChild(table);
  root.appendChild(scroll);
}

function renderStrings(s) {
  const root = viewerRoot();
  setCrumb([s.summary.session_id, "Strings"]);
  const data = s.strings;
  if (!data) {
    root.appendChild(el("p", "muted", "not yet streamed"));
    return;
  }
  vhead(root, "Strings", (data.total || 0) + (data.truncated ? " (truncated)" : ""));
  const scroll = el("div", "tscroll");
  const table = el("table", "grid");
  const thead = el("thead");
  const hr = el("tr");
  ["address", "len", "value", "referenced by"].forEach((c) => hr.appendChild(el("th", null, c)));
  thead.appendChild(hr);
  table.appendChild(thead);
  const tb = el("tbody");
  (data.items || []).forEach((it) => {
    const tr = el("tr");
    if (it.id) tr.dataset.rowId = it.id;
    const atd = el("td", "mono addr");
    atd.textContent = it.address || "";
    tr.appendChild(atd);
    tr.appendChild(el("td", "mono", typeof it.length === "number" ? it.length + "B" : ""));
    const vtd = el("td");
    vtd.appendChild(renderValue(it.value));
    tr.appendChild(vtd);
    const rtd = el("td");
    (it.referenced_by || []).forEach((r, i) => {
      if (i) rtd.appendChild(document.createTextNode(" "));
      rtd.appendChild(xlink(s.summary.session_id, r, "sm"));
    });
    tr.appendChild(rtd);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  scroll.appendChild(table);
  root.appendChild(scroll);
}

/* ---------------------------------------------------------------- interactive call graph (SVG) */

/** Build a unified graph model for a session from functions + callgraph + imports/strings. */
function buildGraphModel(s) {
  const nodes = {};
  const edges = [];
  const seenE = new Set();
  const kindOf = (id, fallback) => (s.idIndex[id] ? s.idIndex[id].kind : fallback || "function");
  function addNode(id, name, kind) {
    if (!id) return;
    if (!nodes[id]) nodes[id] = { id, name: name || { value: id, untrusted: false }, kind: kind || kindOf(id) };
    else if (name && (!nodes[id].name || nodes[id].name.value === id)) nodes[id].name = name;
  }
  function addEdge(from, to, kind) {
    if (!from || !to || from === to) return;
    const k = from + ">" + to + ">" + kind;
    if (seenE.has(k)) return;
    seenE.add(k);
    edges.push({ from, to, kind });
  }
  Object.values(s.functions).forEach((fn) => {
    addNode(fn.id, fn.name, "function");
    (fn.callees || []).forEach((c) => {
      addNode(c.id, c.name);
      addEdge(fn.id, c.id, "call");
    });
    (fn.callers || []).forEach((c) => {
      addNode(c.id, c.name);
      addEdge(c.id, fn.id, "call");
    });
    (fn.xrefs || []).forEach((x) => {
      const dk = x.kind === "string" || x.kind === "data" ? "data" : "call";
      addNode(x.id, x.name, x.kind === "string" ? "string" : x.kind === "import" ? "import" : undefined);
      addEdge(fn.id, x.id, dk);
    });
  });
  if (s.callgraph) {
    (s.callgraph.nodes || []).forEach((n) => addNode(n.id, n.label, "function"));
    (s.callgraph.edges || []).forEach((e) => addEdge(e.from, e.to, "call"));
  }
  (s.imports && s.imports.items ? s.imports.items : []).forEach((it) => addNode(it.id, it.name, "import"));
  (s.strings && s.strings.items ? s.strings.items : []).forEach((it) => addNode(it.id, it.value, "string"));

  const adj = {};
  edges.forEach((e) => {
    (adj[e.from] = adj[e.from] || []).push(e.to);
    (adj[e.to] = adj[e.to] || []).push(e.from);
  });
  return { nodes, edges, adj };
}

/** Undirected BFS closure from `roots` up to `depth` hops. */
function bfsClosure(adj, roots, depth) {
  const seen = new Set(roots);
  let frontier = [...roots];
  for (let d = 0; d < depth; d++) {
    const next = [];
    frontier.forEach((id) =>
      (adj[id] || []).forEach((n) => {
        if (!seen.has(n)) {
          seen.add(n);
          next.push(n);
        }
      })
    );
    frontier = next;
  }
  return seen;
}

const NODE_W = 132;
const NODE_H = 30;

/** Compute {id:{x,y}} positions for the shown node set per the chosen layout. */
function layoutGraph(model, shown, focus, kind) {
  const ids = [...shown];
  const pos = {};
  if (kind === "radial") {
    const dist = {};
    bfsRanks(model.adj, focus, shown, dist);
    const byR = {};
    ids.forEach((id) => ((byR[dist[id] || 0] = byR[dist[id] || 0] || []).push(id)));
    Object.keys(byR).forEach((r) => {
      const ring = byR[r];
      const radius = Number(r) * 170;
      ring.forEach((id, i) => {
        const a = (i / ring.length) * Math.PI * 2;
        pos[id] = { x: 500 + radius * Math.cos(a), y: 320 + radius * Math.sin(a) };
      });
    });
    if (pos[focus]) pos[focus] = { x: 500, y: 320 };
  } else if (kind === "force") {
    ids.forEach((id, i) => {
      const a = (i / ids.length) * Math.PI * 2;
      pos[id] = { x: 500 + 200 * Math.cos(a), y: 320 + 160 * Math.sin(a) };
    });
    pos[focus] = { x: 500, y: 320 };
    for (let it = 0; it < 220; it++) {
      const fx = {};
      const fy = {};
      ids.forEach((a) => {
        fx[a] = 0;
        fy[a] = 0;
      });
      for (let i = 0; i < ids.length; i++) {
        for (let j = i + 1; j < ids.length; j++) {
          const a = ids[i];
          const b = ids[j];
          let dx = pos[a].x - pos[b].x;
          let dy = pos[a].y - pos[b].y;
          let d2 = dx * dx + dy * dy || 1;
          const f = 24000 / d2;
          const d = Math.sqrt(d2);
          dx /= d;
          dy /= d;
          fx[a] += dx * f;
          fy[a] += dy * f;
          fx[b] -= dx * f;
          fy[b] -= dy * f;
        }
      }
      model.edges.forEach((e) => {
        if (!shown.has(e.from) || !shown.has(e.to)) return;
        let dx = pos[e.to].x - pos[e.from].x;
        let dy = pos[e.to].y - pos[e.from].y;
        const d = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (d - 150) * 0.02;
        dx /= d;
        dy /= d;
        fx[e.from] += dx * f;
        fy[e.from] += dy * f;
        fx[e.to] -= dx * f;
        fy[e.to] -= dy * f;
      });
      ids.forEach((id) => {
        if (id === focus) return; // pin focus
        pos[id].x += Math.max(-30, Math.min(30, fx[id]));
        pos[id].y += Math.max(-30, Math.min(30, fy[id]));
      });
    }
  } else {
    // layered: signed directed distance from focus (callers above, callees below)
    const level = {};
    directedLevels(model.edges, shown, focus, level);
    const byL = {};
    ids.forEach((id) => ((byL[level[id] || 0] = byL[level[id] || 0] || []).push(id)));
    Object.keys(byL)
      .map(Number)
      .sort((a, b) => a - b)
      .forEach((l) => {
        const row = byL[l];
        row.forEach((id, i) => {
          pos[id] = { x: 120 + i * (NODE_W + 40), y: 320 + l * (NODE_H + 70) };
        });
      });
  }
  return pos;
}

function bfsRanks(adj, focus, shown, out) {
  out[focus] = 0;
  let frontier = [focus];
  let d = 0;
  const seen = new Set([focus]);
  while (frontier.length) {
    d++;
    const next = [];
    frontier.forEach((id) =>
      (adj[id] || []).forEach((n) => {
        if (shown.has(n) && !seen.has(n)) {
          seen.add(n);
          out[n] = d;
          next.push(n);
        }
      })
    );
    frontier = next;
  }
}

function directedLevels(edges, shown, focus, out) {
  out[focus] = 0;
  const outAdj = {};
  const inAdj = {};
  edges.forEach((e) => {
    if (!shown.has(e.from) || !shown.has(e.to)) return;
    (outAdj[e.from] = outAdj[e.from] || []).push(e.to);
    (inAdj[e.to] = inAdj[e.to] || []).push(e.from);
  });
  const walk = (adj, sign) => {
    let frontier = [focus];
    const seen = new Set([focus]);
    let d = 0;
    while (frontier.length) {
      d++;
      const next = [];
      frontier.forEach((id) =>
        (adj[id] || []).forEach((n) => {
          if (!seen.has(n)) {
            seen.add(n);
            if (out[n] === undefined) out[n] = sign * d;
            next.push(n);
          }
        })
      );
      frontier = next;
    }
  };
  walk(outAdj, 1);
  walk(inAdj, -1);
  [...shown].forEach((id) => {
    if (out[id] === undefined) out[id] = 0;
  });
}

/** Render the interactive graph view (SVG; movable nodes, click-navigate, double-click-expand). */
function renderCallgraph(s) {
  const root = viewerRoot();
  setCrumb([s.summary.session_id, "Call graph"]);
  const model = buildGraphModel(s);
  const nodeIds = Object.keys(model.nodes);
  if (!nodeIds.length) {
    root.appendChild(el("p", "muted", "no call graph streamed yet"));
    return;
  }

  // focus: keep current if still present, else callgraph root / first function / first node
  let focus = graphState && graphState.sessionId === s.summary.session_id ? graphState.focus : null;
  if (!focus || !model.nodes[focus]) {
    const firstFn = Object.values(s.functions)[0];
    focus =
      (s.callgraph && s.callgraph.edges && s.callgraph.edges[0] && s.callgraph.edges[0].from) ||
      (firstFn && firstFn.id) ||
      nodeIds[0];
  }
  graphState = { sessionId: s.summary.session_id, focus, model, pos: {}, extra: new Set() };

  vhead(root, "Call graph", nodeIds.length + " nodes · " + model.edges.length + " edges");

  // toolbar: layout preference + depth + reset
  const bar = el("div", "gbar");
  bar.appendChild(el("label", "gbar-lab", "layout"));
  const sel = el("select", "gsel");
  [
    ["layered", "Layered"],
    ["force", "Force-directed"],
    ["radial", "Radial"],
  ].forEach(([v, t]) => {
    const o = el("option", null, t);
    o.value = v;
    if (graphPrefs.layout === v) o.selected = true;
    sel.appendChild(o);
  });
  sel.addEventListener("change", () => {
    graphPrefs.layout = sel.value;
    saveGraphPrefs();
    draw();
  });
  bar.appendChild(sel);

  bar.appendChild(el("label", "gbar-lab", "depth"));
  const depth = el("input", "grange");
  depth.type = "range";
  depth.min = "1";
  depth.max = "3";
  depth.value = String(graphPrefs.depth);
  const depthOut = el("span", "gdepth", String(graphPrefs.depth));
  depth.addEventListener("input", () => {
    graphPrefs.depth = +depth.value;
    depthOut.textContent = depth.value;
    saveGraphPrefs();
    graphState.extra = new Set();
    draw();
  });
  bar.appendChild(depth);
  bar.appendChild(depthOut);

  const reset = el("button", "gbtn", "reset view");
  reset.type = "button";
  reset.addEventListener("click", () => {
    graphState.pos = {};
    draw();
  });
  bar.appendChild(reset);
  const focusLab = el("span", "gfocus");
  focusLab.appendChild(document.createTextNode("focus: "));
  focusLab.appendChild(renderValue(model.nodes[focus].name));
  bar.appendChild(focusLab);
  root.appendChild(bar);

  root.appendChild(
    el(
      "p",
      "ghint",
      "drag nodes to arrange · drag background to pan · scroll to zoom · click a node to open it · double-click to expand its neighbors"
    )
  );

  const viewport = el("div", "gviewport");
  const svgEl = svg("svg", { class: "graph", width: "100%", height: "560", role: "group" });
  const defs = svg("defs");
  [
    ["arrow-call", "var(--accent)"],
    ["arrow-data", "var(--warn)"],
  ].forEach(([mid, color]) => {
    const marker = svg("marker", {
      id: mid,
      markerWidth: "9",
      markerHeight: "9",
      refX: "8",
      refY: "3",
      orient: "auto",
      markerUnits: "strokeWidth",
    });
    marker.appendChild(svg("path", { d: "M0,0 L8,3 L0,6 z", fill: color }));
    defs.appendChild(marker);
  });
  svgEl.appendChild(defs);
  const pan = svg("g", { class: "gpan" });
  const edgeLayer = svg("g", { class: "gedges" });
  const nodeLayer = svg("g", { class: "gnodes" });
  pan.appendChild(edgeLayer);
  pan.appendChild(nodeLayer);
  svgEl.appendChild(pan);
  viewport.appendChild(svgEl);
  root.appendChild(viewport);

  const view = { x: 40, y: 20, k: 0.85 };
  function applyView() {
    pan.setAttribute("transform", "translate(" + view.x + "," + view.y + ") scale(" + view.k + ")");
  }

  const nodeEls = {};
  const edgeEls = [];

  function nodeCenter(id) {
    const p = graphState.pos[id] || { x: 0, y: 0 };
    return { x: p.x + NODE_W / 2, y: p.y + NODE_H / 2 };
  }
  function updateEdge(rec) {
    const a = nodeCenter(rec.from);
    const b = nodeCenter(rec.to);
    rec.el.setAttribute("x1", a.x);
    rec.el.setAttribute("y1", a.y);
    rec.el.setAttribute("x2", b.x);
    rec.el.setAttribute("y2", b.y);
  }

  function draw() {
    const sid = s.summary.session_id;
    const shown = bfsClosure(model.adj, [focus, ...graphState.extra], graphPrefs.depth);
    // only lay out nodes that don't already have a user position
    const laid = layoutGraph(model, shown, focus, graphPrefs.layout);
    [...shown].forEach((id) => {
      if (!graphState.pos[id]) graphState.pos[id] = laid[id] || { x: 500, y: 320 };
    });
    edgeLayer.replaceChildren();
    nodeLayer.replaceChildren();
    edgeEls.length = 0;
    model.edges.forEach((e) => {
      if (!shown.has(e.from) || !shown.has(e.to)) return;
      const line = svg("line", {
        class: "gedge edge-" + e.kind,
        "marker-end": e.kind === "data" ? "url(#arrow-data)" : "url(#arrow-call)",
      });
      edgeLayer.appendChild(line);
      const rec = { from: e.from, to: e.to, el: line };
      edgeEls.push(rec);
      updateEdge(rec);
    });
    [...shown].forEach((id) => {
      const n = model.nodes[id];
      const p = graphState.pos[id];
      const g = svg("g", {
        class: "gnode kind-" + n.kind + (id === focus ? " focus" : ""),
        transform: "translate(" + p.x + "," + p.y + ")",
        tabindex: "0",
        role: "button",
      });
      g.setAttribute("aria-label", n.kind + " " + plain(n.name));
      g.appendChild(svg("rect", { class: "grect", width: NODE_W, height: NODE_H, rx: "6" }));
      const icon = svg("text", { class: "gicon", x: 12, y: NODE_H / 2 + 4 });
      icon.textContent = n.kind === "import" ? "⇥" : n.kind === "string" ? '"' : "ƒ";
      g.appendChild(icon);
      const t = svg("text", { class: "gtext", x: 26, y: NODE_H / 2 + 4 });
      t.textContent = plain(n.name); // INERT (raster-free DOM text)
      g.appendChild(t);
      nodeLayer.appendChild(g);
      nodeEls[id] = g;
      wireNode(g, id, sid);
    });
    applyView();
  }

  let drag = null; // {id?, moved, startX, startY, origX, origY}
  function wireNode(g, id, sid) {
    g.addEventListener("pointerdown", (ev) => {
      ev.stopPropagation();
      g.setPointerCapture(ev.pointerId);
      drag = {
        id,
        moved: false,
        startX: ev.clientX,
        startY: ev.clientY,
        origX: graphState.pos[id].x,
        origY: graphState.pos[id].y,
      };
    });
    g.addEventListener("pointermove", (ev) => {
      if (!drag || drag.id !== id) return;
      const dx = (ev.clientX - drag.startX) / view.k;
      const dy = (ev.clientY - drag.startY) / view.k;
      if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
      graphState.pos[id] = { x: drag.origX + dx, y: drag.origY + dy };
      g.setAttribute("transform", "translate(" + graphState.pos[id].x + "," + graphState.pos[id].y + ")");
      edgeEls.forEach((rec) => {
        if (rec.from === id || rec.to === id) updateEdge(rec);
      });
    });
    g.addEventListener("pointerup", (ev) => {
      const wasDrag = drag && drag.moved;
      drag = null;
      if (!wasDrag) navigateById(sid, id); // click = open the artifact
    });
    g.addEventListener("dblclick", (ev) => {
      ev.preventDefault();
      graphState.extra.add(id); // expand this node's neighbors into the graph
      draw();
    });
    g.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") navigateById(sid, id);
      else if (ev.key === "+" || ev.key === "=") {
        graphState.extra.add(id);
        draw();
      }
    });
  }

  // background pan + wheel zoom
  let panning = null;
  svgEl.addEventListener("pointerdown", (ev) => {
    if (ev.target.closest(".gnode")) return;
    panning = { x: ev.clientX, y: ev.clientY, ox: view.x, oy: view.y };
  });
  svgEl.addEventListener("pointermove", (ev) => {
    if (!panning) return;
    view.x = panning.ox + (ev.clientX - panning.x);
    view.y = panning.oy + (ev.clientY - panning.y);
    applyView();
  });
  svgEl.addEventListener("pointerup", () => (panning = null));
  svgEl.addEventListener("pointerleave", () => (panning = null));
  svgEl.addEventListener(
    "wheel",
    (ev) => {
      ev.preventDefault();
      const factor = ev.deltaY < 0 ? 1.1 : 1 / 1.1;
      view.k = Math.max(0.2, Math.min(2.5, view.k * factor));
      applyView();
    },
    { passive: false }
  );

  draw();
}

function renderOutput(out) {
  const root = viewerRoot();
  if (!out) {
    root.appendChild(el("p", "muted", "output not found"));
    return;
  }
  setCrumb([selection.sessionId, out.label || "output"]);
  vhead(root, out.label || "output", null, out.content && out.content.untrusted);
  root.appendChild(codeBlock(out.content ? out.content.value : "", "c", selection.sessionId, null));
}

function renderVerdict(v) {
  const root = viewerRoot();
  setCrumb([selection.sessionId, "Verdict"]);
  if (!v) {
    root.appendChild(el("p", "muted", "no verdict yet"));
    return;
  }
  vhead(root, "Analyst verdict", null, v.content && v.content.untrusted);
  const box = el("div", "verdict");
  const p = el("p", "verdict-text");
  p.appendChild(renderValue(v.content));
  box.appendChild(p);
  root.appendChild(box);
}

function renderTimeline(s) {
  const root = viewerRoot();
  setCrumb([s.summary.session_id, "Timeline"]);
  vhead(root, "Timeline", s.timeline.length + " tool calls");
  const ul = el("ul", "timeline");
  s.timeline.forEach((t) => {
    const li = el("li", "tl-row");
    li.appendChild(el("span", "tl-tool mono", t.tool || "tool"));
    if (t.label) li.appendChild(el("span", "tl-label", t.label));
    ul.appendChild(li);
  });
  if (!s.timeline.length) ul.appendChild(el("li", "muted", "no tool calls yet"));
  root.appendChild(ul);
}

function renderCatalog() {
  const root = viewerRoot();
  setCrumb(["Workflows", "Catalog"]);
  const cat = store.catalog;
  vhead(root, "Workflows", "prebuilt RE workflows + operation palette");
  if (!cat) {
    root.appendChild(el("p", "muted", "catalog unavailable"));
    return;
  }
  root.appendChild(
    el(
      "p",
      "ghint",
      "Phase 1: author + visualize. Workflows run via the agent (out-of-band); results stream back " +
        "into the session views. A custom step-list builder + interactive execution are upcoming."
    )
  );

  // prebuilt workflows
  (cat.workflows || []).forEach((wf) => {
    const card = el("section", "wfcard");
    const hrow = el("div", "vh sub");
    hrow.appendChild(el("h3", "vh-sub-title", wf.name));
    const run = el("button", "gbtn sm", "▷ run");
    run.type = "button";
    run.title = "run read-only steps against the current session";
    run.addEventListener("click", () => runWorkflow(wf.name, wf.steps));
    hrow.appendChild(run);
    card.appendChild(hrow);
    card.appendChild(el("p", "wfcard-desc", wf.desc || ""));
    const ol = el("ol", "wfsteps");
    (wf.steps || []).forEach((st) => {
      const li = el("li", "wfstep");
      li.appendChild(el("span", "wfstep-op mono", st.op));
      li.appendChild(el("span", "wfstep-label", st.label || ""));
      if (st.gated) li.appendChild(el("span", "wfgated", "gated"));
      ol.appendChild(li);
    });
    card.appendChild(ol);
    root.appendChild(card);
  });

  // custom (user-authored) workflows saved on this device
  const custom = loadCustomWorkflows();
  if (custom.length) {
    root.appendChild(el("h3", "card2-h", "Custom workflows"));
    custom.forEach((wf) => {
      const card = el("section", "wfcard");
      const hh = el("div", "vh sub");
      hh.appendChild(el("h4", "vh-sub-title", wf.name || wf.id));
      hh.appendChild(el("span", "wfgated", "custom"));
      card.appendChild(hh);
      const ol = el("ol", "wfsteps");
      (wf.steps || []).forEach((st) => {
        const li = el("li", "wfstep");
        li.appendChild(el("span", "wfstep-op mono", st.op));
        li.appendChild(el("span", "wfstep-label", st.label || ""));
        ol.appendChild(li);
      });
      card.appendChild(ol);
      root.appendChild(card);
    });
  }

  // operation palette (covers vivarium functionality)
  root.appendChild(el("h3", "card2-h", "Operation palette"));
  const grid = el("div", "opgrid");
  (cat.op_groups || []).forEach((grp) => {
    const col = el("section", "opgroup");
    col.appendChild(el("h4", "opgroup-h", grp.group));
    const ul = el("ul", "oplist");
    (grp.ops || []).forEach((op) => {
      const li = el("li", "oprow");
      li.appendChild(el("span", "op-name mono", op.op));
      li.appendChild(el("span", "op-desc", op.desc || ""));
      if (op.gated) li.appendChild(el("span", "wfgated", "gated"));
      ul.appendChild(li);
    });
    col.appendChild(ul);
    grid.appendChild(col);
  });
  root.appendChild(grid);
}

/** Custom step-list workflow builder: compose ordered ops from the palette, save, emit a run spec. */
function renderBuilder() {
  const root = viewerRoot();
  setCrumb(["Workflows", "Builder"]);
  const cat = store.catalog;
  vhead(root, "Workflow builder", "compose an ordered step list from vivarium operations");
  if (!cat) {
    root.appendChild(el("p", "muted", "catalog unavailable"));
    return;
  }
  root.appendChild(
    el(
      "p",
      "ghint",
      "Add operations to build a workflow, then Save it (stored on this device) and copy its spec — " +
        "the agent runs the spec and results stream back into the session views (Phase 1)."
    )
  );

  const wrap = el("div", "builder");

  // left: op palette
  const palette = el("div", "bpalette");
  palette.appendChild(el("h3", "card2-h", "Operations"));
  (cat.op_groups || []).forEach((grp) => {
    palette.appendChild(el("div", "opgroup-h", grp.group));
    (grp.ops || []).forEach((op) => {
      const b = el("button", "opbtn");
      b.type = "button";
      b.appendChild(el("span", "op-name mono", op.op));
      if (op.gated) b.appendChild(el("span", "wfgated", "gated"));
      b.title = op.desc || "";
      b.addEventListener("click", () => {
        builderDraft.steps.push({ op: op.op, label: op.desc || "", gated: !!op.gated });
        renderBuilder();
      });
      palette.appendChild(b);
    });
  });
  wrap.appendChild(palette);

  // right: draft editor
  const editor = el("div", "beditor");
  const nameRow = el("div", "brow");
  nameRow.appendChild(el("label", "gbar-lab", "name"));
  const nameInp = el("input", "binput");
  nameInp.type = "text";
  nameInp.value = builderDraft.name;
  nameInp.placeholder = "my workflow";
  nameInp.addEventListener("input", () => (builderDraft.name = nameInp.value));
  nameRow.appendChild(nameInp);
  editor.appendChild(nameRow);

  const ol = el("ol", "bsteps");
  if (!builderDraft.steps.length) ol.appendChild(el("li", "muted", "no steps — add from the palette"));
  builderDraft.steps.forEach((st, i) => {
    const li = el("li", "bstep");
    li.appendChild(el("span", "bstep-n", String(i + 1)));
    li.appendChild(el("span", "wfstep-op mono", st.op));
    if (st.gated) li.appendChild(el("span", "wfgated", "gated"));
    const up = el("button", "bmini", "↑");
    up.type = "button";
    up.title = "move up";
    up.disabled = i === 0;
    up.addEventListener("click", () => {
      const t = builderDraft.steps[i - 1];
      builderDraft.steps[i - 1] = builderDraft.steps[i];
      builderDraft.steps[i] = t;
      renderBuilder();
    });
    const down = el("button", "bmini", "↓");
    down.type = "button";
    down.title = "move down";
    down.disabled = i === builderDraft.steps.length - 1;
    down.addEventListener("click", () => {
      const t = builderDraft.steps[i + 1];
      builderDraft.steps[i + 1] = builderDraft.steps[i];
      builderDraft.steps[i] = t;
      renderBuilder();
    });
    const rm = el("button", "bmini", "✕");
    rm.type = "button";
    rm.title = "remove";
    rm.addEventListener("click", () => {
      builderDraft.steps.splice(i, 1);
      renderBuilder();
    });
    li.appendChild(up);
    li.appendChild(down);
    li.appendChild(rm);
    ol.appendChild(li);
  });
  editor.appendChild(ol);

  // actions
  const actions = el("div", "brow");
  const save = el("button", "gbtn", "save");
  save.type = "button";
  save.addEventListener("click", () => {
    if (!builderDraft.steps.length) return;
    const list = loadCustomWorkflows();
    const id = "custom-" + Date.now();
    list.push({
      id,
      name: builderDraft.name || "custom workflow",
      steps: builderDraft.steps.map((s) => ({ op: s.op, label: s.label, gated: s.gated })),
    });
    saveCustomWorkflows(list);
    setStatus("saved workflow: " + (builderDraft.name || id));
  });
  const clear = el("button", "gbtn", "clear");
  clear.type = "button";
  clear.addEventListener("click", () => {
    builderDraft = { name: "", steps: [] };
    renderBuilder();
  });
  const run = el("button", "gbtn", "▷ run");
  run.type = "button";
  run.title = "run read-only steps against the current session";
  run.addEventListener("click", () => {
    if (builderDraft.steps.length) runWorkflow(builderDraft.name || "custom workflow", builderDraft.steps);
  });
  actions.appendChild(save);
  actions.appendChild(run);
  actions.appendChild(clear);
  editor.appendChild(actions);

  // emitted spec (copyable) — the agent runs this out-of-band
  editor.appendChild(el("h3", "card2-h", "Run spec"));
  const spec = {
    workflow: builderDraft.name || "custom workflow",
    steps: builderDraft.steps.map((s) => ({ op: s.op, label: s.label })),
  };
  const specText = JSON.stringify(spec, null, 2);
  const pre = el("pre", "bspec");
  pre.textContent = specText; // safe: our own JSON
  editor.appendChild(pre);
  const copy = el("button", "gbtn sm", "copy spec");
  copy.type = "button";
  copy.addEventListener("click", () => {
    try {
      navigator.clipboard.writeText(specText);
      setStatus("run spec copied");
    } catch (_) {
      setStatus("copy unavailable — select the text");
    }
  });
  editor.appendChild(copy);

  wrap.appendChild(editor);
  root.appendChild(wrap);

  // saved list with delete
  const saved = loadCustomWorkflows();
  if (saved.length) {
    root.appendChild(el("h3", "card2-h", "Saved workflows"));
    const ul = el("ul", "savedwf");
    saved.forEach((wf) => {
      const li = el("li", "savedrow");
      li.appendChild(el("span", "savedname", wf.name || wf.id));
      li.appendChild(el("span", "muted", (wf.steps || []).length + " steps"));
      const load = el("button", "bmini", "load");
      load.type = "button";
      load.addEventListener("click", () => {
        builderDraft = {
          name: wf.name || "",
          steps: (wf.steps || []).map((s) => ({ ...s })),
        };
        renderBuilder();
      });
      const del = el("button", "bmini", "✕");
      del.type = "button";
      del.addEventListener("click", () => {
        saveCustomWorkflows(loadCustomWorkflows().filter((x) => x.id !== wf.id));
        renderBuilder();
      });
      li.appendChild(load);
      li.appendChild(del);
      ul.appendChild(li);
    });
    root.appendChild(ul);
  }
}

/* ---------------------------------------------------------------- client-side workflow runner */

// Read-only ops are OPERATIONAL client-side: they resolve against the artifacts already streamed
// into the browser store (no server round-trip, no write path). Each resolver returns a step state
// + an optional artifact view to link. Ops needing fresh server work or a write stay "needs-agent"
// (gated: run via the agent under write-consent — propose-first for AI annotation).
const _sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function _firstFunctionId(s) {
  const f = Object.values(s.functions)[0];
  return f && f.id;
}

const _READONLY_OPS = {
  program_metadata: (s) => (s.metadata ? { state: "done", view: "overview" } : { state: "skipped" }),
  list_strings: (s) => (s.strings ? { state: "done", view: "strings" } : { state: "skipped" }),
  list_imports: (s) => (s.imports ? { state: "done", view: "imports" } : { state: "skipped" }),
  list_exports: (s) => (s.exports ? { state: "done", view: "exports" } : { state: "skipped" }),
  list_functions: (s) => {
    const id = _firstFunctionId(s);
    return id ? { state: "done", view: "function:" + id } : { state: "skipped" };
  },
  call_graph: (s) =>
    s.callgraph || Object.keys(s.functions).length
      ? { state: "done", view: "callgraph" }
      : { state: "skipped" },
  function_context: (s) => {
    const id = _firstFunctionId(s);
    return id ? { state: "done", view: "function:" + id } : { state: "skipped" };
  },
  callers: (s) => {
    const id = _firstFunctionId(s);
    return id ? { state: "done", view: "function:" + id } : { state: "skipped" };
  },
  callees: (s) => {
    const id = _firstFunctionId(s);
    return id ? { state: "done", view: "function:" + id } : { state: "skipped" };
  },
  decompile_function: (s) => {
    const id = _firstFunctionId(s);
    const fn = id && s.functions[id];
    return fn && fn.decompile ? { state: "done", view: "function:" + id } : { state: "skipped" };
  },
};

const _GATED_OPS = new Set([
  "session_import",
  "session_analyze",
  "session_close",
  "rename_function",
  "rename_local_variable",
  "rename_parameter",
  "set_comment",
  "set_function_signature",
  "ai_annotate",
]);

function _pickSession() {
  if (selection && selection.sessionId && store.sessions[selection.sessionId]) return selection.sessionId;
  return Object.keys(store.sessions)[0];
}

/** Run a workflow's steps against the browser store: read-only ops execute + link their artifact;
 *  gated / not-yet-streamed ops are marked needs-agent (run via the agent). Live-updates the Runs
 *  view as it goes — operational, client-side, no server write path. */
async function runWorkflow(name, steps) {
  const sid = _pickSession();
  if (!sid) {
    setStatus("no session to run against");
    return;
  }
  const s = store.sessions[sid];
  const runId = "uirun-" + Date.now();
  const run = {
    id: runId,
    name: (name || "workflow") + " (UI run)",
    state: "running",
    steps: (steps || []).map((st) => ({ op: st.op, label: st.label || "", state: "pending" })),
  };
  s.workflows[runId] = run;
  select({ kind: "session-view", sessionId: sid, view: "runs" });
  for (let i = 0; i < run.steps.length; i++) {
    run.steps[i].state = "running";
    if (selection && selection.view === "runs") renderViewer();
    await _sleep(110);
    const op = run.steps[i].op;
    let res;
    if (_GATED_OPS.has(op)) res = { state: "needs-agent" };
    else if (_READONLY_OPS[op]) res = _READONLY_OPS[op](s);
    else res = { state: "needs-agent" }; // scans / similarity: not in the client store → agent
    run.steps[i].state = res.state;
    if (res.view) run.steps[i].view = res.view;
    if (selection && selection.view === "runs") renderViewer();
    await _sleep(110);
  }
  run.state = "done";
  if (selection && selection.view === "runs") renderViewer();
  setStatus("ran " + (name || "workflow") + " — read-only steps applied; gated steps → needs-agent");
}

const _RUN_STEP_ICON = {
  done: "✓",
  running: "▷",
  failed: "✕",
  pending: "○",
  "needs-agent": "⇢",
  skipped: "–",
};

function renderRuns(s) {
  const root = viewerRoot();
  setCrumb([s.summary.session_id, "Runs"]);
  const runs = Object.values(s.workflows);
  vhead(root, "Workflow runs", runs.length + " run(s)");
  if (!runs.length) {
    root.appendChild(el("p", "muted", "no workflow runs yet"));
    return;
  }
  runs.forEach((run) => {
    const card = el("section", "wfcard");
    const h = el("div", "vh sub");
    h.appendChild(el("h3", "vh-sub-title", run.name || run.id));
    h.appendChild(el("span", "run-state state-" + (run.state || "pending"), run.state || "pending"));
    card.appendChild(h);
    const ol = el("ol", "runsteps");
    (run.steps || []).forEach((st) => {
      const li = el("li", "runstep step-" + (st.state || "pending"));
      li.appendChild(el("span", "run-ico", _RUN_STEP_ICON[st.state] || "○"));
      li.appendChild(el("span", "wfstep-op mono", st.op));
      li.appendChild(el("span", "wfstep-label", st.label || ""));
      if (st.view) {
        const link = el("button", "xlink sm", "view →");
        link.type = "button";
        link.addEventListener("click", () =>
          select({ kind: "session-view", sessionId: s.summary.session_id, view: st.view })
        );
        li.appendChild(link);
      }
      ol.appendChild(li);
    });
    card.appendChild(ol);
    root.appendChild(card);
  });
}

/** AI-annotation proposals (apply-transform, propose-first): review a diff per item, approve, then
 *  submit the approved set through the GATED command path — the write happens under write-consent,
 *  never auto from here. All proposed/current text is untrusted → rendered inert. */
function renderProposals(s) {
  const root = viewerRoot();
  setCrumb([s.summary.session_id, "Proposals"]);
  const sets = Object.values(s.annotations);
  vhead(root, "AI annotation proposals", "review · approve · apply (gated write-consent)");
  if (!sets.length) {
    root.appendChild(el("p", "muted", "no proposals yet"));
    return;
  }
  root.appendChild(
    el(
      "p",
      "ghint",
      "Proposed by the agent from decompiled evidence. Applying is a GATED write (write-consent) — " +
        "approved items are submitted for the agent to apply; nothing is written from the browser."
    )
  );
  sets.forEach((set) => {
    const approved = new Set((set.items || []).map((_, i) => i)); // default: all approved
    const card = el("section", "wfcard");
    const h = el("div", "vh sub");
    h.appendChild(el("h3", "vh-sub-title", "proposal " + set.id));
    h.appendChild(el("span", "badge-untrusted", "untrusted"));
    card.appendChild(h);

    const ul = el("ul", "proplist");
    (set.items || []).forEach((it, i) => {
      const li = el("li", "proprow");
      const cb = el("input", "propcb");
      cb.type = "checkbox";
      cb.checked = true;
      cb.addEventListener("change", () => (cb.checked ? approved.add(i) : approved.delete(i)));
      li.appendChild(cb);
      const body = el("div", "propbody");
      const head = el("div", "prophead");
      head.appendChild(el("span", "propkind", it.kind));
      head.appendChild(renderValue(it.target && it.target.name)); // inert target
      body.appendChild(head);
      const diff = el("div", "propdiff");
      const cur = el("span", "diff-old");
      cur.appendChild(renderValue(it.current));
      const arr = el("span", "diff-arr", " → ");
      const prop = el("span", "diff-new");
      prop.appendChild(renderValue(it.proposed));
      diff.appendChild(cur);
      diff.appendChild(arr);
      diff.appendChild(prop);
      body.appendChild(diff);
      if (it.rationale) {
        const r = el("div", "proprat");
        r.appendChild(document.createTextNode("why: "));
        r.appendChild(renderValue(it.rationale));
        body.appendChild(r);
      }
      li.appendChild(body);
      ul.appendChild(li);
    });
    card.appendChild(ul);

    const actions = el("div", "brow");
    const apply = el("button", "gbtn", "apply approved (gated)");
    apply.type = "button";
    const status = el("span", "propstatus muted");
    apply.addEventListener("click", async () => {
      const items = (set.items || []).filter((_, i) => approved.has(i));
      if (!items.length) {
        status.textContent = "nothing approved";
        return;
      }
      status.textContent = "submitting…";
      try {
        const r = await fetch("/api/command", {
          method: "POST",
          headers: cmdHeaders(),
          body: JSON.stringify({
            op: "ai_annotate",
            params: { proposal_id: set.id, count: items.length },
          }),
        });
        if (r.status === 503) status.textContent = "interactive disabled — approved set recorded for the agent to apply (write-consent)";
        else if (r.status === 403) status.textContent = "interactive requires auth";
        else if (r.status === 202) status.textContent = "gated: queued for human-approved apply (write-consent)";
        else if (r.ok) status.textContent = "applied (" + items.length + ") — reversible via session_undo";
        else status.textContent = "submit failed (" + r.status + ")";
      } catch (_) {
        status.textContent = "submit failed";
      }
    });
    actions.appendChild(apply);
    actions.appendChild(status);
    card.appendChild(actions);
    root.appendChild(card);
  });
}

function renderBuild() {
  const root = viewerRoot();
  setCrumb(["Build & deliverables"]);
  const b = store.build || {};
  vhead(root, "Build & deliverables");
  const tiles = el("div", "tiles");
  const t1 = el("div", "tile");
  t1.appendChild(el("div", "tile-num mono", b.tool_count || 0));
  t1.appendChild(el("div", "tile-lab", "tools (" + (b.read_only_count || 0) + " read-only)"));
  tiles.appendChild(t1);
  const bench = b.benchmark || {};
  const t2 = el("div", "tile");
  t2.appendChild(el("div", "tile-num mono", (bench.verdict_hits || 0) + "/" + (bench.cases || 0)));
  t2.appendChild(el("div", "tile-lab", "benchmark verdict hits"));
  tiles.appendChild(t2);
  root.appendChild(tiles);

  const gates = el("div", "gates");
  (b.gates || []).forEach((g) => {
    const chip = el("span", "gate gate-" + g.status, g.name);
    chip.title = g.status;
    gates.appendChild(chip);
  });
  root.appendChild(gates);

  if ((b.recent_prs || []).length) {
    root.appendChild(el("h3", "card2-h", "Recent"));
    const ul = el("ul", "prs");
    b.recent_prs.forEach((p) => ul.appendChild(el("li", "pr", p)));
    root.appendChild(ul);
  }
}

/* ------------------------------------------------------------------ live streaming */

/** Merge a function-context event into the store by id (progressive hydrate). */
function mergeFunction(s, d) {
  if (!d || !d.id) return;
  const cur = s.functions[d.id] || { id: d.id };
  ["name", "signature", "decompile", "provenance"].forEach((k) => {
    if (d[k] !== undefined && d[k] !== null) cur[k] = d[k];
  });
  ["callers", "callees", "xrefs", "variables"].forEach((k) => {
    if (Array.isArray(d[k])) cur[k] = d[k];
  });
  s.functions[d.id] = cur;
  indexSymbol(s, d.id, "function", "function:" + d.id, cur.name ? plain(cur.name) : null);
  // index xref targets by name so code jump-to can resolve imports/strings referenced here
  (cur.xrefs || []).forEach((r) => {
    if (r.id && r.name) s.nameIndex[plain(r.name)] = r.id;
  });
}

function indexItems(s, items, kind, view) {
  (items || []).forEach((it) => {
    if (it.id) indexSymbol(s, it.id, kind, view, it.name ? plain(it.name) : null);
  });
}

function applyEvent(id, e) {
  const s = ensureSession(id);
  if (e.kind === "progress") {
    if (typeof e.percent === "number") s.summary.progress_percent = e.percent;
    if (e.phase) s.summary.phase = e.phase;
  } else if (e.kind === "metadata") s.metadata = e.data || null;
  else if (e.kind === "imports") {
    s.imports = e.data || null;
    indexItems(s, s.imports && s.imports.items, "import", "imports");
  } else if (e.kind === "exports") {
    s.exports = e.data || null;
    indexItems(s, s.exports && s.exports.items, "export", "exports");
  } else if (e.kind === "strings") {
    s.strings = e.data || null;
    indexItems(s, s.strings && s.strings.items, "string", "strings");
  } else if (e.kind === "callgraph") s.callgraph = e.data || null;
  else if (e.kind === "function") mergeFunction(s, e.data);
  else if (e.kind === "workflow") {
    if (e.data && e.data.id) s.workflows[e.data.id] = { ...s.workflows[e.data.id], ...e.data };
  } else if (e.kind === "annotations") {
    if (e.data && e.data.id) s.annotations[e.data.id] = e.data;
  } else if (e.kind === "tool") s.timeline.push({ tool: e.tool, label: e.label });
  else if (e.kind === "output") s.outputs.push({ label: e.label, content: e.content });
  else if (e.kind === "verdict") s.verdict = { label: e.label, content: e.content };
}

function affectsView(e, id) {
  if (!selection || selection.kind !== "session-view" || selection.sessionId !== id) return false;
  const v = selection.view;
  if (e.kind === "progress" || e.kind === "metadata") return v === "overview";
  if (e.kind === "tool") return v === "timeline";
  if (e.kind === "output") return true;
  if (e.kind === "function") return v === "function:" + (e.data && e.data.id);
  if (e.kind === "workflow") return v === "runs";
  if (e.kind === "annotations") return v === "proposals";
  return v === e.kind; // imports/exports/strings/callgraph/verdict
}

/** Signature of what the explorer shows for a session (rebuild only when it changes). */
function explorerShape(id) {
  const s = store.sessions[id];
  if (!s) return null;
  return [
    s.summary.state,
    Object.keys(s.functions).length,
    s.imports ? s.imports.total : 0,
    s.exports ? s.exports.total : 0,
    s.strings ? s.strings.total : 0,
    !!s.callgraph,
    s.outputs.length,
    !!s.verdict,
    Object.keys(s.workflows).length,
    Object.keys(s.annotations).length,
  ];
}

function attachStream(id) {
  const src = new EventSource("/api/sessions/" + encodeURIComponent(id) + "/events");
  src.onmessage = (ev) => {
    let e;
    try {
      e = JSON.parse(ev.data);
    } catch (_) {
      return;
    }
    const before = JSON.stringify(explorerShape(id));
    applyEvent(id, e);
    if (JSON.stringify(explorerShape(id)) !== before) buildExplorer();
    if (affectsView(e, id)) renderViewer();
  };
  src.onerror = () => src.close();
}

/* ------------------------------------------------------------------ boot */

/** Wire the titlebar token field to localStorage (per-viewer; sent only on command POSTs). */
function initToken() {
  const ti = document.getElementById("token");
  if (!ti) return;
  try {
    ti.value = localStorage.getItem("vivarium.dashboard.token") || "";
  } catch (_) {
    /* ignore */
  }
  ti.addEventListener("input", () => {
    try {
      localStorage.setItem("vivarium.dashboard.token", ti.value);
    } catch (_) {
      /* ignore */
    }
  });
}

/* ------------------------------------------------------------------ sidebar (collapse / mobile) */

// Whether the viewport is phone-width (off-canvas sidebar territory).
function isNarrow() {
  return window.matchMedia("(max-width: 760px)").matches;
}

// Reflect the current sidebar-hidden state onto <body>, the toggle button, and the scrim.
function applySidebar() {
  const hidden = document.body.classList.contains("sidebar-hidden");
  const btn = document.getElementById("sidebar-toggle");
  if (btn) btn.setAttribute("aria-expanded", String(!hidden));
  const scrim = document.getElementById("scrim");
  if (scrim) scrim.setAttribute("aria-hidden", String(hidden || !isNarrow()));
}

function setSidebarHidden(hidden) {
  document.body.classList.toggle("sidebar-hidden", hidden);
  try {
    localStorage.setItem("vivarium.dashboard.sidebar", hidden ? "hidden" : "shown");
  } catch (_) {
    /* storage blocked — state holds for this view only */
  }
  applySidebar();
}

// On a phone, collapse the (overlay) sidebar after picking an item so the main pane is visible.
function closeSidebarOnMobile() {
  if (isNarrow()) setSidebarHidden(true);
}

function initSidebar() {
  const btn = document.getElementById("sidebar-toggle");
  const scrim = document.getElementById("scrim");
  // Default: hidden on a phone (main pane full-width), shown on desktop — unless the viewer chose.
  let hidden = isNarrow();
  try {
    const pref = localStorage.getItem("vivarium.dashboard.sidebar");
    if (pref === "hidden") hidden = true;
    else if (pref === "shown") hidden = false;
  } catch (_) {
    /* ignore */
  }
  document.body.classList.toggle("sidebar-hidden", hidden);
  applySidebar();
  if (btn)
    btn.addEventListener("click", () =>
      setSidebarHidden(!document.body.classList.contains("sidebar-hidden"))
    );
  if (scrim) scrim.addEventListener("click", () => setSidebarHidden(true));
  // Esc closes the overlay on a phone.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && isNarrow() && !document.body.classList.contains("sidebar-hidden"))
      setSidebarHidden(true);
  });
  // Keep the scrim/aria correct across rotate/resize.
  window.addEventListener("resize", applySidebar);
}

async function load() {
  initToken();
  initSidebar();
  try {
    const [sr, br, cr] = await Promise.all([
      fetch("/api/sessions"),
      fetch("/api/build"),
      fetch("/api/catalog"),
    ]);
    const sd = await sr.json();
    store.build = await br.json();
    try {
      store.catalog = await cr.json();
    } catch (_) {
      store.catalog = null;
    }
    (sd.sessions || []).forEach((sum) => {
      ensureSession(sum.session_id).summary = sum;
    });
    buildExplorer();
    setConn("live", true);
    setStatus((sd.sessions || []).length + " session(s)");
    (sd.sessions || []).forEach((sum) => attachStream(sum.session_id));
    const first = (sd.sessions || [])[0];
    if (first) select({ kind: "session-view", sessionId: first.session_id, view: "overview" });
  } catch (err) {
    setConn("disconnected", false);
    setStatus("failed to load");
  }
}

document.addEventListener("DOMContentLoaded", load);
