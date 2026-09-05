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

const store = { sessions: {}, build: null };
let selection = null; // { kind:"session-view"|"build", sessionId?, view? }
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
  return (
    selection.kind === "session-view" &&
    selection.sessionId === sessionId &&
    selection.view === view
  );
}

function buildExplorer() {
  const root = document.getElementById("explorer");
  root.replaceChildren();

  const g = el("div", "tw-group");
  g.appendChild(el("div", "tw-group-h", "Sessions"));
  const ids = Object.keys(store.sessions);
  if (!ids.length) g.appendChild(el("div", "tw-none", "no active sessions"));

  ids.forEach((id) => {
    const s = store.sessions[id];
    g.appendChild(
      treeItem(id, {
        depth: 0,
        icon: "i-sess",
        iconText: "●",
        state: s.summary.state,
        onClick: () => select({ kind: "session-view", sessionId: id, view: "overview" }),
      })
    );
    const kid = (label, view, opts) =>
      g.appendChild(
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
      g.appendChild(el("div", "tw-sub", "Functions · " + fns.length));
      fns.forEach((fn) => {
        const lab = el("span", "tw-label");
        lab.appendChild(renderValue(fn.name)); // inert name
        g.appendChild(
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
    kid("Timeline", "timeline", { icon: "i-time", iconText: "≡" });
  });
  root.appendChild(g);

  const b = el("div", "tw-group");
  b.appendChild(el("div", "tw-group-h", "Build"));
  b.appendChild(
    treeItem("Build & deliverables", {
      depth: 0,
      icon: "i-build",
      iconText: "◆",
      active: isActive("build"),
      onClick: () => select({ kind: "build" }),
    })
  );
  root.appendChild(b);
}

/* ------------------------------------------------------------------ selection + navigation */

function select(sel) {
  selection = sel;
  buildExplorer();
  renderViewer();
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
    else if (view.indexOf("function:") === 0) renderFunction(s, view.slice(9));
    else if (view.indexOf("output:") === 0) renderOutput(s.outputs[+view.slice(7)]);
  }
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

function renderCallgraph(s) {
  const root = viewerRoot();
  setCrumb([s.summary.session_id, "Call graph"]);
  const data = s.callgraph;
  if (!data) {
    root.appendChild(el("p", "muted", "not yet streamed"));
    return;
  }
  const labels = {};
  (data.nodes || []).forEach((n) => (labels[n.id] = n.label));
  const adj = {};
  (data.edges || []).forEach((e) => (adj[e.from] = adj[e.from] || []).push(e.to));
  vhead(
    root,
    "Call graph",
    (data.nodes || []).length + " nodes · " + (data.edges || []).length + " edges" + (data.truncated ? " (truncated)" : "")
  );
  const ul = el("ul", "cg");
  Object.keys(adj).forEach((from) => {
    const li = el("li", "cg-row");
    li.appendChild(xlink(s.summary.session_id, { id: from, name: labels[from] || { value: from, untrusted: false } }));
    li.appendChild(el("span", "cg-arrow", " → "));
    const callees = el("span", "cg-callees");
    adj[from].forEach((to, i) => {
      if (i) callees.appendChild(document.createTextNode(", "));
      callees.appendChild(xlink(s.summary.session_id, { id: to, name: labels[to] || { value: to, untrusted: false } }));
    });
    li.appendChild(callees);
    ul.appendChild(li);
  });
  root.appendChild(ul);
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
  else if (e.kind === "tool") s.timeline.push({ tool: e.tool, label: e.label });
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

async function load() {
  try {
    const [sr, br] = await Promise.all([fetch("/api/sessions"), fetch("/api/build")]);
    const sd = await sr.json();
    store.build = await br.json();
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
