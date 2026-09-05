/* Vivarium status dashboard — VSCode-style shell (read-only, display-only).
 *
 * SECURITY (ADR-005): every binary-derived value arrives tagged {value, untrusted:true}. This
 * script renders ALL such content — including inside the syntax colorizer — ONLY via textContent
 * (never innerHTML / insertAdjacentHTML / any DOM-string sink), so hostile bytes appear verbatim and
 * inert. The colorizer splits text into tokens and appends each as a <span> whose text is set with
 * textContent; tokenizing never changes that guarantee. The strict, inline-free CSP is the
 * defense-in-depth backstop. All DOM is built with createElement + textContent.
 */
"use strict";

/* ------------------------------------------------------------------ DOM helpers */

/** Create an element with an optional class and safe text (textContent — never HTML). */
function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

/** Render one value inert: a tagged {value, untrusted} object → textContent span (the sink for
 *  hostile bytes); a plain scalar → text node. */
function renderValue(v) {
  if (v && typeof v === "object" && "value" in v && "untrusted" in v) {
    const span = el("span", v.untrusted ? "u" : "s");
    span.textContent = String(v.value);
    if (v.untrusted) span.title = "binary-derived (untrusted) — shown inert";
    return span;
  }
  return document.createTextNode(v === null || v === undefined ? "" : String(v));
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
// One combined, backtracking-safe tokenizer: block comment | line comment | string | char |
// number | identifier. Anything unmatched is emitted as plain text between matches.
const C_TOKEN =
  /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|0[xX][0-9a-fA-F]+|\b\d+\b|[A-Za-z_]\w*/g;

/** Classify a matched token into a colorizer class (or null for a bare identifier). */
function classifyToken(tok) {
  if (tok.startsWith("/*") || tok.startsWith("//")) return "c-com";
  if (tok[0] === '"' || tok[0] === "'") return "c-str";
  if (/^[0-9]/.test(tok)) return "c-num";
  if (C_KEYWORDS.has(tok)) return "c-kw";
  if (C_TYPES.has(tok)) return "c-ty";
  if (/^(FUN_|LAB_|DAT_|PTR_|UNK_|switchD_|code_)/.test(tok)) return "c-sym"; // Ghidra auto-names
  return null;
}

/** Append one line of C, colorized, into `lineEl` — every token via textContent (inert). */
function colorizeInto(lineEl, line) {
  C_TOKEN.lastIndex = 0;
  let last = 0;
  let m;
  while ((m = C_TOKEN.exec(line)) !== null) {
    if (m.index > last) lineEl.appendChild(document.createTextNode(line.slice(last, m.index)));
    const cls = classifyToken(m[0]);
    if (cls) {
      const s = el("span", cls);
      s.textContent = m[0]; // INERT
      lineEl.appendChild(s);
    } else {
      lineEl.appendChild(document.createTextNode(m[0]));
    }
    last = m.index + m[0].length;
  }
  if (last < line.length) lineEl.appendChild(document.createTextNode(line.slice(last)));
}

/** Build a colorized code block with a line-number gutter. `text` is untrusted; rendered inert. */
function codeBlock(text, lang) {
  const wrap = el("div", "codeblock");
  if (lang) wrap.dataset.lang = lang;
  const lines = String(text).split("\n");
  lines.forEach((line, i) => {
    const gutter = el("span", "ln", String(i + 1));
    const code = el("span", "lc");
    if (lang === "c") colorizeInto(code, line);
    else code.textContent = line; // non-C: plain inert text
    wrap.appendChild(gutter);
    wrap.appendChild(code);
  });
  return wrap;
}

/* ------------------------------------------------------------------ state store */

const store = { sessions: {}, build: null };
let selection = null; // { kind: "session-view"|"build", sessionId?, view? }

function ensureSession(id) {
  if (!store.sessions[id]) {
    store.sessions[id] = {
      summary: { session_id: id, state: "?", progress_percent: null },
      metadata: null,
      imports: null,
      exports: null,
      strings: null,
      callgraph: null,
      timeline: [],
      outputs: [],
      verdict: null,
    };
  }
  return store.sessions[id];
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
  btn.appendChild(el("span", "tw-label", label));
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

  const sessGroup = el("div", "tw-group");
  sessGroup.appendChild(el("div", "tw-group-h", "Sessions"));
  const ids = Object.keys(store.sessions);
  if (!ids.length) sessGroup.appendChild(el("div", "tw-none", "no active sessions"));

  ids.forEach((id) => {
    const s = store.sessions[id];
    sessGroup.appendChild(
      treeItem(id, {
        depth: 0,
        icon: "i-sess",
        iconText: "●",
        state: s.summary.state,
        onClick: () => select({ kind: "session-view", sessionId: id, view: "overview" }),
      })
    );
    const kid = (label, view, opts) =>
      sessGroup.appendChild(
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
  root.appendChild(sessGroup);

  const bGroup = el("div", "tw-group");
  bGroup.appendChild(el("div", "tw-group-h", "Build"));
  bGroup.appendChild(
    treeItem("Build & deliverables", {
      depth: 0,
      icon: "i-build",
      iconText: "◆",
      active: isActive("build"),
      onClick: () => select({ kind: "build" }),
    })
  );
  root.appendChild(bGroup);
}

/* ------------------------------------------------------------------ selection + viewer */

function select(sel) {
  selection = sel;
  buildExplorer();
  renderViewer();
}

function setCrumb(parts) {
  const c = document.getElementById("crumb");
  c.replaceChildren();
  parts.forEach((p, i) => {
    if (i) c.appendChild(el("span", "crumb-sep", "›"));
    c.appendChild(el("span", "crumb-part", p));
  });
}

function viewerRoot() {
  const v = document.getElementById("viewer");
  v.replaceChildren();
  return v;
}

function viewTitle(view) {
  if (view === "overview") return "Overview";
  if (view && view.indexOf("output:") === 0) return "Decompiled output";
  return view ? view.charAt(0).toUpperCase() + view.slice(1) : "";
}

function renderViewer() {
  if (!selection) return;
  if (selection.kind === "build") return renderBuild();
  const s = store.sessions[selection.sessionId];
  if (!s) return;
  const view = selection.view;
  setCrumb([selection.sessionId, viewTitle(view)]);
  setStatus(selection.sessionId + " · " + s.summary.state);
  if (view === "overview") return renderOverview(s);
  if (view === "imports") return renderTable(s.imports, ["address", "name", "library"], "Imports");
  if (view === "exports") return renderTable(s.exports, ["address", "name"], "Exports");
  if (view === "strings") return renderStrings(s.strings);
  if (view === "callgraph") return renderCallgraph(s.callgraph);
  if (view === "verdict") return renderVerdict(s.verdict);
  if (view === "timeline") return renderTimeline(s);
  if (view && view.indexOf("output:") === 0) return renderOutput(s.outputs[+view.slice(7)]);
}

function panelTitle(root, text, sub) {
  const h = el("div", "vh");
  h.appendChild(el("h2", "vh-title", text));
  if (sub) h.appendChild(el("span", "vh-sub", sub));
  root.appendChild(h);
}

function renderOverview(s) {
  const root = viewerRoot();
  panelTitle(root, "Overview", s.summary.state);

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

function renderTable(data, cols, title) {
  const root = viewerRoot();
  if (!data) {
    root.appendChild(el("p", "muted", "not yet streamed"));
    return;
  }
  panelTitle(
    root,
    title,
    (data.total || (data.items || []).length) + (data.truncated ? " (truncated)" : "")
  );
  const scroll = el("div", "tscroll");
  const table = el("table", "grid");
  const thead = el("thead");
  const hr = el("tr");
  cols.forEach((c) => hr.appendChild(el("th", null, c)));
  thead.appendChild(hr);
  table.appendChild(thead);
  const tb = el("tbody");
  (data.items || []).forEach((it) => {
    const tr = el("tr");
    cols.forEach((c) => {
      const td = el("td", c === "address" ? "mono addr" : null);
      td.appendChild(renderValue(it[c]));
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  scroll.appendChild(table);
  root.appendChild(scroll);
}

function renderStrings(data) {
  const root = viewerRoot();
  if (!data) {
    root.appendChild(el("p", "muted", "not yet streamed"));
    return;
  }
  panelTitle(root, "Strings", (data.total || 0) + (data.truncated ? " (truncated)" : ""));
  const scroll = el("div", "tscroll");
  const table = el("table", "grid");
  const thead = el("thead");
  const hr = el("tr");
  ["address", "len", "value"].forEach((c) => hr.appendChild(el("th", null, c)));
  thead.appendChild(hr);
  table.appendChild(thead);
  const tb = el("tbody");
  (data.items || []).forEach((it) => {
    const tr = el("tr");
    const atd = el("td", "mono addr");
    atd.textContent = it.address || "";
    tr.appendChild(atd);
    tr.appendChild(el("td", "mono", typeof it.length === "number" ? it.length + "B" : ""));
    const vtd = el("td");
    vtd.appendChild(renderValue(it.value));
    tr.appendChild(vtd);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  scroll.appendChild(table);
  root.appendChild(scroll);
}

function renderCallgraph(data) {
  const root = viewerRoot();
  if (!data) {
    root.appendChild(el("p", "muted", "not yet streamed"));
    return;
  }
  const labels = {};
  (data.nodes || []).forEach((n) => (labels[n.id] = n.label));
  const adj = {};
  (data.edges || []).forEach((e) => (adj[e.from] = adj[e.from] || []).push(e.to));
  panelTitle(
    root,
    "Call graph",
    (data.nodes || []).length +
      " nodes · " +
      (data.edges || []).length +
      " edges" +
      (data.truncated ? " (truncated)" : "")
  );
  const ul = el("ul", "cg");
  Object.keys(adj).forEach((from) => {
    const li = el("li", "cg-row");
    li.appendChild(renderValue(labels[from] || from));
    li.appendChild(el("span", "cg-arrow", " → "));
    const callees = el("span", "cg-callees");
    adj[from].forEach((to, i) => {
      if (i) callees.appendChild(document.createTextNode(", "));
      callees.appendChild(renderValue(labels[to] || to));
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
  const head = el("div", "vh");
  head.appendChild(el("h2", "vh-title", out.label || "output"));
  if (out.content && out.content.untrusted)
    head.appendChild(el("span", "badge-untrusted", "untrusted"));
  root.appendChild(head);
  root.appendChild(codeBlock(out.content ? out.content.value : "", "c"));
}

function renderVerdict(v) {
  const root = viewerRoot();
  if (!v) {
    root.appendChild(el("p", "muted", "no verdict yet"));
    return;
  }
  panelTitle(root, "Analyst verdict");
  const box = el("div", "verdict");
  if (v.content && v.content.untrusted) box.appendChild(el("span", "badge-untrusted", "untrusted"));
  const p = el("p", "verdict-text");
  p.appendChild(renderValue(v.content));
  box.appendChild(p);
  root.appendChild(box);
}

function renderTimeline(s) {
  const root = viewerRoot();
  panelTitle(root, "Timeline", s.timeline.length + " tool calls");
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
  panelTitle(root, "Build & deliverables");
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

function applyEvent(id, e) {
  const s = ensureSession(id);
  if (e.kind === "progress") {
    if (typeof e.percent === "number") s.summary.progress_percent = e.percent;
    if (e.phase) s.summary.phase = e.phase;
  } else if (e.kind === "metadata") s.metadata = e.data || null;
  else if (e.kind === "imports") s.imports = e.data || null;
  else if (e.kind === "exports") s.exports = e.data || null;
  else if (e.kind === "strings") s.strings = e.data || null;
  else if (e.kind === "callgraph") s.callgraph = e.data || null;
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
  return v === e.kind; // imports/exports/strings/callgraph/verdict
}

/** A cheap signature of what the explorer shows for a session, to decide when to rebuild it. */
function explorerShape(id) {
  const s = store.sessions[id];
  if (!s) return null;
  return [
    s.summary.state,
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
  src.onerror = () => src.close(); // one-shot demo stream; a live provider reconnects w/ backoff
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
