/* Vivarium status dashboard — read-only, display-only MVP.
 *
 * SECURITY: every binary-derived field arrives tagged {value, untrusted:true} (ADR-005). This script
 * renders such content ONLY via textContent (never innerHTML / insertAdjacentHTML / DOM-string
 * sinks), so hostile bytes appear verbatim and inert. The strict CSP (no inline, no eval) is the
 * defense-in-depth backstop. All DOM is built with createElement + textContent.
 */
"use strict";

/** Create an element with a class and safe text (textContent — never HTML). */
function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

/** Render a tagged UiValue ({value, untrusted}) as INERT text into a <pre>. Untrusted or not, we
 *  only ever set textContent — the `untrusted` flag drives a visible marker, not the render mode. */
function renderUntrusted(uiValue, label) {
  const wrap = el("div", "out");
  const head = el("div", "out-head");
  head.appendChild(el("span", "out-label", label || "output"));
  if (uiValue && uiValue.untrusted) head.appendChild(el("span", "badge-untrusted", "untrusted"));
  wrap.appendChild(head);
  const pre = el("pre", "out-body");
  pre.textContent = uiValue ? String(uiValue.value) : ""; // INERT — the one render sink for hostile bytes
  wrap.appendChild(pre);
  return wrap;
}

function setConn(text, ok) {
  const c = document.getElementById("conn");
  c.textContent = text;
  c.classList.toggle("ok", !!ok);
  c.classList.toggle("bad", ok === false);
}

/** Build one session card (safe scalars) + attach a live SSE stream for its events. */
function sessionCard(s) {
  const li = el("li", "card");
  li.dataset.session = s.session_id;

  const head = el("div", "card-head");
  head.appendChild(el("span", "sid mono", s.session_id));
  head.appendChild(el("span", "state state-" + s.state, s.state));
  li.appendChild(head);

  if (s.binary_sha256) {
    const sha = el("div", "sha mono", s.binary_sha256);
    sha.title = "input sha256 (server-computed, safe)";
    li.appendChild(sha);
  }

  const bar = el("div", "bar");
  const fill = el("div", "bar-fill");
  const pct = typeof s.progress_percent === "number" ? s.progress_percent : 0;
  fill.style.width = pct + "%";
  bar.setAttribute("role", "progressbar");
  bar.setAttribute("aria-valuemin", "0");
  bar.setAttribute("aria-valuemax", "100");
  bar.setAttribute("aria-valuenow", String(pct));
  bar.appendChild(fill);
  li.appendChild(bar);

  const meta = el("div", "meta");
  meta.appendChild(el("span", "phase", s.phase || "—"));
  meta.appendChild(el("span", "tools", (s.tool_count || 0) + " tool calls"));
  if (s.last_tool) meta.appendChild(el("span", "mono last", s.last_tool));
  li.appendChild(meta);

  const stream = el("div", "stream");
  li.appendChild(stream);

  attachStream(s.session_id, li, fill, bar, stream);
  return li;
}

/** Open the SSE stream for a session; update the progress bar + append outputs/verdicts inert. */
function attachStream(sid, li, fill, bar, stream) {
  const src = new EventSource("/api/sessions/" + encodeURIComponent(sid) + "/events");
  src.onmessage = (ev) => {
    let e;
    try {
      e = JSON.parse(ev.data);
    } catch (_) {
      return;
    }
    if (e.kind === "progress" && typeof e.percent === "number") {
      fill.style.width = e.percent + "%";
      bar.setAttribute("aria-valuenow", String(e.percent));
      const ph = li.querySelector(".phase");
      if (ph && e.phase) ph.textContent = e.phase;
    } else if (e.kind === "tool") {
      const row = el("div", "ev ev-tool");
      row.appendChild(el("span", "mono", e.tool || "tool"));
      if (e.label) row.appendChild(el("span", "ev-label", e.label));
      stream.appendChild(row);
    } else if (e.kind === "output" || e.kind === "verdict") {
      stream.appendChild(renderUntrusted(e.content, e.label || e.kind));
    }
  };
  src.onerror = () => src.close(); // MVP: one-shot demo stream; a live provider reconnects w/ backoff
}

function renderBuild(b) {
  const root = document.getElementById("build");
  root.replaceChildren();

  const tiles = el("div", "tiles");
  const t1 = el("div", "tile");
  t1.appendChild(el("div", "tile-num mono", b.tool_count));
  t1.appendChild(el("div", "tile-lab", "tools (" + b.read_only_count + " read-only)"));
  tiles.appendChild(t1);
  const bench = b.benchmark || {};
  const t2 = el("div", "tile");
  t2.appendChild(el("div", "tile-num mono", (bench.verdict_hits || 0) + "/" + (bench.cases || 0)));
  t2.appendChild(el("div", "tile-lab", "benchmark verdict hits"));
  tiles.appendChild(t2);
  root.appendChild(tiles);

  const gh = el("div", "gates");
  (b.gates || []).forEach((g) => {
    const chip = el("span", "gate gate-" + g.status, g.name);
    chip.title = g.status;
    gh.appendChild(chip);
  });
  root.appendChild(gh);

  if ((b.recent_prs || []).length) {
    const h = el("h3", "sub-h", "recent");
    root.appendChild(h);
    const ul = el("ul", "prs");
    b.recent_prs.forEach((p) => ul.appendChild(el("li", "pr", p)));
    root.appendChild(ul);
  }
}

async function load() {
  try {
    const [sr, br] = await Promise.all([fetch("/api/sessions"), fetch("/api/build")]);
    const sd = await sr.json();
    const bd = await br.json();
    const list = document.getElementById("sessions");
    list.replaceChildren();
    (sd.sessions || []).forEach((s) => list.appendChild(sessionCard(s)));
    renderBuild(bd);
    setConn("live", true);
  } catch (err) {
    setConn("disconnected", false);
  }
}

document.addEventListener("DOMContentLoaded", load);
