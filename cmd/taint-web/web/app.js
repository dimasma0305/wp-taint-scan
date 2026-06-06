"use strict";

/* ---------- tiny safe DOM builder (text nodes only, no innerHTML) ---------- */
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  if (props) for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v === true) e.setAttribute(k, "");
    else e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return e;
}
const $ = (sel) => document.querySelector(sel);
const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); };

/* ---------- state ---------- */
const state = {
  jobs: new Map(),       // id -> job
  view: "discover",
  jobFilter: "all",
  selected: new Set(),   // selected versions in drawer
  search: { q: "", sort: "relevance", minInstalls: 0, maxInstalls: 0, minRating: 0, page: 1 },
};

/* ---------- API ---------- */
const api = {
  async get(url) {
    const r = await fetch(url);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
    return j;
  },
  async post(url, body) {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : null });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
    return j;
  },
};

/* ---------- toasts ---------- */
function toast(msg, kind = "") {
  const t = h("div", { class: "toast " + kind, text: msg });
  $("#toasts").append(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .3s"; setTimeout(() => t.remove(), 300); }, 3600);
}

/* ---------- formatting ---------- */
function fmtInstalls(n) {
  if (!n) return "—";
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M+";
  if (n >= 1e3) return Math.floor(n / 1e3) + "K+";
  return String(n);
}
function fmtDur(ms) {
  if (!ms) return "—";
  if (ms < 1000) return ms + "ms";
  if (ms < 60000) return (ms / 1000).toFixed(1) + "s";
  return Math.floor(ms / 60000) + "m" + Math.round((ms % 60000) / 1000) + "s";
}
function stars(rating) { // rating is 0..100
  const full = Math.round((rating || 0) / 20);
  return "★".repeat(full) + "☆".repeat(5 - full);
}

/* ---------- severity helpers ---------- */
const SEV = ["critical", "high", "medium", "low", "info"];
function countPills(c) {
  if (!c) return null;
  const f = document.createDocumentFragment();
  const map = [["c", c.critical], ["h", c.high], ["m", c.medium], ["l", c.low]];
  let any = false;
  for (const [cls, n] of map) if (n) { f.append(h("span", { class: "count-pill " + cls, text: n })); any = true; }
  if (!any && c.total === 0) f.append(h("span", { class: "muted", text: "clean" }));
  if (!any && c.total > 0) f.append(h("span", { class: "count-pill l", text: c.total }));
  return f;
}
function sevPill(sev) {
  return h("span", { class: "sev sev-" + sev }, h("span", { class: "dot" }), sev);
}

/* ---------- tabs / views ---------- */
function showView(name) {
  state.view = name;
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
  if (name === "jobs") renderJobs();
  if (name === "diff") populateDiffPlugins();
}

/* ---------- search ---------- */
function searchActive() {
  const s = state.search;
  return s.q !== "" || s.sort !== "relevance" || s.minInstalls > 0 || s.maxInstalls > 0 || s.minRating > 0;
}
let searchTimer = null;
function onSearchInput(e) {
  state.search.q = e.target.value.trim();
  state.search.page = 1;
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => applySearch(), 350);
}
// applySearch reads state.search and fetches a page. With nothing active it
// shows popular plugins so the page is never blank.
async function applySearch() {
  const s = state.search;
  const qs = new URLSearchParams({
    q: s.q, page: String(s.page), sort: s.sort,
    min_installs: String(s.minInstalls), max_installs: String(s.maxInstalls), min_rating: String(s.minRating),
  });
  $("#searchStatus").textContent = s.q || searchActive() ? "Searching…" : "Loading popular plugins…";
  try {
    const res = await api.get("/api/search?" + qs.toString());
    renderResults(res);
    renderPager(res);
  } catch (err) {
    $("#searchStatus").textContent = "Search failed: " + err.message;
    $("#pager").hidden = true;
  }
}
function renderPager(res) {
  const pager = $("#pager");
  clear(pager);
  const pages = res.pages || 1, page = res.page || 1;
  if (pages <= 1) { pager.hidden = true; return; }
  pager.hidden = false;
  pager.append(
    h("button", { class: "btn ghost sm", disabled: page <= 1, onclick: () => gotoPage(page - 1) }, "‹ Prev"),
    h("span", { class: "pageinfo", text: `Page ${page} of ${pages}` }),
    h("button", { class: "btn ghost sm", disabled: page >= pages, onclick: () => gotoPage(page + 1) }, "Next ›"),
  );
}
function gotoPage(p) {
  state.search.page = p;
  applySearch();
  window.scrollTo({ top: 0, behavior: "smooth" });
}
function renderResults(res) {
  const grid = $("#results");
  clear(grid);
  const plugins = res.plugins || [];
  const total = res.results || plugins.length;
  let status = total.toLocaleString() + " result" + (total === 1 ? "" : "s");
  if (res.capped) status += " (showing first matches — narrow your search to see more)";
  if (plugins.length === 0) status = "No plugins match these filters.";
  $("#searchStatus").textContent = status;
  for (const p of plugins) {
    const icon = p.icons && (p.icons.svg || p.icons["2x"] || p.icons["1x"] || p.icons.default) || "";
    const card = h("div", { class: "card", onclick: () => openPlugin(p.slug, p.name) },
      icon && /^https:\/\//.test(icon) ? h("img", { class: "icon", src: icon, loading: "lazy", alt: "" }) : h("div", { class: "icon" }),
      h("div", { class: "body" },
        h("div", { class: "name", text: p.name }),
        h("div", { class: "author", text: "by " + (p.author_name || "unknown") }),
        h("div", { class: "desc", text: p.short_description || "" }),
        h("div", { class: "meta" },
          h("span", {}, h("b", { text: fmtInstalls(p.active_installs) }), " installs"),
          h("span", { title: (p.num_ratings || 0) + " ratings", text: stars(p.rating) }),
          p.version ? h("span", {}, "v", h("b", { text: p.version })) : null,
        ),
      ),
      h("button", {
        class: "btn sm card-scan", title: "Scan the latest version",
        onclick: (e) => { e.stopPropagation(); doScan(p.slug, p.name, [], "latest", { stay: true }); },
      }, "Scan latest"),
    );
    grid.append(card);
  }
}

/* ---------- plugin drawer ---------- */
let openJobId = null; // id of the job whose findings drawer is open (for live updates)
function closeDrawer() { openJobId = null; $("#drawer").hidden = true; $("#overlay").hidden = true; clear($("#drawer")); }
$("#overlay")?.addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

async function openPlugin(slug, name) {
  openJobId = null;
  state.selected = new Set();
  const drawer = $("#drawer");
  $("#overlay").hidden = false;
  drawer.hidden = false;
  clear(drawer);
  drawer.append(h("div", { class: "drawer-body" }, h("div", { class: "spinner-lg" })));
  try {
    const info = await api.get("/api/plugin?slug=" + encodeURIComponent(slug));
    renderPluginDrawer(info, name);
  } catch (err) {
    clear(drawer);
    drawer.append(
      h("div", { class: "drawer-head" }, h("h2", { text: name || slug }), h("button", { class: "close", text: "×", onclick: closeDrawer })),
      h("div", { class: "drawer-body" }, h("p", { class: "muted", text: "Failed to load plugin: " + err.message })),
    );
  }
}

function renderPluginDrawer(info, fallbackName) {
  const drawer = $("#drawer");
  clear(drawer);
  const icon = info.icons && (info.icons.svg || info.icons["2x"] || info.icons["1x"]) || "";
  const versions = info.sorted_versions || [];
  const scanned = info.scanned || {};

  drawer.append(
    h("div", { class: "drawer-head" },
      icon && /^https:\/\//.test(icon) ? h("img", { class: "icon", src: icon, alt: "" }) : h("div", { class: "icon" }),
      h("div", {},
        h("h2", { text: info.name || fallbackName }),
        h("p", { class: "sub", text: "by " + (info.author_name || "unknown") + " · " + fmtInstalls(info.active_installs) + " installs · " + versions.length + " versions" }),
      ),
      h("button", { class: "close", text: "×", onclick: closeDrawer }),
    ),
  );

  const body = h("div", { class: "drawer-body" });
  body.append(h("p", { class: "muted", text: info.short_description || "" }));

  // actions
  const selCountSpan = h("span", { text: "0" });
  const scanSelBtn = h("button", { class: "btn", disabled: true, onclick: () => doScan(info.slug, info.name, [...state.selected], "selected") },
    "Scan selected (", selCountSpan, ")");
  body.append(h("div", { class: "actions-row" },
    h("button", { class: "btn", onclick: () => doScan(info.slug, info.name, [], "latest") }, "Scan latest (", versions[0] || "?", ")"),
    scanSelBtn,
    h("button", { class: "btn ghost", onclick: () => confirmScanAll(info.slug, info.name, versions.length) }, "Scan all ", versions.length),
  ));

  // version filter + list
  const list = h("div", { class: "ver-list" });
  const render = (fstr) => renderVersions(list, info, versions, scanned, fstr, selCountSpan, scanSelBtn);
  const filter = h("input", { type: "search", placeholder: "Filter versions…", oninput: (e) => render(e.target.value.trim()) });
  body.append(h("div", { class: "ver-tools" },
    filter,
    h("button", { class: "btn ghost sm", onclick: () => { state.selected = new Set(versions); render(filter.value.trim()); } }, "Select all"),
    h("button", { class: "btn ghost sm", onclick: () => { state.selected = new Set(); render(filter.value.trim()); } }, "None"),
  ));
  body.append(list);
  render("");
  drawer.append(body);
}

function renderVersions(list, info, versions, scanned, filterStr, selCountSpan, scanSelBtn) {
  clear(list);
  const shown = filterStr ? versions.filter((v) => v.includes(filterStr)) : versions;
  shown.slice(0, 500).forEach((v, i) => {
    const cb = h("input", { type: "checkbox" });
    cb.checked = state.selected.has(v);
    cb.addEventListener("change", () => {
      if (cb.checked) state.selected.add(v); else state.selected.delete(v);
      selCountSpan.textContent = String(state.selected.size);
      scanSelBtn.disabled = state.selected.size === 0;
    });
    const row = h("div", { class: "ver-row" },
      cb,
      h("span", { class: "v", text: v }),
      (!filterStr && i === 0) ? h("span", { class: "latest", text: "latest" }) : null,
    );
    const sc = scanned[v];
    const tail = h("span", { class: "scanned" });
    if (sc) { const p = countPills(sc); if (p) tail.append(p); }
    tail.append(h("button", { class: "btn ghost sm", onclick: () => doScan(info.slug, info.name, [v], "selected") }, "Scan"));
    row.append(tail);
    list.append(row);
  });
  if (shown.length === 0) list.append(h("div", { class: "ver-row muted", text: "No matching versions" }));
  selCountSpan.textContent = String(state.selected.size);
  scanSelBtn.disabled = state.selected.size === 0;
}

function confirmScanAll(slug, name, n) {
  if (n > 25 && !confirm("Scan all " + n + " versions? This will download and analyze each one.")) return;
  doScan(slug, name, [], "all");
}

async function doScan(slug, name, versions, mode, opts = {}) {
  try {
    const res = await api.post("/api/scan", { slug, name, versions: versions || [], mode });
    (res.jobs || []).forEach((j) => state.jobs.set(j.id, j));
    updateBadge();
    const verb = res.jobs && res.jobs[0] && res.jobs[0].from_cache ? "Loaded cached scan" : "Queued " + res.count + " scan" + (res.count === 1 ? "" : "s");
    toast(verb + " for " + slug, "ok");
    if (opts.stay) return;            // card scan: stay on Discover
    closeDrawer();
    showView("jobs");
  } catch (err) {
    toast("Scan failed: " + err.message, "err");
  }
}

/* ---------- jobs view ---------- */
function jobMatchesFilter(j) {
  switch (state.jobFilter) {
    case "active": return j.status === "queued" || j.status === "downloading" || j.status === "scanning";
    case "done": return j.status === "done";
    case "failed": return j.status === "failed" || j.status === "skipped" || j.status === "canceled";
    default: return true;
  }
}

function statusPill(j) {
  const running = j.status === "downloading" || j.status === "scanning";
  return h("span", { class: "pstatus st-" + j.status },
    running ? h("span", { class: "spin" }) : null,
    j.status + (j.from_cache ? " (cached)" : ""),
  );
}

function renderJobs() {
  const wrap = $("#jobsList");
  clear(wrap);
  const all = [...state.jobs.values()].filter(jobMatchesFilter);
  const empty = $("#jobsEmpty");
  empty.hidden = all.length > 0;
  empty.textContent = state.jobs.size > 0
    ? "No jobs match this filter."
    : "No scans yet. Find a plugin in Discover and scan a version.";
  // group by batch
  const batches = new Map();
  for (const j of all) {
    const key = j.batch_id || j.id;
    if (!batches.has(key)) batches.set(key, []);
    batches.get(key).push(j);
  }
  // newest batch first (by max queued time)
  const ordered = [...batches.entries()].sort((a, b) => maxQueued(b[1]) - maxQueued(a[1]));
  for (const [key, jobs] of ordered) {
    if (jobs.length > 1) wrap.append(renderBatch(jobs));
    else wrap.append(renderJobRow(jobs[0], false));
  }
}
function maxQueued(jobs) { return Math.max(...jobs.map((j) => new Date(j.queued_at).getTime() || 0)); }

function renderBatch(jobs) {
  jobs.sort((a, b) => a.version < b.version ? 1 : -1);
  const done = jobs.filter((j) => j.status === "done" || j.status === "failed" || j.status === "skipped" || j.status === "canceled").length;
  const pct = Math.round((done / jobs.length) * 100);
  const totals = jobs.reduce((acc, j) => {
    if (j.counts) { acc.critical += j.counts.critical; acc.high += j.counts.high; acc.medium += j.counts.medium; acc.low += j.counts.low; acc.total += j.counts.total; }
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  const box = h("div", { class: "batch" },
    h("div", { class: "batch-head" },
      h("b", { text: jobs[0].plugin_name || jobs[0].slug }),
      h("span", { class: "muted", text: done + "/" + jobs.length + " done" }),
      h("div", { class: "progress" }, h("div", { style: "width:" + pct + "%" })),
      countPills(totals) || null,
    ),
  );
  for (const j of jobs) box.append(renderJobRow(j, true));
  return box;
}

function renderJobRow(j, inBatch) {
  const running = j.status === "queued" || j.status === "downloading" || j.status === "scanning";
  return h("div", { class: "job", onclick: () => openFindings(j.id) },
    h("span", { class: "ver", text: j.version }),
    inBatch ? null : h("span", { class: "plug", text: j.plugin_name || j.slug }),
    statusPill(j),
    h("div", { class: "grow" }, j.error ? h("span", { class: "muted", text: j.error }) : null),
    h("div", { class: "counts" }, j.status === "done" ? (countPills(j.counts) || null) : null),
    h("span", { class: "dur", text: running ? "" : fmtDur(j.duration_ms) }),
    running ? h("button", { class: "btn danger sm", onclick: (e) => { e.stopPropagation(); cancelJob(j.id); } }, "Cancel") : null,
  );
}

async function cancelJob(id) {
  try { await api.post("/api/cancel?id=" + encodeURIComponent(id)); toast("Canceled", "ok"); }
  catch (err) { toast(err.message, "err"); }
}

/* ---------- findings drawer ---------- */
let findingsFilter = "all";
async function openFindings(id) {
  const drawer = $("#drawer");
  $("#overlay").hidden = false; drawer.hidden = false; clear(drawer);
  drawer.append(h("div", { class: "drawer-body" }, h("div", { class: "spinner-lg" })));
  try {
    const job = await api.get("/api/job?id=" + encodeURIComponent(id));
    openJobId = id;
    findingsFilter = "all";
    renderFindings(job);
  } catch (err) {
    clear(drawer);
    drawer.append(h("div", { class: "drawer-body" }, h("p", { class: "muted", text: err.message })));
  }
}

function renderFindings(job) {
  const drawer = $("#drawer");
  clear(drawer);
  drawer.append(
    h("div", { class: "drawer-head" },
      h("div", {},
        h("h2", { text: (job.plugin_name || job.slug) + " " + job.version }),
        h("p", { class: "sub", text: job.status + " · " + (job.counts ? job.counts.total : 0) + " findings · scanned in " + fmtDur(job.engine_ms || job.duration_ms) + (job.truncated ? " · ⚠ partial (memory)" : "") }),
      ),
      h("button", { class: "close", text: "×", onclick: closeDrawer }),
    ),
  );
  const body = h("div", { class: "drawer-body" });

  if (job.status !== "done") {
    body.append(h("p", { class: "muted", text: job.error || ("Job is " + job.status + "…") }));
    drawer.append(body); return;
  }

  // export + filter chips
  body.append(h("div", { class: "actions-row" },
    h("a", { class: "btn ghost sm", href: "/api/job/export?id=" + encodeURIComponent(job.id) + "&format=md", target: "_blank" }, "Export .md"),
    h("a", { class: "btn ghost sm", href: "/api/job/export?id=" + encodeURIComponent(job.id) + "&format=json", target: "_blank" }, "Export .json"),
    h("button", { class: "btn ghost sm", onclick: () => doScan(job.slug, job.plugin_name, [job.version], "selected") }, "Rescan"),
  ));

  const findings = job.findings || [];
  const counts = job.counts || {};
  const filterRow = h("div", { class: "find-filters" });
  const mkChip = (key, label, n) => {
    const c = h("button", { class: "chip" + (findingsFilter === key ? " active" : ""), onclick: () => { findingsFilter = key; renderFindings(job); } }, label + (n != null ? " " + n : ""));
    return c;
  };
  filterRow.append(mkChip("all", "All", counts.total || 0));
  if (counts.critical) filterRow.append(mkChip("critical", "Critical", counts.critical));
  if (counts.high) filterRow.append(mkChip("high", "High", counts.high));
  if (counts.medium) filterRow.append(mkChip("medium", "Medium", counts.medium));
  if (counts.low) filterRow.append(mkChip("low", "Low", counts.low));
  body.append(filterRow);

  const shown = findings.filter((f) => findingsFilter === "all" || f.severity === findingsFilter);
  if (shown.length === 0) body.append(h("p", { class: "muted", text: "No findings in this category. 🎉" }));
  for (const f of shown) body.append(renderFinding(f));
  drawer.append(body);
}

function renderFinding(f) {
  const card = h("div", { class: "finding" });
  const head = h("div", { class: "finding-head", onclick: () => card.classList.toggle("open") },
    sevPill(f.severity),
    h("div", { class: "grow" },
      h("div", { class: "rule", text: f.rule_id }),
      h("div", { class: "msg", text: f.message }),
      h("div", { class: "loc", text: f.path + ":" + f.line }),
    ),
  );
  const bodyEl = h("div", { class: "finding-body" });
  // access / capability
  const kv = h("div", { class: "kv" });
  if (f.access) kv.append(h("span", {}, h("b", { text: "access " }), f.access));
  if (f.required_capability) kv.append(h("span", {}, h("b", { text: "capability " }), f.required_capability));
  if (f.minimum_role) kv.append(h("span", {}, h("b", { text: "min role " }), f.minimum_role));
  if (f.callable) kv.append(h("span", {}, h("b", { text: "in " }), f.callable));
  if (kv.children.length) bodyEl.append(kv);
  // entrypoints
  if (f.entrypoints && f.entrypoints.length) {
    const ekv = h("div", { class: "kv" });
    for (const e of f.entrypoints) ekv.append(h("span", {}, h("b", { text: (e.kind || "entry") + " " }), [e.route, e.name, e.methods].filter(Boolean).join(" ")));
    bodyEl.append(ekv);
  }
  // dataflow trace
  const trace = h("div", { class: "trace" });
  if (f.source && f.source.path) trace.append(traceStep("source", f.source));
  if (f.sink && f.sink.path) trace.append(traceStep("sink", f.sink));
  if (trace.children.length) bodyEl.append(trace);
  card.append(head, bodyEl);
  return card;
}
function traceStep(tag, loc) {
  const step = h("div", { class: "step" },
    h("span", { class: "tag", text: tag }),
    h("div", {}, h("code", { text: loc.path + ":" + loc.line }),
      loc.snippet ? h("div", { class: "snippet", text: loc.snippet.trim() }) : null),
  );
  return step;
}

/* ---------- diff view ---------- */
// plugins with >=2 scanned versions are eligible for diffing
function diffEligiblePlugins() {
  const m = new Map();
  for (const j of state.jobs.values()) {
    if (j.status !== "done") continue;
    if (!m.has(j.slug)) m.set(j.slug, { name: j.plugin_name || j.slug, versions: new Set() });
    m.get(j.slug).versions.add(j.version);
  }
  return [...m.entries()].filter(([, v]) => v.versions.size >= 2);
}
function populateDiffPlugins() {
  const sel = $("#diffSlug");
  const cur = sel.value;
  const eligible = diffEligiblePlugins().sort((a, b) => a[1].name.localeCompare(b[1].name));
  clear(sel);
  sel.append(h("option", { value: "", text: eligible.length ? "choose a plugin…" : "scan ≥2 versions of a plugin first" }));
  for (const [slug, v] of eligible) sel.append(h("option", { value: slug, text: v.name + " (" + v.versions.size + " versions)" }));
  if (eligible.some(([s]) => s === cur)) sel.value = cur;
  refreshDiffVersions();
}
function refreshDiffVersions() {
  const slug = $("#diffSlug").value;
  const done = [...state.jobs.values()].filter((j) => j.slug === slug && j.status === "done").map((j) => j.version);
  const uniq = [...new Set(done)].sort((a, b) => a < b ? 1 : -1); // newest first
  for (const sel of [$("#diffA"), $("#diffB")]) {
    clear(sel);
    sel.append(h("option", { value: "", text: sel.id === "diffA" ? "version A…" : "version B…" }));
    for (const v of uniq) sel.append(h("option", { value: v, text: v }));
  }
  if (uniq.length >= 2) { $("#diffA").value = uniq[1]; $("#diffB").value = uniq[0]; } // older → newest
}
async function runDiff() {
  const slug = $("#diffSlug").value.trim(), a = $("#diffA").value, b = $("#diffB").value;
  const out = $("#diffResult");
  clear(out);
  if (!slug || !a || !b) { toast("Pick a slug and two scanned versions", "err"); return; }
  try {
    const d = await api.get("/api/diff?slug=" + encodeURIComponent(slug) + "&a=" + encodeURIComponent(a) + "&b=" + encodeURIComponent(b));
    renderDiff(d);
  } catch (err) { out.append(h("p", { class: "muted", text: err.message })); }
}
function renderDiff(d) {
  const out = $("#diffResult");
  clear(out);
  out.append(h("p", { class: "muted", text: (d.added || []).length + " introduced, " + (d.removed || []).length + " fixed, " + (d.common || []).length + " unchanged between " + d.version_a + " → " + d.version_b }));
  const cols = h("div", { class: "diff-cols" });
  const col = (cls, title, items) => {
    const c = h("div", { class: "diff-col " + cls }, h("h3", {}, title + " (" + items.length + ")"));
    if (!items.length) c.append(h("p", { class: "muted", text: "none" }));
    for (const f of items) c.append(renderFinding(f));
    return c;
  };
  cols.append(col("added", "🔴 Introduced in " + d.version_b, d.added || []));
  cols.append(col("removed", "🟢 Fixed in " + d.version_b, d.removed || []));
  out.append(cols);
}

/* ---------- live updates ---------- */
function updateBadge() {
  const active = [...state.jobs.values()].filter((j) => j.status === "queued" || j.status === "downloading" || j.status === "scanning").length;
  const badge = $("#jobsBadge");
  badge.hidden = active === 0;
  badge.textContent = String(active);
}
let statsTimer = null;
function scheduleStats() { // coalesce bursts during big batches
  if (statsTimer) return;
  statsTimer = setTimeout(() => { statsTimer = null; refreshStats(); }, 1500);
}
function connectSSE() {
  const es = new EventSource("/api/events");
  es.addEventListener("job", (ev) => {
    try {
      const data = JSON.parse(ev.data);
      if (data.job) {
        state.jobs.set(data.job.id, data.job);
        updateBadge();
        if (state.view === "jobs") renderJobs();
        if (openJobId && data.job.id === openJobId) renderFindings(data.job);
        scheduleStats();
      }
    } catch (_) {}
  });
  // On (re)connect, re-pull the authoritative job list so nothing is stuck after
  // a dropped connection missed terminal events.
  es.onopen = () => {
    loadExistingJobs().then(() => { updateBadge(); if (state.view === "jobs") renderJobs(); });
  };
  es.onerror = () => { /* browser auto-reconnects */ };
}

async function refreshStats() {
  try {
    const s = await api.get("/api/stats");
    const box = $("#stats");
    clear(box);
    const stat = (num, lbl, cls) => h("div", { class: "stat " + (cls || "") }, h("span", { class: "num", text: num }), h("span", { class: "lbl", text: lbl }));
    box.append(stat(s.plugins_scanned, "scanned"));
    if (s.findings) box.append(stat(s.findings.critical + s.findings.high, "high+crit", (s.findings.critical ? "crit" : "")));
    if (s.running) box.append(stat(s.running, "running"));
  } catch (_) {}
}

async function loadExistingJobs() {
  try {
    const jobs = await api.get("/api/jobs");
    for (const j of jobs) state.jobs.set(j.id, j);
    updateBadge();
  } catch (_) {}
}

/* ---------- init ---------- */
async function init() {
  $("#tabs").addEventListener("click", (e) => { const t = e.target.closest(".tab"); if (t) showView(t.dataset.view); });
  $("#search").addEventListener("input", onSearchInput);
  $("#fSort").addEventListener("change", (e) => { state.search.sort = e.target.value; state.search.page = 1; applySearch(); });
  $("#fInstalls").addEventListener("change", (e) => {
    const [mn, mx] = e.target.value.split(":").map(Number);
    state.search.minInstalls = mn || 0; state.search.maxInstalls = mx || 0; state.search.page = 1; applySearch();
  });
  $("#fRating").addEventListener("change", (e) => { state.search.minRating = Number(e.target.value) || 0; state.search.page = 1; applySearch(); });
  $("#fReset").addEventListener("click", () => {
    Object.assign(state.search, { sort: "relevance", minInstalls: 0, maxInstalls: 0, minRating: 0, page: 1 });
    $("#fSort").value = "relevance"; $("#fInstalls").value = "0:0"; $("#fRating").value = "0";
    applySearch();
  });
  $("#jobFilters").addEventListener("click", (e) => {
    const c = e.target.closest(".chip"); if (!c) return;
    state.jobFilter = c.dataset.filter;
    document.querySelectorAll("#jobFilters .chip").forEach((x) => x.classList.toggle("active", x === c));
    renderJobs();
  });
  $("#clearJobs").addEventListener("click", () => {
    for (const [id, j] of state.jobs) if (j.status !== "queued" && j.status !== "downloading" && j.status !== "scanning") state.jobs.delete(id);
    renderJobs(); updateBadge();
  });
  $("#diffSlug").addEventListener("change", refreshDiffVersions);
  $("#diffRun").addEventListener("click", runDiff);

  // quick chips + bounty preset
  $("#quickChips").addEventListener("click", (e) => {
    const c = e.target.closest(".chip");
    if (!c) return;
    if (c.dataset.preset === "fresh") {
      Object.assign(state.search, { q: "", sort: "new", minInstalls: 0, maxInstalls: 1000, minRating: 0, page: 1 });
      $("#search").value = ""; $("#fSort").value = "new"; $("#fInstalls").value = "0:1000"; $("#fRating").value = "0";
    } else if (c.dataset.q) {
      Object.assign(state.search, { q: c.dataset.q, page: 1 });
      $("#search").value = c.dataset.q;
    }
    applySearch();
  });

  // "/" focuses the search box (unless already typing)
  document.addEventListener("keydown", (e) => {
    if (e.key !== "/" || e.ctrlKey || e.metaKey) return;
    const t = e.target.tagName;
    if (t === "INPUT" || t === "TEXTAREA" || t === "SELECT") return;
    e.preventDefault();
    $("#search").focus();
  });

  await loadExistingJobs(); // load before SSE so no live update gets clobbered
  connectSSE();
  applySearch();            // show popular plugins on load (no blank screen)
  refreshStats();
  setInterval(refreshStats, 8000);
}
init();
