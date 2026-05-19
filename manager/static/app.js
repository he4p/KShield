const state = {
  page: "dashboard",
  search: "",
  rangeHours: 0,
  summary: null,
  agents: [],
  events: [],
  detections: [],
  detectors: [],
  blockedIpv4: [],
  blockedBindPorts: [],
  blockedExecPaths: [],
  protectedWriteTargets: [],
  ptraceDenies: [],
  selectedDetectionId: null,
  agentToken: "",
  agentMetrics: [],
  benchmarks: null,
  detectionsOffset: 0,
  detectionsTotal: 0,
  detectionsPageSize: 30,
  detectionsSeverity: "",
  // Per-page filters
  eventsFilterType: "",
  eventsFilterAction: "",
  eventsFilterSeverity: "",
  eventsFilterAgent: "",
  detectorsFilterSeverity: "",
  detectorsFilterTag: "",
};

/* ---- util ---- */
async function fetchJson(url, opts = {}) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function esc(v) { return String(v ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
function setText(id, v) { const el = document.getElementById(id); if (el) el.textContent = String(v); }
function formatNumber(v) { return Number(v || 0).toLocaleString(); }

function formatTs(v) {
  const d = new Date(v);
  if (isNaN(d)) return String(v || "-");
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function relativeTime(v) {
  const d = new Date(v);
  if (isNaN(d)) return "-";
  const s = Math.max(0, Math.floor((Date.now() - d) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function deriveStatus(agent) {
  const t = new Date(agent.last_seen);
  if (isNaN(t)) return "offline";
  return Date.now() - t <= 15000 ? "online" : "offline";
}

function sevClass(v) { const k = String(v||"").toLowerCase(); return k === "critical" || k === "high" ? "critical" : k === "warning" || k === "medium" ? "warning" : "info"; }
function actClass(v) { const k = String(v||"").toLowerCase(); return k === "block" ? "block" : k === "allow" ? "allowed" : "info"; }

function agentName(id) {
  const a = state.agents.find(a => a.id === id);
  return a ? a.hostname : (id || "-").slice(0, 8);
}

function toast(msg, type = "info") {
  const c = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

function inScope(ts) {
  if (!state.rangeHours) return true;
  const p = new Date(ts).getTime();
  return isNaN(p) || p >= Date.now() - state.rangeHours * 3600000;
}

function createEmptyState(title, copy) {
  const t = document.getElementById("empty-state-template");
  const n = t.content.firstElementChild.cloneNode(true);
  n.querySelector(".empty-title").textContent = title;
  n.querySelector(".empty-copy").textContent = copy;
  return n;
}

function emptyRow(cols, title, copy) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = cols;
  td.appendChild(createEmptyState(title, copy));
  tr.appendChild(td);
  return tr;
}

/* ---- navigation ---- */
function switchPage(page) {
  state.page = page;
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("active", b.dataset.page === page));
  document.querySelectorAll(".page").forEach(p => p.classList.toggle("active", p.id === `page-${page}`));
  refresh();
}
document.querySelectorAll(".nav-btn").forEach(b => b.addEventListener("click", () => switchPage(b.dataset.page)));

/* ---- filters ---- */
function matchesTerm(vals, term) { return vals.some(v => String(v||"").toLowerCase().includes(term)); }

function filterEvents(items) {
  const term = state.search.trim().toLowerCase();
  const { eventsFilterType: ft, eventsFilterAction: fa, eventsFilterSeverity: fs, eventsFilterAgent: fag } = state;
  return items.filter(e => {
    if (!inScope(e.ts)) return false;
    if (ft && e.event_type !== ft) return false;
    if (fa && e.action !== fa) return false;
    if (fs && e.severity !== fs) return false;
    if (fag && e.agent_id !== fag) return false;
    if (term && !matchesTerm([e.agent_id, e.event_type, e.action, e.severity, e.comm, e.dst_ip, e.subject, e.process_path, agentName(e.agent_id)], term)) return false;
    return true;
  });
}

function filterDetections(items) {
  const term = state.search.trim().toLowerCase();
  return items.filter(i => {
    if (!inScope(i.ts)) return false;
    if (term && !matchesTerm([i.detector_name, i.severity, i.summary, i.event_type, agentName(i.agent_id)], term)) return false;
    return true;
  });
}

function filterDetectors(items) {
  const term = state.search.trim().toLowerCase();
  const { detectorsFilterSeverity: fs, detectorsFilterTag: ft } = state;
  return items.filter(d => {
    if (fs && d.severity !== fs) return false;
    if (ft && !(d.tags || []).includes(ft)) return false;
    if (term && !matchesTerm([d.id, d.name, d.description, (d.tags||[]).join(" ")], term)) return false;
    return true;
  });
}

/* ---- render: agents ---- */
function renderAgentsPage() {
  const tbody = document.querySelector("#agents-full-table tbody");
  tbody.innerHTML = "";
  const items = state.agents;
  if (!items.length) { tbody.appendChild(emptyRow(8, "No agents", "Deploy an agent to get started.")); return; }
  for (const a of items) {
    const s = deriveStatus(a);
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><strong>${esc(a.hostname || a.id.slice(0,8))}</strong></td><td class="mono subtle">${esc(a.ip)}</td><td class="mono subtle">${esc(a.kernel||"-")}</td><td class="subtle">${esc(a.version||"-")}</td><td><span class="pill ${s}">${s}</span></td><td class="subtle">${formatTs(a.first_seen)}</td><td class="subtle">${relativeTime(a.last_seen)}</td><td><button class="action-btn danger" data-remove-agent="${esc(a.id)}">Remove</button></td>`;
    tbody.appendChild(tr);
  }
}

/* ---- render: events ---- */
function renderEventsPage() {
  const items = filterEvents(state.events);
  const tbody = document.querySelector("#events-full-table tbody");
  tbody.innerHTML = "";
  setText("events-page-chip", `${formatNumber(items.length)} events`);
  if (!items.length) { tbody.appendChild(emptyRow(8, "No events match", "Adjust filters or time range.")); return; }
  const detIds = new Set(state.detections.map(d => Number(d.event_id)).filter(Boolean));
  for (const e of items.slice(0, 500)) {
    const dst = e.dst_ip ? `${e.dst_ip}:${e.dst_port||0}` : "-";
    const subj = e.subject || "-";
    const proc = e.process_path || e.comm || "-";
    const tr = document.createElement("tr");
    if (actClass(e.action) === "block") tr.classList.add("blocked-row");
    if (detIds.has(e.id)) tr.classList.add("detection-linked");
    tr.innerHTML = `<td class="subtle">${formatTs(e.ts)}</td><td>${esc(agentName(e.agent_id))}</td><td><span class="mono">${esc(e.event_type)}</span></td><td class="mono subtle">${esc(proc)} <span class="subtle">(${e.pid||0})</span></td><td class="mono subtle">${esc(subj)}</td><td class="mono subtle">${esc(dst)}</td><td><span class="pill ${sevClass(e.severity)}">${esc(e.severity||"info")}</span></td><td><span class="pill ${actClass(e.action)}">${esc(e.action||"observe")}</span></td>`;
    tbody.appendChild(tr);
  }
}

/* ---- render: detections ---- */
function renderDetections() {
  const items = filterDetections(state.detections);
  const tbody = document.querySelector("#detections-table tbody");
  tbody.innerHTML = "";
  if (!items.length) { tbody.appendChild(emptyRow(6, "No detections", "Trigger activity or adjust filters.")); }
  for (const h of items) {
    const tr = document.createElement("tr");
    tr.dataset.detectionId = String(h.id);
    tr.innerHTML = `<td class="subtle">${formatTs(h.ts)}</td><td><strong>${esc(h.detector_name)}</strong></td><td><span class="pill ${sevClass(h.severity)}">${esc(h.severity)}</span></td><td>${esc(agentName(h.agent_id))}</td><td><span class="mono">${esc(h.event_type)}</span></td><td>${esc(h.summary)}</td>`;
    tbody.appendChild(tr);
  }
  const total = state.detectionsTotal;
  const start = total ? state.detectionsOffset + 1 : 0;
  const end = Math.min(state.detectionsOffset + state.detectionsPageSize, total);
  setText("detections-page-info", `${formatNumber(start)}–${formatNumber(end)} of ${formatNumber(total)}`);
  document.getElementById("detections-prev").disabled = state.detectionsOffset <= 0;
  document.getElementById("detections-next").disabled = state.detectionsOffset + state.detectionsPageSize >= total;
}

/* ---- render: policy ---- */
function policyCard(strong, detail, entry, scope, attrs) {
  const card = document.createElement("div");
  card.className = `policy-item${entry.enabled ? "" : " is-disabled"}`;
  let a = "";
  for (const [k, v] of Object.entries(attrs)) a += ` data-${k}="${esc(v)}"`;
  card.innerHTML = `<div class="policy-item-main"><strong>${esc(strong)}</strong><span>${esc(detail)}</span></div><div class="policy-actions"><button type="button" class="toggle-button ${entry.enabled?"active":""}" data-scope="${esc(scope)}" data-action="toggle"${a}>${entry.enabled?"Disable":"Enable"}</button><button type="button" data-scope="${esc(scope)}" data-action="remove"${a}>Remove</button></div>`;
  return card;
}

function renderIpv4Policy(items) {
  const r = document.getElementById("policy-list"); r.innerHTML = "";
  setText("policy-ipv4-count", items.length);
  if (!items.length) { r.appendChild(createEmptyState("No blocked IPs", "Block destination IPs via socket_connect LSM.")); return; }
  for (const e of items) r.appendChild(policyCard(e.ip, `${e.agent_id ? agentName(e.agent_id) : "Global"} · ${e.enabled?"Active":"Disabled"}`, e, "ip", { ip: e.ip, agent: e.agent_id||"" }));
}
function renderBindPolicy(items) {
  const r = document.getElementById("bind-policy-list"); r.innerHTML = "";
  setText("policy-bind-count", items.length);
  if (!items.length) { r.appendChild(createEmptyState("No blocked ports", "Block bind attempts via socket_bind LSM.")); return; }
  for (const e of items) r.appendChild(policyCard(`tcp/${e.port}`, `${e.agent_id ? agentName(e.agent_id) : "Global"} · ${e.enabled?"Active":"Disabled"}`, e, "bind", { port: e.port, agent: e.agent_id||"" }));
}
function renderExecPolicy(items) {
  const r = document.getElementById("exec-policy-list"); r.innerHTML = "";
  setText("policy-exec-count", items.length);
  if (!items.length) { r.appendChild(createEmptyState("No denied paths", "Block execution via bprm_check_security LSM.")); return; }
  for (const e of items) r.appendChild(policyCard(e.path, `${e.agent_id ? agentName(e.agent_id) : "Global"} · ${e.enabled?"Active":"Disabled"}`, e, "exec", { path: e.path, agent: e.agent_id||"" }));
}
function renderWritePolicy(items) {
  const r = document.getElementById("write-policy-list"); r.innerHTML = "";
  setText("policy-write-count", items.length);
  if (!items.length) { r.appendChild(createEmptyState("No protected targets", "Deny writes via file_permission LSM.")); return; }
  for (const e of items) r.appendChild(policyCard(e.target, `${e.agent_id ? agentName(e.agent_id) : "Global"} · ${e.enabled?"Active":"Disabled"}`, e, "write", { target: e.target, agent: e.agent_id||"" }));
}
function renderPtracePolicy(items) {
  const r = document.getElementById("ptrace-policy-list"); r.innerHTML = "";
  setText("policy-ptrace-count", items.length);
  if (!items.length) { r.appendChild(createEmptyState("Ptrace allowed", "Enable to block process tracing.")); return; }
  for (const e of items) r.appendChild(policyCard(e.agent_id ? agentName(e.agent_id) : "Global", `${e.enabled?"Active":"Disabled"}`, e, "ptrace", { agent: e.agent_id||"" }));
}

/* ---- render: detectors ---- */
function renderDetectorsPage() {
  const items = filterDetectors(state.detectors);
  const root = document.getElementById("detector-list-page");
  root.innerHTML = "";
  setText("catalog-chip-page", `${items.length} loaded`);
  if (!items.length) { root.appendChild(createEmptyState("No detectors match", "Adjust filters or add TOML files.")); return; }
  for (const d of items) {
    const card = document.createElement("div");
    card.className = "detector-item";
    card.innerHTML = `<div class="detector-item-top"><strong>${esc(d.name)}</strong><span class="pill ${sevClass(d.severity)}">${esc(d.severity)}</span></div><p>${esc(d.description)}</p><div class="detector-item-meta"><span class="mono">${esc(d.id)}</span><span>${formatNumber(d.hit_count)} hits</span></div><div class="detector-tags">${(d.tags||[]).map(t=>`<span class="mini-tag">${esc(t)}</span>`).join("")}</div>`;
    root.appendChild(card);
  }
  // Populate tag filter
  const tagSel = document.getElementById("detectors-filter-tag");
  const allTags = [...new Set(state.detectors.flatMap(d => d.tags || []))].sort();
  const curVal = tagSel.value;
  tagSel.innerHTML = `<option value="">All Tags</option>` + allTags.map(t => `<option value="${esc(t)}"${t===curVal?" selected":""}>${esc(t)}</option>`).join("");
}

/* ---- render: severity chart ---- */
function renderSeverity(items) {
  const root = document.getElementById("severity-chart"); root.innerHTML = "";
  const counts = { critical: 0, warning: 0, info: 0 };
  for (const e of items) counts[sevClass(e.severity)] += 1;
  for (const [key, label, desc, color] of [["critical","Critical","Blocked / high-risk","var(--critical)"],["warning","Warning","Suspicious activity","var(--warning)"],["info","Info","Observed telemetry","var(--info)"]]) {
    const el = document.createElement("div"); el.className = "legend-row";
    el.innerHTML = `<span class="legend-dot" style="background:${color}"></span><div class="legend-label"><strong>${label}</strong><span>${desc}</span></div><span class="legend-value">${formatNumber(counts[key])}</span>`;
    root.appendChild(el);
  }
}

/* ---- render: top detectors ---- */
function renderTopDetectors() {
  const root = document.getElementById("top-detectors-chart"); root.innerHTML = "";
  if (!state.detectors.length) { root.appendChild(createEmptyState("No data", "Load detectors first.")); return; }
  const ranked = [...state.detectors].sort((a,b) => (b.hit_count||0) - (a.hit_count||0)).slice(0, 3);
  const max = Math.max(1, ...ranked.map(i => i.hit_count||0));
  for (const item of ranked) {
    const row = document.createElement("div"); row.className = "rank-item";
    row.innerHTML = `<div class="rank-item-head"><div><strong>${esc(item.name)}</strong><span class="mono">${esc(item.id)}</span></div><span class="legend-value">${formatNumber(item.hit_count)}</span></div><div class="rank-item-bar"><div class="rank-item-bar-fill" style="width:${Math.max(8, Math.round((item.hit_count||0)/max*100))}%"></div></div>`;
    root.appendChild(row);
  }
}

/* ---- render: summary ---- */
function renderSummary() {
  const agents = state.agents;
  const events = filterEvents(state.events);
  const online = agents.filter(a => deriveStatus(a) === "online").length;
  const blocked = events.filter(e => actClass(e.action) === "block").length;
  setText("agents-count", formatNumber(online));
  setText("events-count", formatNumber(state.summary?.total_events || 0));
  setText("blocked-count", formatNumber(blocked));
  setText("detections-count", formatNumber(state.summary?.total_detections || 0));
  setText("agents-meta", `${agents.length} total · ${agents.length - online} offline`);
  setText("events-meta", `${formatNumber(state.summary?.total_events||0)} stored`);
  setText("blocked-meta", blocked ? `${blocked} in view` : "None in view");
  setText("detections-meta", `${state.detectors.length} detectors`);
  setText("detector-chip", `${formatNumber(state.detectionsTotal)} total`);
  setText("agents-fleet-chip", `${agents.length} agents`);
  setText("topbar-events", `${formatNumber(events.length)} events`);
  setText("topbar-agents", `${agents.length} agents`);
}

/* ---- render: detection drawer ---- */
function openDetectionDrawer(id) { state.selectedDetectionId = id; renderDetectionDrawer(); }
function closeDetectionDrawer() { state.selectedDetectionId = null; renderDetectionDrawer(); }

function renderDetectionDrawer() {
  const backdrop = document.getElementById("detection-backdrop");
  const drawer = document.getElementById("detection-drawer");
  const title = document.getElementById("drawer-title");
  const body = document.getElementById("drawer-body");
  const hit = state.detections.find(i => String(i.id) === String(state.selectedDetectionId));
  if (!hit) { backdrop.classList.add("hidden"); drawer.classList.add("hidden"); return; }
  const src = state.events.find(i => Number(i.id) === Number(hit.event_id));
  const dst = src?.dst_ip ? `${src.dst_ip}:${src.dst_port||0}` : "-";
  backdrop.classList.remove("hidden"); drawer.classList.remove("hidden");
  title.textContent = hit.detector_name;
  const dr = (l,v) => `<div class="drawer-row"><span class="drawer-row-label">${l}</span><span class="drawer-row-value">${esc(v)}</span></div>`;
  body.innerHTML = `
    <section class="drawer-card"><span class="pill ${sevClass(hit.severity)}">${esc(hit.severity)}</span> <span class="pill ${actClass(hit.action)}">${esc(hit.action)}</span><p class="drawer-summary">${esc(hit.summary)}</p></section>
    <section class="drawer-card-grid"><article class="drawer-card"><strong>Time</strong><code>${formatTs(hit.ts)}</code></article><article class="drawer-card"><strong>Event ID</strong><code>${esc(hit.event_id||"-")}</code></article></section>
    <section class="drawer-card"><strong>Details</strong><div class="drawer-list">${dr("Agent", agentName(hit.agent_id))}${dr("Detector", hit.detector_id)}${dr("Type", hit.event_type)}${dr("Subject", src?.subject||hit.subject||"-")}${dr("Process", `${src?.process_path||src?.comm||"-"} (${src?.pid||0})`)}${dr("UID", src?.uid||0)}${dr("Ancestry", src?.ancestry||"-")}${dr("Destination", dst)}</div></section>`;
}

/* ---- render: performance ---- */
function renderPerformancePage() {
  const container = document.getElementById("perf-agent-cards");
  if (!container) return;
  const agents = state.agents;
  const metricByAgent = Object.fromEntries(state.agentMetrics.map(m => [m.agent_id, m]));
  if (!agents.length) { container.innerHTML = `<div class="empty-state"><p class="empty-title">No agents</p><p class="empty-copy">Connect an agent to see metrics.</p></div>`; return; }
  container.innerHTML = agents.map(a => {
    const m = metricByAgent[a.id] || {};
    const cpu = (m.cpu_percent||0).toFixed(2);
    const rss = (m.rss_mb||0).toFixed(1);
    const uptime = m.uptime_secs ? `${Math.floor(m.uptime_secs/3600)}h ${Math.floor((m.uptime_secs%3600)/60)}m` : "-";
    const hist = a._metricsHistory || [];
    const cpuVals = hist.slice(-30).map(h => h.cpu_percent||0);
    const rssVals = hist.slice(-30).map(h => h.rss_mb||0);
    return `<div class="perf-agent-card"><div class="perf-card-header"><div><h3>${esc(a.hostname)}</h3><p class="perf-agent-ip">${esc(a.ip)} · ${esc(a.kernel)}</p></div><span class="perf-agent-status ${deriveStatus(a)}">${deriveStatus(a)}</span></div><div class="perf-metrics-row"><div class="perf-metric-box"><p class="perf-metric-label">CPU</p><p class="perf-metric-value">${cpu}%</p><div class="sparkline-wrap">${sparkline(cpuVals, 180, 24)}</div></div><div class="perf-metric-box"><p class="perf-metric-label">RSS</p><p class="perf-metric-value">${rss} MB</p><div class="sparkline-wrap">${sparkline(rssVals, 180, 24)}</div></div><div class="perf-metric-box"><p class="perf-metric-label">Uptime</p><p class="perf-metric-value">${uptime}</p><div class="sparkline-wrap muted">${hist.length} pts</div></div></div></div>`;
  }).join("");
}

function sparkline(vals, w, h) {
  if (!vals.length) return `<svg class="sparkline" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"></svg>`;
  const max = Math.max(...vals, 0.01), min = Math.min(...vals, 0), range = max - min || 1;
  const step = w / (vals.length - 1 || 1);
  const pts = vals.map((v, i) => `${(i*step).toFixed(1)},${(h - ((v-min)/range)*h).toFixed(1)}`);
  return `<svg class="sparkline" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" preserveAspectRatio="none"><polyline points="${pts.join(" ")}" fill="none" stroke="var(--primary)" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>`;
}

/* ---- render: benchmarks ---- */
function renderBenchmarksPage() {
  const b = state.benchmarks, container = document.getElementById("benchmark-content");
  if (!container || !b) return;
  const s = b.summary, l = b.latency, t = b.throughput, a = b.accuracy, r = b.resource_efficiency, ds = b.detector_stats || [];
  container.innerHTML = `
    <section class="kpi-grid">
      <article class="kpi-card"><div><p class="kpi-label">Detection Rate</p><p class="kpi-value">${s.detection_rate_pct}%</p><p class="kpi-meta">${s.total_detections} / ${formatNumber(s.total_events)} events</p></div><div class="kpi-icon info"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg></div></article>
      <article class="kpi-card"><div><p class="kpi-label">Precision</p><p class="kpi-value">${a.precision_pct}%</p><p class="kpi-meta">F1: ${a.f1_score}%</p></div><div class="kpi-icon success"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="m9 11 3 3L22 4"/></svg></div></article>
      <article class="kpi-card"><div><p class="kpi-label">Recall</p><p class="kpi-value">${a.recall_pct}%</p><p class="kpi-meta">${a.false_negatives_est} FN / ${a.false_positives_est} FP</p></div><div class="kpi-icon warning"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"><path d="M12 3 2 21h20L12 3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg></div></article>
      <article class="kpi-card"><div><p class="kpi-label">Hook Latency</p><p class="kpi-value">${l.hook_mean_us} µs</p><p class="kpi-meta">p99: ${l.hook_p99_us} µs</p></div><div class="kpi-icon primary"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/></svg></div></article>
    </section>
    <section class="insight-grid">
      <section class="panel"><div class="panel-header"><div><p class="eyebrow">Timing</p><h2>Pipeline Latency</h2></div></div><div style="padding:12px 16px"><div class="bench-latency-grid"><div class="bench-latency-item"><span class="bench-latency-label">Hook (mean)</span><span class="bench-latency-value">${l.hook_mean_us} µs</span></div><div class="bench-latency-item"><span class="bench-latency-label">Hook (p99)</span><span class="bench-latency-value">${l.hook_p99_us} µs</span></div><div class="bench-latency-item"><span class="bench-latency-label">Pipeline (mean)</span><span class="bench-latency-value">${l.pipeline_mean_us} µs</span></div><div class="bench-latency-item"><span class="bench-latency-label">Pipeline (p99)</span><span class="bench-latency-value">${l.pipeline_p99_us} µs</span></div><div class="bench-latency-item"><span class="bench-latency-label">Ringbuffer Flush</span><span class="bench-latency-value">${l.ringbuffer_flush_us} µs</span></div></div><p class="bench-note">${esc(l.note)}</p></div></section>
      <section class="panel"><div class="panel-header"><div><p class="eyebrow">Volume</p><h2>Throughput</h2></div></div><div style="padding:12px 16px"><div class="bench-latency-grid"><div class="bench-latency-item"><span class="bench-latency-label">Peak Events/sec</span><span class="bench-latency-value">${formatNumber(t.events_per_sec_peak)}</span></div><div class="bench-latency-item"><span class="bench-latency-label">Sustained</span><span class="bench-latency-value">${formatNumber(t.events_per_sec_sustained)}</span></div><div class="bench-latency-item"><span class="bench-latency-label">Detections/sec</span><span class="bench-latency-value">${formatNumber(t.detections_per_sec)}</span></div><div class="bench-latency-item"><span class="bench-latency-label">Ring Loss</span><span class="bench-latency-value">${t.ringbuffer_loss_events}</span></div></div><p class="bench-note">${esc(t.note)}</p></div></section>
    </section>
    <section class="panel" style="margin-top:14px"><div class="panel-header"><div><p class="eyebrow">Accuracy</p><h2>Classification</h2></div></div><div style="padding:12px 16px"><div class="bench-accuracy-grid"><div class="bench-acc-box"><p class="bench-acc-label">TP</p><p class="bench-acc-value good">${a.true_positives}</p></div><div class="bench-acc-box"><p class="bench-acc-label">FP (est)</p><p class="bench-acc-value warn">${a.false_positives_est}</p></div><div class="bench-acc-box"><p class="bench-acc-label">FN (est)</p><p class="bench-acc-value warn">${a.false_negatives_est}</p></div></div><p class="bench-note">${esc(a.note)}</p></div></section>
    <section class="insight-grid" style="margin-top:14px">
      <section class="panel"><div class="panel-header"><div><p class="eyebrow">Resources</p><h2>Efficiency</h2></div></div><div style="padding:12px 16px"><div class="bench-latency-grid"><div class="bench-latency-item"><span class="bench-latency-label">CPU/1K events</span><span class="bench-latency-value">${r.cpu_per_1k_events_pct}%</span></div><div class="bench-latency-item"><span class="bench-latency-label">RSS/Agent</span><span class="bench-latency-value">${r.rss_per_agent_mb} MB</span></div><div class="bench-latency-item"><span class="bench-latency-label">Growth/Hour</span><span class="bench-latency-value">${r.rss_growth_mb_per_hour} MB</span></div><div class="bench-latency-item"><span class="bench-latency-label">Events/MB</span><span class="bench-latency-value">${formatNumber(r.events_per_mb_ram)}</span></div></div><p class="bench-note">${esc(r.note)}</p></div></section>
      <section class="panel"><div class="panel-header"><div><p class="eyebrow">Detectors</p><h2>Per-Detector Stats</h2></div></div><div style="padding:0"><table style="width:100%"><thead><tr><th>Name</th><th>Matches</th><th>Avg µs</th><th>FP%</th></tr></thead><tbody>${ds.map(d=>`<tr><td class="mono">${esc(d.name)}</td><td>${d.matches}</td><td>${d.avg_match_us}</td><td>${d.fp_rate_pct}%</td></tr>`).join("")}</tbody></table></div></section>
    </section>
    <p class="bench-generated">Generated: ${b.generated_ts}</p>`;
}

/* ---- applyState: only render active page ---- */
function applyState() {
  renderSummary();
  const p = state.page;
  if (p === "dashboard") { renderSeverity(state.detections.length ? state.detections : state.events); renderTopDetectors(); renderDetections(); }
  else if (p === "events") renderEventsPage();
  else if (p === "agents") renderAgentsPage();
  else if (p === "detectors") renderDetectorsPage();
  else if (p === "policy") { renderIpv4Policy(state.blockedIpv4); renderBindPolicy(state.blockedBindPorts); renderExecPolicy(state.blockedExecPaths); renderWritePolicy(state.protectedWriteTargets); renderPtracePolicy(state.ptraceDenies); }
  else if (p === "performance") renderPerformancePage();
  else if (p === "benchmarks") renderBenchmarksPage();
  // Update agent filter dropdown
  const agSel = document.getElementById("events-filter-agent");
  if (agSel && state.agents.length) {
    const cur = agSel.value;
    agSel.innerHTML = `<option value="">All Agents</option>` + state.agents.map(a => `<option value="${esc(a.id)}"${a.id===cur?" selected":""}>${esc(a.hostname)}</option>`).join("");
  }
}

/* ---- refresh ---- */
async function refresh() {
  const page = state.page;
  try {
    if (page === "performance") {
      const [agents, metricsRes] = await Promise.all([fetchJson("/api/v1/agents"), fetchJson("/api/v1/agent-metrics").catch(() => ({ items: [] }))]);
      state.agents = agents.items || [];
      state.agentMetrics = metricsRes.items || [];
      applyState();
      await Promise.all(state.agents.map(a => fetchJson(`/api/v1/agent-metrics?agent_id=${a.id}`).then(r => { a._metricsHistory = (r.items||[]).reverse(); }).catch(() => {})));
      applyState();
      return;
    }
    if (page === "benchmarks") {
      state.benchmarks = await fetchJson("/api/v1/benchmarks").catch(() => null);
      applyState();
      return;
    }
    const hours = state.rangeHours > 0 ? state.rangeHours : "";
    const hp = hours ? `&hours=${hours}` : "";
    const limit = hours ? "5000" : "200";
    const df = state.detectionsSeverity ? `&severity=${state.detectionsSeverity}` : "";
    const [summary, agents, events, detsRes, detectors, policy, tokenRes, metricsRes] = await Promise.all([
      fetchJson("/api/v1/metrics/summary"),
      fetchJson("/api/v1/agents"),
      fetchJson(`/api/v1/events?limit=${limit}${hp}`),
      fetchJson(`/api/v1/detections?limit=${state.detectionsPageSize}&offset=${state.detectionsOffset}${hp}${df}`),
      fetchJson("/api/v1/detectors"),
      fetchJson("/api/v1/policy"),
      fetchJson("/api/v1/agent-token").catch(() => ({ agent_token: "" })),
      fetchJson("/api/v1/agent-metrics").catch(() => ({ items: [] })),
    ]);
    state.summary = summary;
    state.agents = agents.items || [];
    state.events = events.items || [];
    state.detections = detsRes.items || [];
    state.detectionsTotal = detsRes.total || 0;
    state.detectors = detectors.items || [];
    state.agentMetrics = metricsRes.items || [];
    state.blockedIpv4 = policy.blocked_ipv4_items || [];
    state.blockedBindPorts = policy.blocked_bind_port_items || [];
    state.blockedExecPaths = policy.blocked_exec_path_items || [];
    state.protectedWriteTargets = policy.protected_write_target_items || [];
    state.ptraceDenies = policy.ptrace_deny_items || [];
    state.agentToken = tokenRes.agent_token || "";
    if (state.selectedDetectionId && !state.detections.some(i => String(i.id) === String(state.selectedDetectionId))) state.selectedDetectionId = null;
    applyState();
    buildInstallCommand();
  } catch (e) {
    document.getElementById("sidebar-status").textContent = "● Disconnected";
    document.getElementById("sidebar-status").style.color = "var(--critical)";
  }
}

/* ---- policy API ---- */
async function submitIpv4Policy(ip, enabled, agentId = "") { await fetchJson("/api/v1/policy/blocked-ipv4", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip, enabled, agent_id: agentId }) }); }
async function deleteIpv4Policy(ip, agentId = "") { await fetchJson("/api/v1/policy/blocked-ipv4", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip, agent_id: agentId }) }); }
async function submitBindPolicy(port, enabled, agentId = "") { await fetchJson("/api/v1/policy/blocked-bind-port", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ port, enabled, agent_id: agentId }) }); }
async function deleteBindPolicy(port, agentId = "") { await fetchJson("/api/v1/policy/blocked-bind-port", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ port, agent_id: agentId }) }); }
async function submitExecPolicy(path, enabled, agentId = "") { await fetchJson("/api/v1/policy/blocked-exec-path", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ path, enabled, agent_id: agentId }) }); }
async function deleteExecPolicy(path, agentId = "") { await fetchJson("/api/v1/policy/blocked-exec-path", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ path, agent_id: agentId }) }); }
async function submitWritePolicy(target, enabled, agentId = "") { await fetchJson("/api/v1/policy/protected-write-target", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target, enabled, agent_id: agentId }) }); }
async function deleteWritePolicy(target, agentId = "") { await fetchJson("/api/v1/policy/protected-write-target", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target, agent_id: agentId }) }); }
async function submitPtracePolicy(enabled, agentId = "") { await fetchJson("/api/v1/policy/deny-ptrace", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled, agent_id: agentId }) }); }
async function deletePtracePolicy(agentId = "") { await fetchJson("/api/v1/policy/deny-ptrace", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent_id: agentId }) }); }

async function registerAgent(hostname, ip, kernel, version, token) {
  return fetchJson("/api/v1/agents/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ hostname, ip, kernel, version, agent_token: token }) });
}

/* ---- install command ---- */
function buildInstallCommand() {
  const el = document.getElementById("install-command");
  if (!el) return;
  const host = window.location.hostname || "MANAGER_IP";
  const port = window.location.port || "8080";
  const url = `http://${host}:${port}`;
  el.textContent = state.agentToken
    ? `curl -sSL ${url}/install.sh | sudo bash -s -- --token ${state.agentToken} --manager-url ${url}`
    : `curl -sSL ${url}/install.sh | sudo bash -s -- --manager-url ${url}`;
}

/* ---- event listeners ---- */
document.getElementById("search-input").addEventListener("input", e => { state.search = e.target.value; applyState(); });
document.getElementById("time-range").addEventListener("change", e => { state.rangeHours = Number(e.target.value); refresh(); });

// Events page filters
document.getElementById("events-filter-type").addEventListener("change", e => { state.eventsFilterType = e.target.value; applyState(); });
document.getElementById("events-filter-action").addEventListener("change", e => { state.eventsFilterAction = e.target.value; applyState(); });
document.getElementById("events-filter-severity").addEventListener("change", e => { state.eventsFilterSeverity = e.target.value; applyState(); });
document.getElementById("events-filter-agent").addEventListener("change", e => { state.eventsFilterAgent = e.target.value; applyState(); });

// Detectors page filters
document.getElementById("detectors-filter-severity").addEventListener("change", e => { state.detectorsFilterSeverity = e.target.value; applyState(); });
document.getElementById("detectors-filter-tag").addEventListener("change", e => { state.detectorsFilterTag = e.target.value; applyState(); });

// Detections severity + pagination
document.getElementById("detections-severity-filter").addEventListener("change", e => { state.detectionsSeverity = e.target.value; state.detectionsOffset = 0; refresh(); });
document.getElementById("detections-prev").addEventListener("click", () => { state.detectionsOffset = Math.max(0, state.detectionsOffset - state.detectionsPageSize); refresh(); });
document.getElementById("detections-next").addEventListener("click", () => { if (state.detectionsOffset + state.detectionsPageSize < state.detectionsTotal) { state.detectionsOffset += state.detectionsPageSize; refresh(); } });

// Copy install command
document.getElementById("copy-install-btn").addEventListener("click", () => {
  const code = document.getElementById("install-command").textContent;
  navigator.clipboard.writeText(code).then(() => toast("Copied to clipboard", "success")).catch(() => toast("Copy failed", "error"));
});

// Policy forms
document.getElementById("policy-form").addEventListener("submit", async e => { e.preventDefault(); const ip = document.getElementById("ip-input").value.trim(); const ag = document.getElementById("ip-agent-input").value.trim(); if (!ip) return; await submitIpv4Policy(ip, true, ag); document.getElementById("ip-input").value = ""; document.getElementById("ip-agent-input").value = ""; toast(`Blocked ${ip}`, "success"); await refresh(); });
document.getElementById("bind-policy-form").addEventListener("submit", async e => { e.preventDefault(); const port = Number(document.getElementById("bind-port-input").value); const ag = document.getElementById("bind-agent-input").value.trim(); if (!port || port < 1 || port > 65535) return; await submitBindPolicy(port, true, ag); document.getElementById("bind-port-input").value = ""; document.getElementById("bind-agent-input").value = ""; toast(`Blocked port ${port}`, "success"); await refresh(); });
document.getElementById("exec-policy-form").addEventListener("submit", async e => { e.preventDefault(); const p = document.getElementById("exec-path-input").value.trim(); const ag = document.getElementById("exec-agent-input").value.trim(); if (!p) return; await submitExecPolicy(p, true, ag); document.getElementById("exec-path-input").value = ""; document.getElementById("exec-agent-input").value = ""; toast(`Blocked exec ${p}`, "success"); await refresh(); });
document.getElementById("write-policy-form").addEventListener("submit", async e => { e.preventDefault(); const t = document.getElementById("write-target-input").value.trim(); const ag = document.getElementById("write-agent-input").value.trim(); if (!t) return; await submitWritePolicy(t, true, ag); document.getElementById("write-target-input").value = ""; document.getElementById("write-agent-input").value = ""; toast(`Protected ${t}`, "success"); await refresh(); });
document.getElementById("ptrace-policy-form").addEventListener("submit", async e => { e.preventDefault(); const ag = document.getElementById("ptrace-agent-input").value.trim(); await submitPtracePolicy(true, ag); document.getElementById("ptrace-agent-input").value = ""; toast("Ptrace deny enabled", "success"); await refresh(); });

// Agent register
document.getElementById("manual-register-btn").addEventListener("click", async e => {
  e.preventDefault();
  const fb = document.getElementById("reg-feedback");
  fb.textContent = ""; fb.className = "form-feedback";
  try {
    const result = await registerAgent(document.getElementById("reg-hostname").value.trim(), document.getElementById("reg-ip").value.trim(), document.getElementById("reg-kernel").value.trim(), document.getElementById("reg-version").value.trim(), state.agentToken);
    fb.textContent = `Registered: ${result.agent_id}`; fb.className = "form-feedback success";
    document.getElementById("reg-hostname").value = ""; document.getElementById("reg-ip").value = ""; document.getElementById("reg-kernel").value = ""; document.getElementById("reg-version").value = "";
    toast("Agent registered", "success"); await refresh();
  } catch (err) { fb.textContent = `Error: ${err.message}`; fb.className = "form-feedback error"; }
});

// Agent remove (table delegation)
document.querySelector("#agents-full-table tbody").addEventListener("click", async e => {
  const btn = e.target.closest("[data-remove-agent]");
  if (!btn) return;
  const id = btn.dataset.removeAgent;
  if (!confirm(`Remove agent ${agentName(id)}?`)) return;
  try { await fetchJson("/api/v1/agents", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent_id: id }) }); toast("Agent removed", "success"); await refresh(); }
  catch (err) { toast(`Error: ${err.message}`, "error"); }
});

// Agents tabs
document.querySelector(".agents-tabs").addEventListener("click", e => {
  const tab = e.target.closest(".agents-tab");
  if (!tab) return;
  const name = tab.dataset.agentsTab;
  document.querySelectorAll(".agents-tab").forEach(t => t.classList.toggle("active", t.dataset.agentsTab === name));
  document.querySelectorAll(".agents-tab-panel").forEach(p => p.classList.toggle("active", p.id === `agents-tab-${name}`));
});

// Detection drawer
document.querySelector("#detections-table tbody").addEventListener("click", e => { const row = e.target.closest("tr[data-detection-id]"); if (row) openDetectionDrawer(row.dataset.detectionId); });
document.getElementById("drawer-close").addEventListener("click", closeDetectionDrawer);
document.getElementById("detection-backdrop").addEventListener("click", closeDetectionDrawer);
window.addEventListener("keydown", e => { if (e.key === "Escape") closeDetectionDrawer(); });

// Policy list delegation
function policyClickHandler(listId, submitFn, deleteFn, keyMap) {
  document.getElementById(listId).addEventListener("click", async e => {
    const btn = e.target.closest("button[data-action]");
    if (!btn) return;
    const action = btn.dataset.action;
    const params = {};
    for (const [ds, fn] of Object.entries(keyMap)) params[fn] = btn.dataset[ds];
    if (action === "toggle") {
      const sets = { "policy-list": state.blockedIpv4, "bind-policy-list": state.blockedBindPorts, "exec-policy-list": state.blockedExecPaths, "write-policy-list": state.protectedWriteTargets, "ptrace-policy-list": state.ptraceDenies };
      const matchers = {
        "policy-list": e => e.ip === params.ip && (e.agent_id||"") === (params.agent||""),
        "bind-policy-list": e => Number(e.port) === Number(params.port) && (e.agent_id||"") === (params.agent||""),
        "exec-policy-list": e => e.path === params.path && (e.agent_id||"") === (params.agent||""),
        "write-policy-list": e => e.target === params.target && (e.agent_id||"") === (params.agent||""),
        "ptrace-policy-list": e => (e.agent_id||"") === (params.agent||""),
      };
      const cur = sets[listId].find(matchers[listId]);
      if (!cur) return;
      await submitFn(!cur.enabled, params);
      toast(cur.enabled ? "Rule disabled" : "Rule enabled", "info");
    } else if (action === "remove") {
      await deleteFn(params);
      toast("Rule removed", "success");
    }
    await refresh();
  });
}
policyClickHandler("policy-list", (en, p) => submitIpv4Policy(p.ip, en, p.agent||""), p => deleteIpv4Policy(p.ip, p.agent||""), { ip: "ip", agent: "agent" });
policyClickHandler("bind-policy-list", (en, p) => submitBindPolicy(Number(p.port), en, p.agent||""), p => deleteBindPolicy(Number(p.port), p.agent||""), { port: "port", agent: "agent" });
policyClickHandler("exec-policy-list", (en, p) => submitExecPolicy(p.path, en, p.agent||""), p => deleteExecPolicy(p.path, p.agent||""), { path: "path", agent: "agent" });
policyClickHandler("write-policy-list", (en, p) => submitWritePolicy(p.target, en, p.agent||""), p => deleteWritePolicy(p.target, p.agent||""), { target: "target", agent: "agent" });
policyClickHandler("ptrace-policy-list", (en, p) => submitPtracePolicy(en, p.agent||""), p => deletePtracePolicy(p.agent||""), { agent: "agent" });

/* ---- init ---- */
refresh().catch(console.error);
setInterval(() => refresh().catch(console.error), 5000);
