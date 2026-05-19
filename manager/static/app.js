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
};

/* ---- util ---- */

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

function esc(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function setText(id, value) { const el = document.getElementById(id); if (el) el.textContent = String(value); }

function formatNumber(value) { return Number(value || 0).toLocaleString(); }

function formatTs(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value || "-");
  return date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function relativeTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function deriveAgentStatus(agent) {
  const lastSeen = new Date(agent.last_seen);
  if (Number.isNaN(lastSeen.getTime())) return agent.status || "offline";
  return Date.now() - lastSeen.getTime() <= 15000 ? "online" : "offline";
}

function severityClass(value) {
  const key = String(value || "").toLowerCase();
  if (key === "critical" || key === "high") return "critical";
  if (key === "warning" || key === "medium") return "warning";
  return "info";
}

function actionClass(value) {
  const key = String(value || "").toLowerCase();
  if (key === "block") return "block";
  if (key === "allow") return "allowed";
  return "info";
}

function createEmptyState(title, copy) {
  const template = document.getElementById("empty-state-template");
  const node = template.content.firstElementChild.cloneNode(true);
  node.querySelector(".empty-title").textContent = title;
  node.querySelector(".empty-copy").textContent = copy;
  return node;
}

function inScope(ts) {
  if (!state.rangeHours) return true;
  const parsed = new Date(ts).getTime();
  if (Number.isNaN(parsed)) return true;
  return parsed >= Date.now() - state.rangeHours * 60 * 60 * 1000;
}

/* ---- navigation ---- */

function switchPage(page) {
  state.page = page;
  document.querySelectorAll(".nav-btn").forEach(btn => btn.classList.toggle("active", btn.dataset.page === page));
  document.querySelectorAll(".page").forEach(p => p.classList.toggle("active", p.id === `page-${page}`));
}

document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => switchPage(btn.dataset.page));
});

/* ---- filters ---- */

function matchesTerm(values, term) {
  return values.some(v => String(v || "").toLowerCase().includes(term));
}

function filterAgents(items) {
  const term = state.search.trim().toLowerCase();
  if (!term) return items;
  return items.filter(item => matchesTerm([item.id, item.hostname, item.ip, item.kernel, item.version], term));
}

function filterEvents(items) {
  const term = state.search.trim().toLowerCase();
  return items.filter(item => {
    if (!inScope(item.ts)) return false;
    if (!term) return true;
    return matchesTerm([item.id, item.agent_id, item.event_type, item.action, item.severity, item.comm, item.dst_ip, item.dst_port, item.subject, item.arg0, item.arg1, item.ppid, item.ancestry, item.process_path, item.pid_ns, item.mount_ns, item.net_ns], term);
  });
}

function filterDetections(items) {
  const term = state.search.trim().toLowerCase();
  return items.filter(item => {
    if (!inScope(item.ts)) return false;
    if (!term) return true;
    return matchesTerm([item.id, item.detector_id, item.detector_name, item.severity, item.agent_id, item.event_type, item.summary, item.subject, item.match_count, item.correlation_key], term);
  });
}

function filterDetectors(items) {
  const term = state.search.trim().toLowerCase();
  if (!term) return items;
  return items.filter(item => matchesTerm([item.id, item.name, item.description, (item.tags || []).join(" ")], term));
}

/* ---- render: agents page ---- */

function renderAgentsPage(items) {
  const tbody = document.querySelector("#agents-full-table tbody");
  tbody.innerHTML = "";
  if (!items.length) { tbody.appendChild(emptyRow(8, "No agents registered", "Use the Add Agent form to register a new endpoint agent.")); return; }
  for (const agent of items) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${esc(agent.hostname || agent.id)}</td><td class="mono subtle">${esc(agent.ip)}</td><td class="mono subtle">${esc(agent.kernel || "-")}</td><td class="subtle">${esc(agent.version || "-")}</td><td><span class="pill ${deriveAgentStatus(agent)}">${esc(deriveAgentStatus(agent))}</span></td><td class="subtle">${esc(formatTs(agent.first_seen))}</td><td class="subtle">${esc(relativeTime(agent.last_seen))}</td><td><button class="action-btn danger" data-remove-agent="${esc(agent.id)}">Remove</button></td>`;
    tbody.appendChild(tr);
  }
}

/* ---- render: events page ---- */

function renderEventsPage(items, detectionEventIds) {
  const tbody = document.querySelector("#events-full-table tbody");
  tbody.innerHTML = "";
  if (!items.length) { tbody.appendChild(emptyRow(8, "No events in scope", "Adjust time range or search filter.")); return; }
  for (const evt of items.slice(0, 500)) {
    const dst = evt.dst_ip ? `${evt.dst_ip}:${evt.dst_port || 0}` : "-";
    const subject = evt.subject || (evt.event_type === "ptrace" ? `req=${evt.arg0} pid=${evt.arg1}` : "-");
    const process = evt.process_path || evt.comm || "-";
    const tr = document.createElement("tr");
    if (actionClass(evt.action) === "block") tr.classList.add("blocked-row");
    if (detectionEventIds && detectionEventIds.has(evt.id)) tr.classList.add("detection-linked");
    tr.innerHTML = `<td class="subtle">${esc(formatTs(evt.ts))}</td><td class="mono">${esc(evt.agent_id)}</td><td>${esc(evt.event_type)}</td><td class="mono subtle">${esc(process)} (${esc(evt.pid || 0)})</td><td class="mono subtle">${esc(subject)}</td><td class="mono subtle">${esc(dst)}</td><td><span class="pill ${severityClass(evt.severity)}">${esc(evt.severity || "info")}</span></td><td><span class="pill ${actionClass(evt.action)}">${esc(evt.action || "observe")}</span></td>`;
    tbody.appendChild(tr);
  }
}

/* ---- render: detections ---- */

function renderDetections(items) {
  const tbody = document.querySelector("#detections-table tbody");
  tbody.innerHTML = "";
  if (!items.length) { tbody.appendChild(emptyRow(6, "No detectors fired", "Trigger activity on an agent or load more detector definitions.")); }

  for (const hit of items) {
    const tr = document.createElement("tr");
    tr.dataset.detectionId = String(hit.id);
    tr.innerHTML = `<td class="subtle">${esc(formatTs(hit.ts))}</td><td><div class="stacked-cell"><strong>${esc(hit.detector_name)}</strong><span class="subtle mono">${esc(hit.detector_id)}</span></div></td><td><span class="pill ${severityClass(hit.severity)}">${esc(hit.severity)}</span></td><td class="mono">${esc(hit.agent_id)}</td><td><div class="stacked-cell"><span>${esc(hit.event_type)}</span><span class="subtle">${esc(hit.action)}</span></div></td><td><div class="stacked-cell"><strong>${esc(hit.summary)}</strong><span class="subtle">${actionClass(hit.action) === "block" ? "Enforced" : "Observed"}</span></div></td>`;
    tbody.appendChild(tr);
  }

  // Pagination controls
  const total = state.detectionsTotal;
  const start = total ? state.detectionsOffset + 1 : 0;
  const end = Math.min(state.detectionsOffset + state.detectionsPageSize, total);
  setText("detections-page-info", `${formatNumber(start)}\u2013${formatNumber(end)} of ${formatNumber(total)}`);
  document.getElementById("detections-prev").disabled = state.detectionsOffset <= 0;
  document.getElementById("detections-next").disabled = state.detectionsOffset + state.detectionsPageSize >= total;
}

/* ---- render: policy ---- */

function policyCard(strong, detail, entry, scope, dataAttrs) {
  const card = document.createElement("div");
  card.className = `policy-item${entry.enabled ? "" : " is-disabled"}`;
  let attrStr = "";
  for (const [k, v] of Object.entries(dataAttrs)) attrStr += ` data-${k}="${esc(v)}"`;
  card.innerHTML = `<div class="policy-item-main"><strong>${esc(strong)}</strong><span>${esc(detail)}</span></div><div class="policy-actions"><button type="button" class="toggle-button ${entry.enabled ? "active" : ""}" data-scope="${esc(scope)}" data-action="toggle"${attrStr}>${entry.enabled ? "Disable" : "Enable"}</button><button type="button" data-scope="${esc(scope)}" data-action="remove"${attrStr}>Remove</button></div>`;
  return card;
}

function renderIpv4Policy(items) {
  const root = document.getElementById("policy-list");
  root.innerHTML = "";
  if (!items.length) { root.appendChild(createEmptyState("No blocked IPs", "Add destination IPs to block via socket_connect LSM hook.")); return; }
  for (const e of items) root.appendChild(policyCard(e.ip, `${e.agent_id ? "Scoped: "+e.agent_id : "Global"} • ${e.enabled?"Enabled":"Disabled"}`, e, "ip", { ip: e.ip, agent: e.agent_id || "" }));
}

function renderBindPolicy(items) {
  const root = document.getElementById("bind-policy-list");
  root.innerHTML = "";
  if (!items.length) { root.appendChild(createEmptyState("No blocked ports", "Block local bind attempts via socket_bind LSM hook.")); return; }
  for (const e of items) root.appendChild(policyCard(`tcp/${e.port}`, `${e.agent_id ? "Scoped: "+e.agent_id : "Global"} • ${e.enabled?"Enabled":"Disabled"}`, e, "bind", { port: e.port, agent: e.agent_id || "" }));
}

function renderExecPolicy(items) {
  const root = document.getElementById("exec-policy-list");
  root.innerHTML = "";
  if (!items.length) { root.appendChild(createEmptyState("No denied exec paths", "Block execution via bprm_check_security LSM hook.")); return; }
  for (const e of items) root.appendChild(policyCard(e.path, `${e.agent_id ? "Scoped: "+e.agent_id : "Global"} • ${e.enabled?"Enabled":"Disabled"}`, e, "exec", { path: e.path, agent: e.agent_id || "" }));
}

function renderWritePolicy(items) {
  const root = document.getElementById("write-policy-list");
  root.innerHTML = "";
  if (!items.length) { root.appendChild(createEmptyState("No protected targets", "Deny writes via file_permission LSM hook.")); return; }
  for (const e of items) root.appendChild(policyCard(e.target, `${e.agent_id ? "Scoped: "+e.agent_id : "Global"} • ${e.enabled?"Enabled":"Disabled"}`, e, "write", { target: e.target, agent: e.agent_id || "" }));
}

function renderPtracePolicy(items) {
  const root = document.getElementById("ptrace-policy-list");
  root.innerHTML = "";
  if (!items.length) { root.appendChild(createEmptyState("Ptrace deny is off", "Enable to block process tracing via ptrace_access_check LSM.")); return; }
  for (const e of items) root.appendChild(policyCard(e.agent_id || "Global", `${e.agent_id ? "Scoped: "+e.agent_id : "Global"} • ${e.enabled?"Enabled":"Disabled"}`, e, "ptrace", { agent: e.agent_id || "" }));
}

/* ---- render: detectors page ---- */

function renderDetectorsPage(items) {
  const root = document.getElementById("detector-list-page");
  root.innerHTML = "";
  if (!items.length) { root.appendChild(createEmptyState("No detectors loaded", "Add TOML files under manager/detectors/ — they auto-load.")); return; }
  for (const d of items) {
    const card = document.createElement("div");
    card.className = "detector-item";
    card.innerHTML = `<div class="detector-item-top"><strong>${esc(d.name)}</strong><span class="pill ${severityClass(d.severity)}">${esc(d.severity)}</span></div><p>${esc(d.description)}</p><div class="detector-item-meta"><span class="mono">${esc(d.id)}</span><span>${formatNumber(d.hit_count)} hits${d.threshold_count > 1 ? ` • ${esc(d.threshold_count)}/${esc(d.threshold_window_secs)}s` : ""}</span></div><div class="detector-tags">${(d.tags || []).map(t => `<span class="mini-tag">${esc(t)}</span>`).join("")}</div>`;
    root.appendChild(card);
  }
}

/* ---- render: severity ---- */

function renderSeverity(items) {
  const root = document.getElementById("severity-chart");
  root.innerHTML = "";
  const counts = { critical: 0, warning: 0, info: 0 };
  for (const evt of items) counts[severityClass(evt.severity)] += 1;
  for (const [key, label, copy, color] of [
    ["critical", "Critical", "Blocked actions and high-risk", "var(--critical)"],
    ["warning", "Warning", "Suspicious activity worth review", "var(--warning)"],
    ["info", "Info", "Observed telemetry", "var(--info)"],
  ]) {
    const el = document.createElement("div");
    el.className = "legend-row";
    el.innerHTML = `<span class="legend-dot" style="background:${color}"></span><div class="legend-label"><strong>${label}</strong><span>${copy}</span></div><span class="legend-value">${formatNumber(counts[key])}</span>`;
    root.appendChild(el);
  }
}

/* ---- render: top detectors ---- */

function renderTopDetectors(items) {
  const root = document.getElementById("top-detectors-chart");
  root.innerHTML = "";
  if (!items.length) { root.appendChild(createEmptyState("No statistics yet", "Load detectors and generate hits.")); return; }
  const ranked = [...items].sort((a, b) => Number(b.hit_count || 0) - Number(a.hit_count || 0)).slice(0, 3);
  const maxHits = Math.max(1, ...ranked.map(i => Number(i.hit_count || 0)));
  for (const item of ranked) {
    const row = document.createElement("div");
    row.className = "rank-item";
    row.innerHTML = `<div class="rank-item-head"><div><strong>${esc(item.name)}</strong><span class="mono">${esc(item.id)}</span></div><span class="legend-value">${formatNumber(item.hit_count)}</span></div><div class="rank-item-bar"><div class="rank-item-bar-fill" style="width:${Math.max(8, Math.round((Number(item.hit_count || 0) / maxHits) * 100))}%"></div></div>`;
    root.appendChild(row);
  }
}

/* ---- render: detection drawer ---- */

function openDetectionDrawer(id) { state.selectedDetectionId = id; renderDetectionDrawer(); }
function closeDetectionDrawer() { state.selectedDetectionId = null; renderDetectionDrawer(); }

function renderDetectionDrawer() {
  const backdrop = document.getElementById("detection-backdrop");
  const drawer = document.getElementById("detection-drawer");
  const title = document.getElementById("drawer-title");
  const body = document.getElementById("drawer-body");
  const hit = state.detections.find(item => String(item.id) === String(state.selectedDetectionId));
  if (!hit) { backdrop.classList.add("hidden"); drawer.classList.add("hidden"); drawer.setAttribute("aria-hidden", "true"); title.textContent = "No detection selected"; body.innerHTML = ""; return; }
  const sourceEvent = state.events.find(item => Number(item.id) === Number(hit.event_id));
  const destination = sourceEvent?.dst_ip ? `${sourceEvent.dst_ip}:${sourceEvent.dst_port || 0}` : "-";
  const sourceSubject = sourceEvent?.subject || hit.subject || "-";
  const process = sourceEvent?.process_path || sourceEvent?.comm || "-";
  backdrop.classList.remove("hidden"); drawer.classList.remove("hidden"); drawer.setAttribute("aria-hidden", "false");
  title.textContent = hit.detector_name;
  body.innerHTML = `
    <section class="drawer-card"><span class="pill ${severityClass(hit.severity)}">${esc(hit.severity)}</span><span class="pill ${actionClass(hit.action)}">${esc(hit.action)}</span><p class="drawer-summary">${esc(hit.summary)}</p></section>
    <section class="drawer-card-grid"><article class="drawer-card"><strong>Detection</strong><span class="drawer-muted">Timestamp</span><code>${esc(formatTs(hit.ts))}</code></article><article class="drawer-card"><strong>Source</strong><span class="drawer-muted">Event ID</span><code>${esc(hit.event_id || "-")}</code></article></section>
    <section class="drawer-card"><strong>Details</strong><div class="drawer-list">${drawerRow("Agent", hit.agent_id)}${drawerRow("Detector", hit.detector_id)}${drawerRow("Type", hit.event_type)}${drawerRow("Subject", sourceSubject)}${drawerRow("Process", `${process} (${sourceEvent?.pid || 0})`)}${drawerRow("UID", sourceEvent?.uid || 0)}${drawerRow("Ancestry", sourceEvent?.ancestry || "-")}${drawerRow("Destination", destination)}</div></section>`;
}

function drawerRow(label, value) { return `<div class="drawer-row"><span class="drawer-row-label">${label}</span><span class="drawer-row-value">${esc(value)}</span></div>`; }

function emptyRow(cols, title, copy) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = cols;
  td.appendChild(createEmptyState(title, copy));
  tr.appendChild(td);
  return tr;
}

/* ---- summary ---- */

function renderSummary() {
  const events = filterEvents(state.events);
  const agents = state.agents;
  const online = agents.filter(a => deriveAgentStatus(a) === "online").length;
  const offline = Math.max(0, agents.length - online);
  const blocked = events.filter(e => actionClass(e.action) === "block").length;
  const scopeLabel = state.rangeHours > 0 ? `${state.rangeHours}h` : "all";
  setText("agents-count", formatNumber(online));
  setText("events-count", formatNumber(state.summary?.total_events || 0));
  setText("blocked-count", formatNumber(blocked));
  setText("detections-count", formatNumber(state.summary?.total_detections || 0));
  setText("agents-meta", `${formatNumber(agents.length)} total • ${offline} offline`);
  setText("events-meta", `${scopeLabel} • ${formatNumber(state.summary?.total_events || 0)} stored`);
  setText("blocked-meta", blocked ? `${blocked} blocked` : "No blocks");
  setText("detections-meta", `${formatNumber(state.detectors.length)} detectors`);
  setText("detector-chip", `${formatNumber(state.detectionsTotal)} total`);
  setText("catalog-chip-page", `${formatNumber(state.detectors.length)} loaded`);
  setText("agents-fleet-chip", `${formatNumber(agents.length)} agents`);
  setText("events-page-chip", `${formatNumber(events.length)} events`);
  setText("topbar-events", `${formatNumber(events.length)} events`);
  setText("topbar-agents", `${formatNumber(agents.length)} agents`);
}

/* ---- apply ---- */

function applyState() {
  const agents = filterAgents(state.agents);
  const events = filterEvents(state.events);
  const detections = filterDetections(state.detections);
  const detectors = filterDetectors(state.detectors);
  const detectionEventIds = new Set(detections.map(i => Number(i.event_id)).filter(Boolean));

  renderSummary();
  renderAgentsPage(state.agents);
  renderDetections(detections);
  renderEventsPage(events, detectionEventIds);
  renderDetectorsPage(detectors);
  renderIpv4Policy(state.blockedIpv4);
  renderBindPolicy(state.blockedBindPorts);
  renderExecPolicy(state.blockedExecPaths);
  renderWritePolicy(state.protectedWriteTargets);
  renderPtracePolicy(state.ptraceDenies);
  renderSeverity(detections.length ? detections : events);
  renderTopDetectors(state.detectors);
  renderDetectionDrawer();
  if (state.page === "performance") renderPerformancePage();
  if (state.page === "benchmarks") renderBenchmarksPage();
}

/* ---- refresh ---- */

async function refresh() {
  const hours = state.rangeHours > 0 ? state.rangeHours : "";
  const hoursParam = hours ? `&hours=${hours}` : "";
  const limit = hours ? "5000" : "200";

  const detFilter = state.detectionsSeverity ? `&severity=${state.detectionsSeverity}` : "";
  const detUrl = `/api/v1/detections?limit=${state.detectionsPageSize}&offset=${state.detectionsOffset}${hoursParam}${detFilter}`;

  const [summary, agents, events, detectionsRes, detectors, policy, tokenRes, benchmarksRes, metricsRes] = await Promise.all([
    fetchJson("/api/v1/metrics/summary"),
    fetchJson("/api/v1/agents"),
    fetchJson(`/api/v1/events?limit=${limit}${hoursParam}`),
    fetchJson(detUrl),
    fetchJson("/api/v1/detectors"),
    fetchJson("/api/v1/policy"),
    fetchJson("/api/v1/agent-token").catch(() => ({ agent_token: "" })),
    fetchJson("/api/v1/benchmarks").catch(() => null),
    fetchJson("/api/v1/agent-metrics").catch(() => ({ items: [] })),
  ]);
  state.summary = summary;
  state.agents = agents.items || [];
  state.events = events.items || [];
  state.detections = detectionsRes.items || [];
  state.detectionsTotal = detectionsRes.total || 0;
  state.detectors = detectors.items || [];
  state.benchmarks = benchmarksRes;
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

  // Background: fetch per-agent history for performance sparklines
  for (const agent of state.agents) {
    fetchJson(`/api/v1/agent-metrics?agent_id=${agent.id}`).then(histRes => {
      agent._metricsHistory = (histRes.items || []).reverse();
    }).catch(() => {});
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

/* ---- agent management API ---- */

async function registerAgent(hostname, ip, kernel, version, token) {
  return await fetchJson("/api/v1/agents/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hostname, ip, kernel, version, agent_token: token }),
  });
}

/* ---- agent install wizard ---- */

function buildInstallCommand() {
  const codeEl = document.getElementById("install-command");
  if (!codeEl) return;
  const token = state.agentToken;
  const managerHost = window.location.hostname || "MANAGER_IP";
  const managerPort = window.location.port || "8080";
  const managerUrl = `http://${managerHost}:${managerPort}`;
  codeEl.textContent = token
    ? `curl -sSL ${managerUrl}/install.sh | sudo bash -s -- --token ${token} --manager-url ${managerUrl}`
    : `curl -sSL ${managerUrl}/install.sh | sudo bash -s -- --manager-url ${managerUrl}`;
}

document.getElementById("copy-install-btn").addEventListener("click", () => {
  const code = document.getElementById("install-command").textContent;
  navigator.clipboard.writeText(code).then(() => {
    const fb = document.getElementById("copy-feedback");
    fb.style.display = "inline";
    setTimeout(() => { fb.style.display = "none"; }, 2000);
  }).catch(() => {
    const textarea = document.createElement("textarea");
    textarea.value = code;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
    const fb = document.getElementById("copy-feedback");
    fb.style.display = "inline";
    setTimeout(() => { fb.style.display = "none"; }, 2000);
  });
});

/* ---- event listeners ---- */

document.getElementById("search-input").addEventListener("input", e => { state.search = e.target.value; applyState(); });
document.getElementById("time-range").addEventListener("change", e => { state.rangeHours = Number(e.target.value || 24); applyState(); });

document.getElementById("policy-form").addEventListener("submit", async e => {
  e.preventDefault();
  const ip = document.getElementById("ip-input").value.trim();
  const agentId = document.getElementById("ip-agent-input").value.trim();
  if (!ip) return;
  await submitIpv4Policy(ip, true, agentId);
  document.getElementById("ip-input").value = "";
  document.getElementById("ip-agent-input").value = "";
  await refresh();
});

document.getElementById("bind-policy-form").addEventListener("submit", async e => {
  e.preventDefault();
  const port = Number(document.getElementById("bind-port-input").value);
  const agentId = document.getElementById("bind-agent-input").value.trim();
  if (!port || port < 1 || port > 65535) return;
  await submitBindPolicy(port, true, agentId);
  document.getElementById("bind-port-input").value = "";
  document.getElementById("bind-agent-input").value = "";
  await refresh();
});

document.getElementById("exec-policy-form").addEventListener("submit", async e => {
  e.preventDefault();
  const path = document.getElementById("exec-path-input").value.trim();
  const agentId = document.getElementById("exec-agent-input").value.trim();
  if (!path) return;
  await submitExecPolicy(path, true, agentId);
  document.getElementById("exec-path-input").value = "";
  document.getElementById("exec-agent-input").value = "";
  await refresh();
});

document.getElementById("write-policy-form").addEventListener("submit", async e => {
  e.preventDefault();
  const target = document.getElementById("write-target-input").value.trim();
  const agentId = document.getElementById("write-agent-input").value.trim();
  if (!target) return;
  await submitWritePolicy(target, true, agentId);
  document.getElementById("write-target-input").value = "";
  document.getElementById("write-agent-input").value = "";
  await refresh();
});

document.getElementById("ptrace-policy-form").addEventListener("submit", async e => {
  e.preventDefault();
  const agentId = document.getElementById("ptrace-agent-input").value.trim();
  await submitPtracePolicy(true, agentId);
  document.getElementById("ptrace-agent-input").value = "";
  await refresh();
});

/* ---- agent register form ---- */

document.getElementById("manual-register-btn").addEventListener("click", async (e) => {
  e.preventDefault();
  const fb = document.getElementById("reg-feedback");
  fb.textContent = "";
  fb.className = "form-feedback";
  try {
    const result = await registerAgent(
      document.getElementById("reg-hostname").value.trim(),
      document.getElementById("reg-ip").value.trim(),
      document.getElementById("reg-kernel").value.trim(),
      document.getElementById("reg-version").value.trim(),
      state.agentToken,
    );
    fb.textContent = `Agent registered: ${result.agent_id}`;
    fb.className = "form-feedback success";
    document.getElementById("reg-hostname").value = "";
    document.getElementById("reg-ip").value = "";
    document.getElementById("reg-kernel").value = "";
    document.getElementById("reg-version").value = "";
    await refresh();
  } catch (err) {
    fb.textContent = `Error: ${err.message}`;
    fb.className = "form-feedback error";
  }
});

/* ---- agent remove form ---- */

const removeForm = document.getElementById("agent-remove-form");
if (removeForm) {
  removeForm.addEventListener("submit", async e => {
  e.preventDefault();
  const fb = document.getElementById("remove-feedback");
  fb.textContent = "";
  fb.className = "form-feedback";
  const agentId = document.getElementById("remove-agent-id").value.trim();
  if (!agentId) return;
  try {
    await fetchJson("/api/v1/agents", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent_id: agentId }) });
    fb.textContent = `Agent ${agentId} removed.`;
    fb.className = "form-feedback success";
    document.getElementById("agent-remove-form").reset();
    await refresh();
  } catch (err) {
    fb.textContent = `Error: ${err.message}`;
    fb.className = "form-feedback error";
  }
});
}

/* ---- agents table: remove button ---- */

const agentsFullTbody = document.querySelector("#agents-full-table tbody");
if (agentsFullTbody) {
  agentsFullTbody.addEventListener("click", async e => {
  const btn = e.target.closest("[data-remove-agent]");
  if (!btn) return;
  const id = btn.dataset.removeAgent;
  if (!confirm(`Remove agent ${id}?`)) return;
  try {
    await fetchJson("/api/v1/agents", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent_id: id }) });
    await refresh();
  } catch (err) { alert(`Error: ${err.message}`); }
});

}

/* ---- policy list click delegation ---- */

function policyClickHandler(listId, submitFn, deleteFn, keyMap) {
  document.getElementById(listId).addEventListener("click", async e => {
    const btn = e.target.closest("button[data-action]");
    if (!btn) return;
    const action = btn.dataset.action;
    const params = {};
    for (const [ds, fn] of Object.entries(keyMap)) params[fn] = btn.dataset[ds];
    if (action === "toggle") {
      const currentSet = { "policy-list": state.blockedIpv4, "bind-policy-list": state.blockedBindPorts, "exec-policy-list": state.blockedExecPaths, "write-policy-list": state.protectedWriteTargets, "ptrace-policy-list": state.ptraceDenies }[listId];
      const matchFn = {
        "policy-list": e => e.ip === params.ip && (e.agent_id||"") === (params.agent||""),
        "bind-policy-list": e => Number(e.port) === Number(params.port) && (e.agent_id||"") === (params.agent||""),
        "exec-policy-list": e => e.path === params.path && (e.agent_id||"") === (params.agent||""),
        "write-policy-list": e => e.target === params.target && (e.agent_id||"") === (params.agent||""),
        "ptrace-policy-list": e => (e.agent_id||"") === (params.agent||""),
      }[listId];
      const current = currentSet.find(matchFn);
      if (!current) return;
      await submitFn(!current.enabled, params);
      await refresh();
    } else if (action === "remove") {
      await deleteFn(params);
      await refresh();
    }
  });
}

policyClickHandler("policy-list", (enabled, p) => submitIpv4Policy(p.ip, enabled, p.agent || ""), (p) => deleteIpv4Policy(p.ip, p.agent || ""), { ip: "ip", agent: "agent" });
policyClickHandler("bind-policy-list", (enabled, p) => submitBindPolicy(Number(p.port), enabled, p.agent || ""), (p) => deleteBindPolicy(Number(p.port), p.agent || ""), { port: "port", agent: "agent" });
policyClickHandler("exec-policy-list", (enabled, p) => submitExecPolicy(p.path, enabled, p.agent || ""), (p) => deleteExecPolicy(p.path, p.agent || ""), { path: "path", agent: "agent" });
policyClickHandler("write-policy-list", (enabled, p) => submitWritePolicy(p.target, enabled, p.agent || ""), (p) => deleteWritePolicy(p.target, p.agent || ""), { target: "target", agent: "agent" });
policyClickHandler("ptrace-policy-list", (enabled, p) => submitPtracePolicy(enabled, p.agent || ""), (p) => deletePtracePolicy(p.agent || ""), { agent: "agent" });

/* ---- agents tabs ---- */

const agentsTabs = document.querySelector(".agents-tabs");
if (agentsTabs) {
  agentsTabs.addEventListener("click", e => {
  const tab = e.target.closest(".agents-tab");
  if (!tab) return;
  const tabName = tab.dataset.agentsTab;
  document.querySelectorAll(".agents-tab").forEach(t => t.classList.toggle("active", t.dataset.agentsTab === tabName));
  document.querySelectorAll(".agents-tab-panel").forEach(p => p.classList.toggle("active", p.id === `agents-tab-${tabName}`));
  });
}

/* ---- detection drawer ---- */

document.getElementById("detections-severity-filter").addEventListener("change", e => {
  state.detectionsSeverity = e.target.value;
  state.detectionsOffset = 0;
  refresh();
});

document.getElementById("detections-prev").addEventListener("click", () => {
  state.detectionsOffset = Math.max(0, state.detectionsOffset - state.detectionsPageSize);
  refresh();
});

document.getElementById("detections-next").addEventListener("click", () => {
  if (state.detectionsOffset + state.detectionsPageSize < state.detectionsTotal) {
    state.detectionsOffset += state.detectionsPageSize;
    refresh();
  }
});

/* ---- detection drawer ---- */

document.querySelector("#detections-table tbody").addEventListener("click", e => {
  const row = e.target.closest("tr[data-detection-id]");
  if (row) openDetectionDrawer(row.dataset.detectionId);
});
document.getElementById("drawer-close").addEventListener("click", closeDetectionDrawer);
document.getElementById("detection-backdrop").addEventListener("click", closeDetectionDrawer);
window.addEventListener("keydown", e => { if (e.key === "Escape") closeDetectionDrawer(); });

/* ---- performance page ---- */

function renderPerformancePage() {
  const container = document.getElementById("perf-agent-cards");
  if (!container) return;

  const agents = state.agents;
  const metrics = state.agentMetrics;
  const metricByAgent = Object.fromEntries(metrics.map(m => [m.agent_id, m]));

  if (!agents.length) {
    container.innerHTML = `<div class="empty-state"><p class="empty-title">No agents connected</p><p class="empty-copy">Connect an agent to see performance metrics.</p></div>`;
    return;
  }

  container.innerHTML = agents.map(agent => {
    const m = metricByAgent[agent.id] || {};
    const cpu = (m.cpu_percent || 0).toFixed(2);
    const rss = (m.rss_mb || 0).toFixed(1);
    const uptime = m.uptime_secs ? `${Math.floor(m.uptime_secs / 3600)}h ${Math.floor((m.uptime_secs % 3600) / 60)}m` : "-";
    const history = agent._metricsHistory || [];
    
    // Sparkline SVG for CPU
    const cpuValues = history.slice(-30).map(h => h.cpu_percent || 0);
    const rssValues = history.slice(-30).map(h => h.rss_mb || 0);
    
    return `
      <div class="perf-agent-card">
        <div class="perf-card-header">
          <div>
            <h3>${esc(agent.hostname)}</h3>
            <p class="perf-agent-ip">${esc(agent.ip)} · kernel ${esc(agent.kernel)}</p>
          </div>
          <span class="perf-agent-status ${agent.status === 'online' ? 'online' : 'offline'}">${esc(agent.status)}</span>
        </div>
        
        <div class="perf-metrics-row">
          <div class="perf-metric-box">
            <p class="perf-metric-label">CPU</p>
            <p class="perf-metric-value">${cpu}%</p>
            <div class="sparkline-wrap">${renderSparkline(cpuValues, cpuValues.map(v => v > 1 ? 'var(--critical)' : v > 0.1 ? 'var(--warning)' : 'var(--success)'), 200, 28)}</div>
          </div>
          <div class="perf-metric-box">
            <p class="perf-metric-label">RAM (RSS)</p>
            <p class="perf-metric-value">${rss} MB</p>
            <div class="sparkline-wrap">${renderSparkline(rssValues, Array(rssValues.length).fill('var(--info)'), 200, 28)}</div>
          </div>
          <div class="perf-metric-box">
            <p class="perf-metric-label">Uptime</p>
            <p class="perf-metric-value">${uptime}</p>
            <div class="sparkline-wrap muted">${history.length} data points</div>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

function renderSparkline(values, colors, width, height) {
  if (!values.length) return `<svg class="sparkline" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}"></svg>`;
  
  const max = Math.max(...values, 0.01);
  const min = Math.min(...values, 0);
  const range = max - min || 1;
  const step = width / (values.length - 1 || 1);
  
  const points = values.map((v, i) => `${(i * step).toFixed(1)},${(height - ((v - min) / range) * height).toFixed(1)}`);
  
  return `<svg class="sparkline" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" preserveAspectRatio="none">
    <polyline points="${points.join(" ")}" fill="none" stroke="${colors[0] || 'var(--info)'}" stroke-width="1.5" vector-effect="non-scaling-stroke"/>
  </svg>`;
}

/* ---- benchmarks page ---- */

function renderBenchmarksPage() {
  const b = state.benchmarks;
  const container = document.getElementById("benchmark-content");
  if (!container || !b) return;

  const s = b.summary;
  const l = b.latency;
  const t = b.throughput;
  const a = b.accuracy;
  const r = b.resource_efficiency;
  const ds = b.detector_stats || [];

  container.innerHTML = `
    <section class="kpi-grid">
      <article class="kpi-card">
        <div><p class="kpi-label">Detection Rate</p><p class="kpi-value">${s.detection_rate_pct}%</p><p class="kpi-meta">${s.total_detections} hits / ${formatNumber(s.total_events)} events</p></div>
        <div class="kpi-icon info"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg></div>
      </article>
      <article class="kpi-card">
        <div><p class="kpi-label">Precision</p><p class="kpi-value">${a.precision_pct}%</p><p class="kpi-meta">F1 Score: ${a.f1_score}%</p></div>
        <div class="kpi-icon success"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="m9 11 3 3L22 4"/></svg></div>
      </article>
      <article class="kpi-card">
        <div><p class="kpi-label">Recall</p><p class="kpi-value">${a.recall_pct}%</p><p class="kpi-meta">Est. ${a.false_negatives_est} FN / ${a.false_positives_est} FP</p></div>
        <div class="kpi-icon warning"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 2 21h20L12 3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg></div>
      </article>
      <article class="kpi-card">
        <div><p class="kpi-label">eBPF Hook Latency</p><p class="kpi-value">${l.hook_mean_us} &mu;s</p><p class="kpi-meta">p99: ${l.hook_p99_us} &mu;s</p></div>
        <div class="kpi-icon primary"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/></svg></div>
      </article>
    </section>

    <section class="insight-grid">
      <section class="panel">
        <div class="panel-header"><div><p class="eyebrow">Timing</p><h2>Processing Pipeline Latency</h2></div></div>
        <div class="bench-latency-grid">
          <div class="bench-latency-item"><span class="bench-latency-label">eBPF Hook (mean)</span><span class="bench-latency-value">${l.hook_mean_us} &mu;s</span></div>
          <div class="bench-latency-item"><span class="bench-latency-label">eBPF Hook (p99)</span><span class="bench-latency-value">${l.hook_p99_us} &mu;s</span></div>
          <div class="bench-latency-item"><span class="bench-latency-label">Pipeline (mean)</span><span class="bench-latency-value">${l.pipeline_mean_us} &mu;s</span></div>
          <div class="bench-latency-item"><span class="bench-latency-label">Pipeline (p99)</span><span class="bench-latency-value">${l.pipeline_p99_us} &mu;s</span></div>
          <div class="bench-latency-item"><span class="bench-latency-label">Ringbuffer Flush</span><span class="bench-latency-value">${l.ringbuffer_flush_us} &mu;s</span></div>
        </div>
        <p class="bench-note">${esc(l.note)}</p>
      </section>

      <section class="panel">
        <div class="panel-header"><div><p class="eyebrow">Volume</p><h2>Throughput</h2></div></div>
        <div class="bench-latency-grid">
          <div class="bench-latency-item"><span class="bench-latency-label">Peak Events/sec</span><span class="bench-latency-value">${formatNumber(t.events_per_sec_peak)}</span></div>
          <div class="bench-latency-item"><span class="bench-latency-label">Sustained Events/sec</span><span class="bench-latency-value">${formatNumber(t.events_per_sec_sustained)}</span></div>
          <div class="bench-latency-item"><span class="bench-latency-label">Detections/sec</span><span class="bench-latency-value">${formatNumber(t.detections_per_sec)}</span></div>
          <div class="bench-latency-item"><span class="bench-latency-label">Ringbuffer Loss</span><span class="bench-latency-value">${t.ringbuffer_loss_events}</span></div>
        </div>
        <p class="bench-note">${esc(t.note)}</p>
      </section>
    </section>

    <section class="panel" style="margin-top:20px">
      <div class="panel-header"><div><p class="eyebrow">Detectors</p><h2>Per-Detector Accuracy</h2></div><span class="panel-chip">${ds.length} detectors</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Detector</th><th>Matches</th><th>Avg Match Time</th><th>FP Rate</th></tr></thead>
        <tbody>${ds.map(d => `<tr><td><code>${esc(d.name)}</code></td><td>${d.matches}</td><td>${d.avg_match_us} &mu;s</td><td>${d.fp_rate_pct}%</td></tr>`).join("")}</tbody>
      </table></div>
    </section>

    <section class="insight-grid" style="margin-top:20px">
      <section class="panel">
        <div class="panel-header"><div><p class="eyebrow">Classification</p><h2>Accuracy Breakdown</h2></div></div>
        <div class="bench-accuracy-grid">
          <div class="bench-acc-box"><p class="bench-acc-label">True Positives</p><p class="bench-acc-value good">${a.true_positives}</p></div>
          <div class="bench-acc-box"><p class="bench-acc-label">False Positives (est.)</p><p class="bench-acc-value warn">${a.false_positives_est}</p></div>
          <div class="bench-acc-box"><p class="bench-acc-label">False Negatives (est.)</p><p class="bench-acc-value warn">${a.false_negatives_est}</p></div>
        </div>
        <p class="bench-note">${esc(a.note)}</p>
      </section>

      <section class="panel">
        <div class="panel-header"><div><p class="eyebrow">Resources</p><h2>Resource Efficiency</h2></div></div>
        <div class="bench-latency-grid">
          <div class="bench-latency-item"><span class="bench-latency-label">CPU per 1K events</span><span class="bench-latency-value">${r.cpu_per_1k_events_pct}%</span></div>
          <div class="bench-latency-item"><span class="bench-latency-label">RSS per Agent</span><span class="bench-latency-value">${r.rss_per_agent_mb} MB</span></div>
          <div class="bench-latency-item"><span class="bench-latency-label">RSS Growth/Hour</span><span class="bench-latency-value">${r.rss_growth_mb_per_hour} MB</span></div>
          <div class="bench-latency-item"><span class="bench-latency-label">Events per MB RAM</span><span class="bench-latency-value">${formatNumber(r.events_per_mb_ram)}</span></div>
        </div>
        <p class="bench-note">${esc(r.note)}</p>
      </section>
    </section>

    <p class="bench-generated">Generated: ${b.generated_ts}</p>
  `;
}

refresh().catch(console.error);
setInterval(() => { refresh().catch(console.error); }, 4000);
