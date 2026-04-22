const state = {
  search: "",
  rangeHours: 24,
  summary: null,
  agents: [],
  events: [],
  detections: [],
  detectors: [],
  blockedIpv4: [],
  blockedBindPorts: [],
  selectedDetectionId: null,
};

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value);
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatTs(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value || "-");
  return date.toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
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
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
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

function matchesTerm(values, term) {
  return values.some((value) => String(value || "").toLowerCase().includes(term));
}

function filterAgents(items) {
  const term = state.search.trim().toLowerCase();
  if (!term) return items;
  return items.filter((item) =>
    matchesTerm([item.id, item.hostname, item.ip, item.kernel, item.version], term),
  );
}

function filterEvents(items) {
  const term = state.search.trim().toLowerCase();
  return items.filter((item) => {
    if (!inScope(item.ts)) return false;
    if (!term) return true;
    return matchesTerm(
      [
        item.id,
        item.agent_id,
        item.event_type,
        item.action,
        item.severity,
        item.comm,
        item.dst_ip,
        item.dst_port,
        item.subject,
        item.arg0,
        item.arg1,
      ],
      term,
    );
  });
}

function filterDetections(items) {
  const term = state.search.trim().toLowerCase();
  return items.filter((item) => {
    if (!inScope(item.ts)) return false;
    if (!term) return true;
    return matchesTerm(
      [
        item.id,
        item.detector_id,
        item.detector_name,
        item.severity,
        item.agent_id,
        item.event_type,
        item.summary,
        item.subject,
      ],
      term,
    );
  });
}

function filterDetectors(items) {
  const term = state.search.trim().toLowerCase();
  if (!term) return items;
  return items.filter((item) =>
    matchesTerm([item.id, item.name, item.description, (item.tags || []).join(" ")], term),
  );
}

function renderAgents(items) {
  const tbody = document.querySelector("#agents-table tbody");
  tbody.innerHTML = "";

  if (!items.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.appendChild(createEmptyState("No agents match the current filters", "Clear the search box or wait for agents to check in."));
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const agent of items) {
    const status = deriveAgentStatus(agent);
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${esc(agent.hostname || agent.id)}</td>
      <td class="mono subtle">${esc(agent.ip)}</td>
      <td class="mono subtle">${esc(agent.kernel || "-")}</td>
      <td><span class="pill ${status}">${esc(status)}</span></td>
      <td class="subtle">${esc(relativeTime(agent.last_seen))}</td>
    `;
    tbody.appendChild(tr);
  }
}

function renderEvents(items, detectionEventIds) {
  const tbody = document.querySelector("#events-table tbody");
  tbody.innerHTML = "";

  if (!items.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 8;
    td.appendChild(createEmptyState("No security events in scope", "Adjust the time range or search filter to widen the view."));
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const evt of items) {
    const action = actionClass(evt.action);
    const severity = severityClass(evt.severity);
    const dst = evt.dst_ip ? `${evt.dst_ip}:${evt.dst_port || 0}` : "-";
    const subject = evt.subject || (evt.event_type === "ptrace" ? `request=${evt.arg0} pid=${evt.arg1}` : "-");
    const tr = document.createElement("tr");
    if (action === "block") tr.classList.add("blocked-row");
    if (detectionEventIds.has(evt.id)) tr.classList.add("detection-linked");
    tr.innerHTML = `
      <td class="subtle">${esc(formatTs(evt.ts))}</td>
      <td class="mono">${esc(evt.agent_id)}</td>
      <td>${esc(evt.event_type)}</td>
      <td class="mono subtle">${esc(evt.comm || "-")} (${esc(evt.pid || 0)})</td>
      <td class="mono subtle">${esc(subject)}</td>
      <td class="mono subtle">${esc(dst)}</td>
      <td><span class="pill ${severity}">${esc(evt.severity || "info")}</span></td>
      <td><span class="pill ${action}">${esc(evt.action || "observe")}</span></td>
    `;
    tbody.appendChild(tr);
  }
}

function renderDetections(items) {
  const tbody = document.querySelector("#detections-table tbody");
  tbody.innerHTML = "";

  if (!items.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6;
    td.appendChild(createEmptyState("No detectors have fired", "Trigger sample activity on an agent or load additional detector definitions."));
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const hit of items) {
    const severity = severityClass(hit.severity);
    const action = actionClass(hit.action);
    const tr = document.createElement("tr");
    tr.dataset.detectionId = String(hit.id);
    tr.innerHTML = `
      <td class="subtle">${esc(formatTs(hit.ts))}</td>
      <td>
        <div class="stacked-cell">
          <strong>${esc(hit.detector_name)}</strong>
          <span class="subtle mono">${esc(hit.detector_id)}</span>
        </div>
      </td>
      <td><span class="pill ${severity}">${esc(hit.severity)}</span></td>
      <td class="mono">${esc(hit.agent_id)}</td>
      <td>
        <div class="stacked-cell">
          <span>${esc(hit.event_type)}</span>
          <span class="subtle">${esc(hit.action)}</span>
        </div>
      </td>
      <td>
        <div class="stacked-cell">
          <strong>${esc(hit.summary)}</strong>
          <span class="subtle">${action === "block" ? "Enforced by policy or LSM" : "Observed by detector only"}</span>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

function renderIpv4Policy(items) {
  const root = document.getElementById("policy-list");
  root.innerHTML = "";

  if (!items.length) {
    root.appendChild(createEmptyState("No blocked IPs configured", "Add a destination IP to push egress blocking down to connected agents."));
    return;
  }

  for (const entry of items) {
    const card = document.createElement("div");
    card.className = `policy-item${entry.enabled ? "" : " is-disabled"}`;
    card.innerHTML = `
      <div class="policy-item-main">
        <strong>${esc(entry.ip)}</strong>
        <span>${entry.enabled ? "Enabled" : "Disabled"} • Updated ${esc(relativeTime(entry.updated_at))}</span>
      </div>
      <div class="policy-actions">
        <button type="button" class="toggle-button ${entry.enabled ? "active" : ""}" data-scope="ip" data-action="toggle" data-ip="${esc(entry.ip)}">
          ${entry.enabled ? "Disable" : "Enable"}
        </button>
        <button type="button" data-scope="ip" data-action="remove" data-ip="${esc(entry.ip)}">Remove</button>
      </div>
    `;
    root.appendChild(card);
  }
}

function renderBindPolicy(items) {
  const root = document.getElementById("bind-policy-list");
  root.innerHTML = "";

  if (!items.length) {
    root.appendChild(createEmptyState("No blocked bind ports configured", "Add a local port to prevent listeners from binding to it via the socket_bind LSM hook."));
    return;
  }

  for (const entry of items) {
    const card = document.createElement("div");
    card.className = `policy-item${entry.enabled ? "" : " is-disabled"}`;
    card.innerHTML = `
      <div class="policy-item-main">
        <strong>tcp/${esc(entry.port)}</strong>
        <span>${entry.enabled ? "Enabled" : "Disabled"} • Updated ${esc(relativeTime(entry.updated_at))}</span>
      </div>
      <div class="policy-actions">
        <button type="button" class="toggle-button ${entry.enabled ? "active" : ""}" data-scope="bind" data-action="toggle" data-port="${esc(entry.port)}">
          ${entry.enabled ? "Disable" : "Enable"}
        </button>
        <button type="button" data-scope="bind" data-action="remove" data-port="${esc(entry.port)}">Remove</button>
      </div>
    `;
    root.appendChild(card);
  }
}

function renderDetectorCatalog(items) {
  const root = document.getElementById("detector-list");
  root.innerHTML = "";

  if (!items.length) {
    root.appendChild(createEmptyState("No detectors loaded", "Add detector TOML files under manager/detectors and restart or refresh the manager."));
    return;
  }

  for (const detector of items) {
    const severity = severityClass(detector.severity);
    const card = document.createElement("div");
    card.className = "detector-item";
    card.innerHTML = `
      <div class="detector-item-top">
        <strong>${esc(detector.name)}</strong>
        <span class="pill ${severity}">${esc(detector.severity)}</span>
      </div>
      <p>${esc(detector.description || "Custom detector")}</p>
      <div class="detector-item-meta">
        <span class="mono">${esc(detector.id)}</span>
        <span>${formatNumber(detector.hit_count)} hits</span>
      </div>
      <div class="detector-tags">
        ${(detector.tags || []).map((tag) => `<span class="mini-tag">${esc(tag)}</span>`).join("")}
      </div>
    `;
    root.appendChild(card);
  }
}

function renderSeverity(items) {
  const root = document.getElementById("severity-chart");
  root.innerHTML = "";
  const counts = { critical: 0, warning: 0, info: 0 };
  for (const evt of items) {
    counts[severityClass(evt.severity)] += 1;
  }

  const rows = [
    { key: "critical", label: "Critical", copy: "Blocked actions and high-risk behavior", color: "var(--critical)" },
    { key: "warning", label: "Warning", copy: "Suspicious kernel activity worth review", color: "var(--warning)" },
    { key: "info", label: "Info", copy: "Observed telemetry and lower-risk signals", color: "var(--info)" },
  ];

  for (const row of rows) {
    const el = document.createElement("div");
    el.className = "legend-row";
    el.innerHTML = `
      <span class="legend-dot" style="background:${row.color}"></span>
      <div class="legend-label">
        <strong>${row.label}</strong>
        <span>${row.copy}</span>
      </div>
      <span class="legend-value">${formatNumber(counts[row.key])}</span>
    `;
    root.appendChild(el);
  }
}

function renderTopDetectors(items) {
  const root = document.getElementById("top-detectors-chart");
  root.innerHTML = "";

  if (!items.length) {
    root.appendChild(createEmptyState("No detector statistics yet", "Load detector files and generate hits to see which rules fire most often."));
    return;
  }

  const ranked = [...items]
    .sort((a, b) => Number(b.hit_count || 0) - Number(a.hit_count || 0))
    .slice(0, 5);
  const maxHits = Math.max(1, ...ranked.map((item) => Number(item.hit_count || 0)));

  for (const item of ranked) {
    const row = document.createElement("div");
    row.className = "rank-item";
    row.innerHTML = `
      <div class="rank-item-head">
        <div>
          <strong>${esc(item.name)}</strong>
          <span class="mono">${esc(item.id)}</span>
        </div>
        <span class="legend-value">${formatNumber(item.hit_count)}</span>
      </div>
      <div class="rank-item-bar">
        <div class="rank-item-bar-fill" style="width:${Math.max(8, Math.round((Number(item.hit_count || 0) / maxHits) * 100))}%"></div>
      </div>
    `;
    root.appendChild(row);
  }
}

function buildVolumeBuckets(items) {
  const bucketCount = 8;
  const hours = state.rangeHours > 0 ? state.rangeHours : 24 * 30;
  const bucketSize = Math.max(1, Math.floor(hours / bucketCount));
  const now = Date.now();
  const buckets = Array.from({ length: bucketCount }, (_, idx) => ({
    label: idx === bucketCount - 1 ? "Now" : `-${hours - bucketSize * (idx + 1)}h`,
    value: 0,
  }));

  for (const evt of items) {
    const ts = new Date(evt.ts).getTime();
    if (Number.isNaN(ts)) continue;
    const ageHours = Math.floor((now - ts) / (1000 * 60 * 60));
    if (ageHours < 0 || ageHours > hours) continue;
    const index = Math.min(bucketCount - 1, bucketCount - 1 - Math.floor(ageHours / bucketSize));
    buckets[index].value += 1;
  }
  return buckets;
}

function renderVolume(items) {
  const root = document.getElementById("volume-chart");
  root.innerHTML = "";
  const buckets = buildVolumeBuckets(items);
  const maxValue = Math.max(1, ...buckets.map((bucket) => bucket.value));

  for (const bucket of buckets) {
    const group = document.createElement("div");
    group.className = "bar-group";
    const height = Math.max(10, Math.round((bucket.value / maxValue) * 100));
    group.innerHTML = `
      <div class="bar-value">${formatNumber(bucket.value)}</div>
      <div class="bar-track">
        <div class="bar-fill" style="height:${height}%"></div>
      </div>
      <div class="bar-label">${esc(bucket.label)}</div>
    `;
    root.appendChild(group);
  }
}

function renderSummary(summary, agents, events, detections, detectors, blockedIpv4, blockedBindPorts) {
  const online = agents.filter((agent) => deriveAgentStatus(agent) === "online").length;
  const offline = Math.max(0, agents.length - online);
  const blocked = events.filter((evt) => actionClass(evt.action) === "block").length;
  const scopeLabel = state.rangeHours > 0 ? `${state.rangeHours}h scope` : "all available data";

  setText("agents-count", formatNumber(online));
  setText("events-count", formatNumber(events.length));
  setText("blocked-count", formatNumber(blocked));
  setText("policy-count", formatNumber(blockedIpv4.filter((entry) => entry.enabled).length));
  setText("bind-count", formatNumber(blockedBindPorts.filter((entry) => entry.enabled).length));
  setText("detections-count", formatNumber(detections.length));

  setText("agents-meta", `${formatNumber(agents.length)} total • ${offline} offline`);
  setText("events-meta", `${scopeLabel} • ${formatNumber(summary?.total_events || 0)} stored total`);
  setText("blocked-meta", blocked ? `${blocked} blocked actions in view` : "No blocked actions in current scope");
  setText("policy-meta", `${formatNumber(summary?.blocked_ipv4_count || 0)} active IPv4 rules`);
  setText("bind-meta", `${formatNumber(summary?.blocked_bind_port_count || 0)} active bind blocks`);
  setText("detections-meta", `${formatNumber(detectors.length)} detectors loaded`);
  setText("fleet-chip", `${formatNumber(agents.length)} agents`);
  setText("detector-chip", `${formatNumber(detections.length)} hits`);
  setText("catalog-chip", `${formatNumber(detectors.length)} loaded`);
  setText("volume-label", state.rangeHours > 0 ? `${state.rangeHours}h window` : "full history");
}

function openDetectionDrawer(id) {
  state.selectedDetectionId = id;
  renderDetectionDrawer();
}

function closeDetectionDrawer() {
  state.selectedDetectionId = null;
  renderDetectionDrawer();
}

function renderDetectionDrawer() {
  const backdrop = document.getElementById("detection-backdrop");
  const drawer = document.getElementById("detection-drawer");
  const title = document.getElementById("drawer-title");
  const body = document.getElementById("drawer-body");
  const hit = state.detections.find((item) => String(item.id) === String(state.selectedDetectionId));

  if (!hit) {
    backdrop.classList.add("hidden");
    drawer.classList.add("hidden");
    drawer.setAttribute("aria-hidden", "true");
    title.textContent = "No detection selected";
    body.innerHTML = "";
    return;
  }

  const sourceEvent = state.events.find((item) => Number(item.id) === Number(hit.event_id));
  const severity = severityClass(hit.severity);
  const action = actionClass(hit.action);
  const destination = sourceEvent?.dst_ip ? `${sourceEvent.dst_ip}:${sourceEvent.dst_port || 0}` : "-";
  const sourceSubject = sourceEvent?.subject || hit.subject || "-";

  backdrop.classList.remove("hidden");
  drawer.classList.remove("hidden");
  drawer.setAttribute("aria-hidden", "false");
  title.textContent = hit.detector_name;
  body.innerHTML = `
    <section class="drawer-card">
      <span class="pill ${severity}">${esc(hit.severity)}</span>
      <span class="pill ${action}">${esc(hit.action)}</span>
      <p class="drawer-summary">${esc(hit.summary)}</p>
      <span class="drawer-copy">Detector <code>${esc(hit.detector_id)}</code> fired from ${esc(hit.event_type)} on agent <code>${esc(hit.agent_id)}</code>.</span>
    </section>

    <section class="drawer-card-grid">
      <article class="drawer-card">
        <strong>Detection</strong>
        <span class="drawer-muted">Timestamp</span>
        <code>${esc(formatTs(hit.ts))}</code>
      </article>
      <article class="drawer-card">
        <strong>Source Event</strong>
        <span class="drawer-muted">Event ID</span>
        <code>${esc(hit.event_id || "-")}</code>
      </article>
    </section>

    <section class="drawer-card">
      <strong>Detection Metadata</strong>
      <div class="drawer-list">
        <div class="drawer-row">
          <span class="drawer-row-label">Agent</span>
          <span class="drawer-row-value">${esc(hit.agent_id)}</span>
        </div>
        <div class="drawer-row">
          <span class="drawer-row-label">Detector ID</span>
          <span class="drawer-row-value">${esc(hit.detector_id)}</span>
        </div>
        <div class="drawer-row">
          <span class="drawer-row-label">Event Type</span>
          <span class="drawer-row-value">${esc(hit.event_type)}</span>
        </div>
        <div class="drawer-row">
          <span class="drawer-row-label">Action</span>
          <span class="drawer-row-value">${esc(hit.action)}</span>
        </div>
        <div class="drawer-row">
          <span class="drawer-row-label">Subject</span>
          <span class="drawer-row-value">${esc(sourceSubject)}</span>
        </div>
      </div>
    </section>

    <section class="drawer-card">
      <strong>Kernel Event Context</strong>
      <div class="drawer-list">
        <div class="drawer-row">
          <span class="drawer-row-label">Process</span>
          <span class="drawer-row-value">${esc(sourceEvent?.comm || "-")} (${esc(sourceEvent?.pid || 0)})</span>
        </div>
        <div class="drawer-row">
          <span class="drawer-row-label">UID</span>
          <span class="drawer-row-value">${esc(sourceEvent?.uid || 0)}</span>
        </div>
        <div class="drawer-row">
          <span class="drawer-row-label">Destination</span>
          <span class="drawer-row-value">${esc(destination)}</span>
        </div>
        <div class="drawer-row">
          <span class="drawer-row-label">Arg0 / Arg1</span>
          <span class="drawer-row-value">${esc(sourceEvent?.arg0 || 0)} / ${esc(sourceEvent?.arg1 || 0)}</span>
        </div>
      </div>
    </section>
  `;
}

function applyState() {
  const agents = filterAgents(state.agents);
  const events = filterEvents(state.events);
  const detections = filterDetections(state.detections);
  const detectors = filterDetectors(state.detectors);
  const detectionEventIds = new Set(detections.map((item) => Number(item.event_id)).filter(Boolean));

  renderSummary(
    state.summary,
    state.agents,
    events,
    detections,
    state.detectors,
    state.blockedIpv4,
    state.blockedBindPorts,
  );
  renderAgents(agents);
  renderDetections(detections);
  renderEvents(events, detectionEventIds);
  renderDetectorCatalog(detectors);
  renderIpv4Policy(state.blockedIpv4);
  renderBindPolicy(state.blockedBindPorts);
  renderSeverity(detections.length ? detections : events);
  renderTopDetectors(state.detectors);
  renderVolume(events);
  renderDetectionDrawer();
}

async function refresh() {
  const [summary, agents, events, detections, detectors, policy] = await Promise.all([
    fetchJson("/api/v1/metrics/summary"),
    fetchJson("/api/v1/agents"),
    fetchJson("/api/v1/events?limit=200"),
    fetchJson("/api/v1/detections?limit=200"),
    fetchJson("/api/v1/detectors"),
    fetchJson("/api/v1/policy"),
  ]);

  state.summary = summary;
  state.agents = agents.items || [];
  state.events = events.items || [];
  state.detections = detections.items || [];
  state.detectors = detectors.items || [];
  state.blockedIpv4 = policy.blocked_ipv4_items || [];
  state.blockedBindPorts = policy.blocked_bind_port_items || [];

  if (state.selectedDetectionId && !state.detections.some((item) => String(item.id) === String(state.selectedDetectionId))) {
    state.selectedDetectionId = null;
  }

  applyState();
}

async function submitIpv4Policy(ip, enabled) {
  await fetchJson("/api/v1/policy/blocked-ipv4", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, enabled }),
  });
}

async function deleteIpv4Policy(ip) {
  await fetchJson("/api/v1/policy/blocked-ipv4", {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
}

async function submitBindPolicy(port, enabled) {
  await fetchJson("/api/v1/policy/blocked-bind-port", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ port, enabled }),
  });
}

async function deleteBindPolicy(port) {
  await fetchJson("/api/v1/policy/blocked-bind-port", {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ port }),
  });
}

document.getElementById("search-input").addEventListener("input", (event) => {
  state.search = event.target.value;
  applyState();
});

document.getElementById("time-range").addEventListener("change", (event) => {
  state.rangeHours = Number(event.target.value || 24);
  applyState();
});

document.getElementById("policy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("ip-input");
  const ip = input.value.trim();
  if (!ip) return;
  await submitIpv4Policy(ip, true);
  input.value = "";
  await refresh();
});

document.getElementById("bind-policy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("bind-port-input");
  const port = Number(input.value);
  if (!port || port < 1 || port > 65535) return;
  await submitBindPolicy(port, true);
  input.value = "";
  await refresh();
});

document.getElementById("policy-list").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const ip = button.dataset.ip;
  const action = button.dataset.action;
  if (!ip || !action) return;

  if (action === "toggle") {
    const current = state.blockedIpv4.find((entry) => entry.ip === ip);
    if (!current) return;
    await submitIpv4Policy(ip, !current.enabled);
    await refresh();
    return;
  }

  if (action === "remove") {
    await deleteIpv4Policy(ip);
    await refresh();
  }
});

document.getElementById("bind-policy-list").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const port = Number(button.dataset.port);
  const action = button.dataset.action;
  if (!port || !action) return;

  if (action === "toggle") {
    const current = state.blockedBindPorts.find((entry) => Number(entry.port) === port);
    if (!current) return;
    await submitBindPolicy(port, !current.enabled);
    await refresh();
    return;
  }

  if (action === "remove") {
    await deleteBindPolicy(port);
    await refresh();
  }
});

document.querySelector("#detections-table tbody").addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-detection-id]");
  if (!row) return;
  openDetectionDrawer(row.dataset.detectionId);
});

document.getElementById("drawer-close").addEventListener("click", closeDetectionDrawer);
document.getElementById("detection-backdrop").addEventListener("click", closeDetectionDrawer);
window.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDetectionDrawer();
});

refresh().catch(console.error);
setInterval(() => {
  refresh().catch(console.error);
}, 4000);
