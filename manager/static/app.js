async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value);
}

function renderAgents(items) {
  const tbody = document.querySelector("#agents-table tbody");
  tbody.innerHTML = "";
  for (const a of items) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${a.id}</td>
      <td>${a.hostname}</td>
      <td>${a.ip}</td>
      <td>${a.kernel || ""}</td>
      <td>${a.version || ""}</td>
      <td>${a.last_seen}</td>
    `;
    tbody.appendChild(tr);
  }
}

function renderEvents(items) {
  const tbody = document.querySelector("#events-table tbody");
  tbody.innerHTML = "";
  for (const e of items) {
    const tr = document.createElement("tr");
    const actionClass = e.action === "block" ? "action-block" : "";
    const dst = e.dst_ip ? `${e.dst_ip}:${e.dst_port}` : "-";
    tr.innerHTML = `
      <td>${e.ts}</td>
      <td>${e.agent_id}</td>
      <td>${e.event_type}</td>
      <td class="${actionClass}">${e.action}</td>
      <td>${e.severity}</td>
      <td>${e.comm} (${e.pid})</td>
      <td>${dst}</td>
    `;
    tbody.appendChild(tr);
  }
}

function renderPolicy(ips) {
  const root = document.getElementById("policy-list");
  root.innerHTML = "";
  for (const ip of ips) {
    const span = document.createElement("span");
    span.className = "pill";
    span.textContent = ip;
    root.appendChild(span);
  }
}

async function refresh() {
  const [summary, agents, events, policy] = await Promise.all([
    fetchJson("/api/v1/metrics/summary"),
    fetchJson("/api/v1/agents"),
    fetchJson("/api/v1/events?limit=120"),
    fetchJson("/api/v1/policy"),
  ]);
  setText("agents-count", summary.total_agents);
  setText("events-count", summary.total_events);
  setText("blocked-count", summary.blocked_events);
  setText("policy-count", summary.blocked_ipv4_count);
  renderAgents(agents.items || []);
  renderEvents(events.items || []);
  renderPolicy(policy.blocked_ipv4 || []);
}

document.getElementById("policy-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const ipInput = document.getElementById("ip-input");
  const ip = ipInput.value.trim();
  if (!ip) return;
  await fetchJson("/api/v1/policy/blocked-ipv4", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, enabled: true }),
  });
  ipInput.value = "";
  await refresh();
});

refresh().catch(console.error);
setInterval(() => {
  refresh().catch(console.error);
}, 4000);
