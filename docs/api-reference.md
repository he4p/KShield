# Manager API Reference

The Ataree backend manager exposes a RESTful API over HTTP to interact with agents, fetch metrics, and manage LSM enforcement policies. Below is the API reference.

> **Note on Authentication:**
> Most endpoints used by the dashboard UI require HTTP Basic Authentication (`admin:secret`), with the exception of `/healthz`, `/api/v1/agents/register`, and `/api/v1/policy/{agent_id}`.

---

## Agent & Event Ingestion

### `POST /api/v1/agents/register`
Registers a new eBPF agent.
- **Payload:** `{"hostname": "...", "ip": "...", "kernel": "...", "version": "..."}`
- **Returns:** `{"agent_id": "<uuid>"}`

### `POST /api/v1/events`
Submit a batch of raw telemetry events gathered by the eBPF agent from the kernel ring buffer.
- **Payload:** `{"events": [ { ... } ]}`
- **Returns:** `{"written": int}`

---

## Dashboard Data

### `GET /api/v1/metrics/summary`
Returns overarching aggregation statistics for the dashboard.
- **Returns:** Total occurrences, blocked events, severity breakdown, and loaded policy counts.

### `GET /api/v1/agents`
Returns a list of all known registered agents and their last seen statuses.

### `GET /api/v1/events`
Returns a paginated list of recent raw telemetry events.
- **Query Params:** `limit` (default: 200, max: 2000)

### `GET /api/v1/detections`
Returns a list of events that matched active TOML detectors (Triggered Detectors).
- **Query Params:** `limit` (default: 200, max: 2000)

### `GET /api/v1/detectors`
Returns all active loaded rules from the `manager/detectors/*.toml` directory, with their current live hit counts.

---

## Policy & LSM Enforcement

Policies dictating what gets blocked (IPv4s, bind ports, exec paths, file writes, ptrace) can be dynamically configured.

### `GET /api/v1/policy`
Returns all globally defined policies.

### `GET /api/v1/policy/{agent_id}`
Returns all active policies tailored to a specific agent's scope. The agents constantly poll this endpoint.

### Modifying Policies
You can add or remove policies via `POST` or `DELETE` across various sub-routes:
- `/api/v1/policy/blocked-ipv4`
- `/api/v1/policy/blocked-bind-port`
- `/api/v1/policy/blocked-exec-path`
- `/api/v1/policy/protected-write-target`
- `/api/v1/policy/deny-ptrace`

**POST Example (Block an IP):**
```json
{
  "ip": "203.0.113.10",
  "enabled": true,
  "agent_id": "" 
}
```

**DELETE Example:**
```json
{
  "ip": "203.0.113.10",
  "agent_id": "" 
}
```
*(Passing an empty `agent_id` scopes the rule globally.)*
