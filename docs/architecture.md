# Architecture

## Manager

- Runtime: Python `http.server` (`manager/app.py`)
- Storage: SQLite (`manager/data/siem.db`)
- APIs:
  - `POST /api/v1/agents/register`
  - `GET /api/v1/agents`
  - `POST /api/v1/events`
  - `GET /api/v1/events`
  - `GET /api/v1/metrics/summary`
  - `GET /api/v1/policy/<agent_id>`
  - `POST /api/v1/policy/blocked-ipv4`
- Dashboard: static HTML/CSS/JS in `manager/static`

## Agent

- Runtime: Rust (`agent/src/main.rs`)
- Kernel programs:
  - `tracepoint/syscalls/sys_enter_execve` -> execution telemetry
  - `lsm/socket_connect` -> inline destination IP blocking
- Maps:
  - `EVENTS` (ringbuf): kernel -> userspace events
  - `BLOCKED_IPV4` (hash): userspace policy -> kernel enforcement

## Event Flow

1. Kernel eBPF emits events to ring buffer.
2. Agent reads ring buffer, converts to JSON.
3. Agent POSTs to manager `/api/v1/events`.
4. Manager writes SQLite rows and updates dashboard views.

## Policy Flow

1. Operator blocks IP via dashboard.
2. Manager persists blocked IP list.
3. Agent polls `/api/v1/policy/<agent_id>`.
4. Agent rewrites `BLOCKED_IPV4` map.
5. LSM hook returns `-EPERM` for blocked destinations.
