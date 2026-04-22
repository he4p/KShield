# Architecture

## Manager

- Runtime: Python `http.server` (`manager/app.py`)
- Storage: SQLite (`manager/data/siem.db`)
- Detector loading: TOML definitions from `manager/detectors/`
- Dashboard: static HTML/CSS/JS in `manager/static`
- APIs:
  - `POST /api/v1/agents/register`
  - `GET /api/v1/agents`
  - `POST /api/v1/events`
  - `GET /api/v1/events`
  - `GET /api/v1/detections`
  - `GET /api/v1/detectors`
  - `GET /api/v1/metrics/summary`
  - `GET /api/v1/policy`
  - `GET /api/v1/policy/<agent_id>`
  - `POST /api/v1/policy/blocked-ipv4`
  - `DELETE /api/v1/policy/blocked-ipv4`
  - `POST /api/v1/policy/blocked-bind-port`
  - `DELETE /api/v1/policy/blocked-bind-port`

## Agent

- Runtime: Rust (`agent/src/main.rs`)
- Kernel programs:
  - `kprobe/__x64_sys_execve` -> execution telemetry
  - `kprobe/__x64_sys_openat` -> file access telemetry
  - `kprobe/__x64_sys_openat2` -> file access telemetry when available
  - `kprobe/__x64_sys_ptrace` -> ptrace telemetry
  - `kprobe/__x64_sys_init_module` -> module load telemetry when available
  - `kprobe/__x64_sys_finit_module` -> module load telemetry when available
  - `lsm/socket_connect` -> inline IPv4 destination blocking
  - `lsm/socket_bind` -> inline local bind-port blocking
- Maps:
  - `EVENTS` (ringbuf): kernel -> userspace events
  - `BLOCKED_IPV4` (hash): userspace policy -> `socket_connect` enforcement
  - `BLOCKED_BIND_PORTS` (hash): userspace policy -> `socket_bind` enforcement

## Event Flow

1. Kernel eBPF programs emit raw events to the ring buffer.
2. Agent reads ring buffer events and converts them to JSON.
3. Agent POSTs raw events to `/api/v1/events`.
4. Manager stores raw events in the `events` table.
5. Manager evaluates each event against loaded detector definitions.
6. Matching detectors produce derived detection hits in the `detections` table.
7. Dashboard renders both raw events and triggered detections.

## Policy Flow

1. Operator creates or updates blocked IPv4 or blocked bind-port policy in the dashboard.
2. Manager persists policy in SQLite.
3. Agent polls `/api/v1/policy/<agent_id>`.
4. Agent rewrites the relevant eBPF policy maps.
5. LSM hooks return `-EPERM` for blocked destinations or blocked bind ports.
6. The same LSM hooks still emit ring-buffer events so policy hits are visible in the UI and can trigger detectors.

## Detector Flow

1. Operator or developer adds a TOML detector under `manager/detectors/`.
2. Manager reloads detector definitions when the directory contents change.
3. Incoming events are evaluated against detector match criteria such as:
   - `event_types`
   - `actions`
   - `comm_in`
   - `subject_prefixes`
   - `subject_contains`
   - `dst_ports`
   - `dst_ips`
   - `arg0_in`
   - `arg1_in`
4. Matching events create persisted detection hits.
5. Dashboard shows detector hit volume, hit details, and per-detector hit counts.
