# Detector Authoring

KShield detectors are TOML files in `manager/detectors/`. They match normalized events after
the manager stores raw agent events. Adding a detector does not require rebuilding the agent.

## Quick Start

1. Create a new `*.toml` file under `manager/detectors/`.
2. Give it a unique `id`.
3. Choose match fields under `[match]`.
4. Start or refresh the manager. The manager reloads detectors when files change.
5. Generate matching telemetry and check `/api/v1/detections` or the dashboard.

Example:

```toml
id = "suspicious-shell-from-temp"
name = "Suspicious Shell From Temp"
description = "Flags shell execution where the executed path is under /tmp."
severity = "warning"
tags = ["execution", "suspicious-path"]
summary_template = "{comm} executed {subject}"

[match]
event_types = ["execve"]
comm_in = ["bash", "sh", "dash"]
subject_prefixes = ["/tmp/"]
```

## Detector Fields

Top-level fields:

- `id`: stable unique detector ID. Use lowercase words separated by `-`.
- `name`: human-readable name shown in the UI.
- `description`: short reason this detector exists.
- `severity`: `info`, `warning`, or `critical`.
- `tags`: list of strings for grouping and search.
- `summary_template`: detection summary. May reference event fields with `{field}`.
- `threshold_count`: optional count needed before emitting a detection.
- `threshold_window_secs`: optional correlation window in seconds.
- `group_by`: optional event fields used as the threshold correlation key.

Match fields under `[match]`:

- `event_types`: event names such as `execve`, `file_open`, `file_write`, `ptrace`,
  `module_load`, `socket_connect`, `socket_bind`, `setuid`, `mount`, `bpf`.
- `actions`: `observe`, `allow`, or `block`.
- `comm_in`: exact process names from `comm`.
- `comm_prefixes`: process-name prefixes.
- `subject_prefixes`: path or subject prefixes.
- `subject_contains`: substrings in `subject`.
- `dst_ports`: destination or bind ports.
- `dst_ips`: destination IPv4 addresses.
- `uids`: Linux UIDs.
- `arg0_in`: exact numeric `arg0` values.
- `arg1_in`: exact numeric `arg1` values.

All string matching is case-insensitive except `dst_ips`.

## Event Fields

Detectors can match or render these normalized fields:

- `agent_id`
- `ts`
- `event_type`
- `action`
- `severity`
- `pid`
- `uid`
- `comm`
- `dst_ip`
- `dst_port`
- `subject`
- `arg0`
- `arg1`
- `ppid`
- `ancestry`
- `process_path`
- `pid_ns`
- `mount_ns`
- `net_ns`

## Threshold Detectors

Use `threshold_count`, `threshold_window_secs`, and `group_by` when one event is too noisy.

Example:

```toml
id = "repeated-bind-denials"
name = "Repeated Bind Denials"
description = "Flags repeated blocked bind attempts against the same port and process."
severity = "critical"
tags = ["network", "ips", "threshold"]
threshold_count = 3
threshold_window_secs = 120
group_by = ["agent_id", "comm", "dst_port"]
summary_template = "{comm} hit {match_count} blocked bind attempts on port {dst_port} within 120s"

[match]
event_types = ["socket_bind"]
actions = ["block"]
```

This emits on the third matching event in the 120 second window for the same
`agent_id`, `comm`, and `dst_port`.

## Block Detectors

LSM policy blocks are normal events with `action = "block"`. Detector examples:

```toml
id = "blocked-exec-path"
name = "Blocked Exec Path"
description = "Highlights execution denied by selected exec path policy."
severity = "critical"
tags = ["execution", "ips", "lsm"]
summary_template = "{comm} was blocked from executing {subject}"

[match]
event_types = ["execve"]
actions = ["block"]
```

```toml
id = "blocked-sensitive-write"
name = "Blocked Sensitive Write"
description = "Highlights denied writes to protected targets."
severity = "critical"
tags = ["filesystem", "ips", "lsm"]
summary_template = "{comm} was blocked from writing target {subject}"

[match]
event_types = ["file_write"]
actions = ["block"]
```

## Testing

List loaded detectors:

```bash
curl -s http://127.0.0.1:8080/api/v1/detectors | jq
```

List detections:

```bash
curl -s http://127.0.0.1:8080/api/v1/detections | jq
```

Run replay tests after adding detector fixtures:

```bash
python3 -m unittest tests.test_replay
```

## Detector Limits

Current detectors are single-event or simple threshold rules. They do not yet support:

- regex
- negative matches
- complex boolean logic
- multi-stage sequence correlation
- file hash matching
- content scanning

Use agent or manager code changes for those features.
