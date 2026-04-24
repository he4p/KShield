# KShield: Kernel Threat Detection SIEM (eBPF + LSM IPS)

KShield is a manager/agent platform inspired by the Elastic/Kibana + Agent model:

- `manager`: central API, detector engine, dashboard, and policy store
- `agent`: endpoint kernel monitor using eBPF
- `LSM`: inline blocking for outbound connects and local bind operations

## Current Coverage

The agent now captures:

- `execve` execution telemetry
- `openat` and `openat2` file access telemetry
- `ptrace` activity telemetry
- kernel module load attempts (`init_module`, `finit_module`) when available
- `socket_connect` LSM allow/block events
- `socket_bind` LSM allow/block events

The manager evaluates incoming events against file-based detectors loaded from `manager/detectors/*.toml`
and stores detector hits separately from the raw event stream. See [Detector Authoring](docs/detectors.md)
for adding human-maintained rules.

## Architecture

1. Agent registers itself to the manager.
2. Agent loads eBPF telemetry probes and LSM enforcement hooks.
3. Agent posts raw kernel events to the manager over HTTP JSON.
4. Manager stores raw events in SQLite.
5. Manager evaluates each event against loaded detectors and stores matching detector hits.
6. Dashboard shows fleet health, raw events, triggered detectors, and active policy.

## Detector Format

KShield detectors use TOML so users can add rules without changing code or needing extra dependencies.

Example:

```toml
id = "sensitive-shadow-access"
name = "Sensitive Shadow Access"
description = "Flags access attempts against /etc/shadow."
severity = "critical"
tags = ["credential-access", "filesystem"]
summary_template = "{comm} accessed {subject}"

[match]
event_types = ["file_open"]
subject_prefixes = ["/etc/shadow"]
```

Supported match fields:

- `event_types`
- `actions`
- `comm_in`
- `comm_prefixes`
- `subject_prefixes`
- `subject_contains`
- `dst_ports`
- `dst_ips`
- `uids`
- `arg0_in`
- `arg1_in`

Threshold detectors are also supported with `threshold_count`, `threshold_window_secs`, and `group_by`.
See [Detector Authoring](docs/detectors.md) for examples and testing commands.

## Signature Antivirus Direction

Signature-based antivirus is possible, but eBPF LSM should enforce userspace scan verdicts rather than scan
file contents directly in kernel BPF. See [Signature Antivirus With LSM](docs/signature-av-lsm.md).

## Quick Start (Host)

```bash
cd <project-root>
bash scripts/start_manager.sh
```

Open: `http://127.0.0.1:8080`

## Build Agent

```bash
cd <project-root>
bash scripts/build_agent.sh
```

Run locally (requires root):

```bash
sudo ./agent/target/release/kshield-agent \
  --manager-url http://127.0.0.1:8080 \
  --bpf-object ./agent/bpf/kshield.bpf.o
```

## Deploy Agent to VM

Install deploy dependency on the host if needed:

```bash
sudo pacman -S --noconfirm python-paramiko
```

Deploy:

```bash
python3 deploy/deploy_agent.py \
  --host 192.168.122.27 \
  --user he4p \
  --manager-url http://<HOST_IP>:8080
```

The deploy script prompts for the SSH password if `--password` is omitted. If the remote sudo password
differs from the SSH password, pass it with `--sudo-password`.

## API Summary

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

## Notes

- LSM eBPF requires kernel support: `CONFIG_BPF_LSM=y` and BTF enabled.
- On Ubuntu VMs, the boot LSM order must include `bpf`. Example GRUB setting:
  `GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=lockdown,capability,landlock,yama,apparmor,bpf"`
- Agent must run as root to load and attach eBPF programs.
- `socket_bind` policy currently targets IPv4 bind attempts by local port.
- A sample VM service unit is provided at `deploy/kshield-agent.service`.
- KShield now has its own detector engine. It does not embed Tracee's detector library directly.
