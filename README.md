# KShield: Kernel Threat Detection SIEM (eBPF + LSM IPS)

KShield is a manager/agent platform inspired by the Elastic/Kibana + Agent model:

- `manager`: central API + dashboard + policy store
- `agent`: endpoint kernel monitor using eBPF
- LSM eBPF hook for inline blocking (`security_socket_connect`)

## Architecture

1. Agent registers itself to the manager.
2. Agent loads two eBPF programs:
   - Tracepoint: `sys_enter_execve` (process execution telemetry)
   - LSM: `socket_connect` (inline IPv4 destination blocking)
3. Agent sends events to manager over HTTP JSON.
4. Manager stores events and policy in SQLite, serves dashboard.
5. Dashboard allows adding blocked IPv4 entries, pushed to agents during policy sync.

## Quick Start (Host)

```bash
cd /home/hitler/Study/project
bash scripts/start_manager.sh
```

Open: `http://127.0.0.1:8080`

## Build Agent

```bash
cd /home/hitler/Study/project
bash scripts/build_agent.sh
```

Run locally (requires root):

```bash
sudo ./agent/target/release/kshield-agent \
  --manager-url http://127.0.0.1:8080 \
  --bpf-object ./agent/bpf/kshield.bpf.o
```

## Deploy Agent to VM (Password SSH)

Install deploy dependency (Arch Linux):

```bash
printf 'hitler\n' | sudo -S pacman -S --noconfirm python-paramiko
```

Deploy:

```bash
python3 deploy/deploy_agent.py \
  --host 192.168.122.27 \
  --user hitler \
  --password hitler \
  --manager-url http://<HOST_IP>:8080
```

If deployment fails with connection refused on port 22, enable SSH server inside the VM first:

```bash
sudo systemctl enable --now sshd
```

## Notes

- LSM eBPF requires kernel support: `CONFIG_BPF_LSM=y` and BTF enabled.
- Agent must run as root to load and attach eBPF programs.
- Policy map currently supports IPv4 destination blocks.
