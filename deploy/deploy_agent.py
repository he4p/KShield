#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import pathlib
import shlex
import subprocess
import sys

import paramiko


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy kshield-agent to a remote VM over SSH")
    parser.add_argument("--host", required=True, help="remote IP or hostname")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", required=True)
    parser.add_argument(
        "--password",
        default="",
        help="SSH password. If omitted, the script prompts for it.",
    )
    parser.add_argument("--manager-url", required=True, help="e.g. http://192.168.122.1:8080")
    parser.add_argument(
        "--remote-dir",
        default="~/kshield-agent",
        help="directory where agent binary and bpf object will be uploaded",
    )
    parser.add_argument(
        "--project-root",
        default=str(pathlib.Path(__file__).resolve().parent.parent),
    )
    parser.add_argument(
        "--sudo-password",
        default="",
        help="sudo password used on remote VM (defaults to the SSH password)",
    )
    return parser.parse_args()


def local_build(project_root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    subprocess.run(["bash", "agent/build_bpf.sh"], cwd=project_root, check=True)
    subprocess.run(["cargo", "build", "--release"], cwd=project_root / "agent", check=True)

    bin_path = project_root / "agent" / "target" / "release" / "kshield-agent"
    bpf_obj = project_root / "agent" / "bpf" / "kshield.bpf.o"
    if not bin_path.exists() or not bpf_obj.exists():
        raise RuntimeError("build artifacts not found")
    return bin_path, bpf_obj


def run_remote(ssh: paramiko.SSHClient, cmd: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = ssh.exec_command(cmd)
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return code, out, err


def main() -> int:
    args = parse_args()
    ssh_password = args.password or getpass.getpass(
        f"SSH password for {args.user}@{args.host}: "
    )
    sudo_password = args.sudo_password or ssh_password
    project_root = pathlib.Path(args.project_root).resolve()

    print("building agent locally...")
    bin_path, bpf_obj = local_build(project_root)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"connecting to {args.user}@{args.host}:{args.port} ...")
    ssh.connect(
        hostname=args.host,
        port=args.port,
        username=args.user,
        password=ssh_password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )

    requested_remote_dir = args.remote_dir
    quoted_remote_dir = shlex.quote(requested_remote_dir)
    code, out, err = run_remote(
        ssh,
        f"bash -lc 'mkdir -p {quoted_remote_dir} && cd {quoted_remote_dir} && pwd'",
    )
    if code != 0:
        print(err, file=sys.stderr)
        return 1
    remote_dir = out.strip()
    if not remote_dir:
        print("could not resolve remote directory", file=sys.stderr)
        return 1

    sftp = ssh.open_sftp()
    sftp.put(str(bin_path), f"{remote_dir}/kshield-agent")
    sftp.put(str(bpf_obj), f"{remote_dir}/kshield.bpf.o")
    sftp.close()

    run_remote(ssh, f"chmod +x {shlex.quote(remote_dir)}/kshield-agent")

    agent_cmd = (
        f"{shlex.quote(remote_dir)}/kshield-agent "
        f"--manager-url {shlex.quote(args.manager_url)} "
        f"--bpf-object {shlex.quote(remote_dir)}/kshield.bpf.o"
    )
    escaped_sudo_password = sudo_password.replace("'", "'\"'\"'")
    remote_script = f"""
set -e
pkill -f '{remote_dir}/kshield-agent' || true
if sudo -n true >/dev/null 2>&1; then
  nohup sudo {agent_cmd} > {shlex.quote(remote_dir)}/agent.log 2>&1 &
else
  nohup bash -lc "printf '%s\\n' '{escaped_sudo_password}' | sudo -S {agent_cmd}" > {shlex.quote(remote_dir)}/agent.log 2>&1 &
fi
sleep 1
ps aux | grep kshield-agent | grep -v grep || true
tail -n 40 {shlex.quote(remote_dir)}/agent.log || true
"""
    start_cmd = f"bash -lc {shlex.quote(remote_script)}"
    code, out, err = run_remote(ssh, start_cmd)
    if code != 0:
        print(out)
        print(err, file=sys.stderr)
        return 1
    if out.strip():
        print(out.strip())
    if err.strip():
        print(err.strip(), file=sys.stderr)
    print("deployment finished")
    ssh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
