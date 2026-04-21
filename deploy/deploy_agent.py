#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

import paramiko


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy kshield-agent to a remote VM over SSH")
    parser.add_argument("--host", required=True, help="remote IP or hostname")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
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
        password=args.password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )

    remote_dir = args.remote_dir
    code, _, err = run_remote(ssh, f"mkdir -p {remote_dir}")
    if code != 0:
        print(err, file=sys.stderr)
        return 1

    sftp = ssh.open_sftp()
    sftp.put(str(bin_path), f"{remote_dir}/kshield-agent")
    sftp.put(str(bpf_obj), f"{remote_dir}/kshield.bpf.o")
    sftp.close()

    run_remote(ssh, f"chmod +x {remote_dir}/kshield-agent")
    run_remote(ssh, f"pkill -f '{remote_dir}/kshield-agent' || true")

    start_cmd = (
        f"nohup {remote_dir}/kshield-agent "
        f"--manager-url {args.manager_url} "
        f"--bpf-object {remote_dir}/kshield.bpf.o "
        f"> {remote_dir}/agent.log 2>&1 &"
    )
    code, out, err = run_remote(ssh, start_cmd)
    if code != 0:
        print(out)
        print(err, file=sys.stderr)
        return 1

    code, out, err = run_remote(ssh, f"ps aux | grep kshield-agent | grep -v grep")
    print(out)
    if code != 0:
        print(err, file=sys.stderr)
    print("deployment finished")
    ssh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
