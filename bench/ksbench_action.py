#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import errno
import os
import socket
import stat
import sys
import time
from ctypes import c_char_p, c_int, c_long, c_size_t, c_ulong, c_void_p


LIBC = ctypes.CDLL(None, use_errno=True)

PR_SET_NAME = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

SYS_x86_64 = {
    "bpf": 321,
    "mount": 165,
    "init_module": 175,
}


def die(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def prctl_set_name(name: str) -> None:
    raw = name.encode("utf-8")[:15]
    buf = ctypes.create_string_buffer(raw + b"\x00")
    res = LIBC.prctl(c_int(PR_SET_NAME), ctypes.byref(buf), c_ulong(0), c_ulong(0), c_ulong(0))
    if res != 0:
        err = ctypes.get_errno()
        die(f"prctl(PR_SET_NAME) failed: {os.strerror(err)}")


def _ensure_x86_64() -> None:
    if os.uname().machine != "x86_64":
        die(f"unsupported arch for syscall mapping: {os.uname().machine} (expected x86_64)")


def _syscall(num: int, *args: int) -> int:
    LIBC.syscall.restype = c_long
    LIBC.syscall.argtypes = [c_long] + [c_long] * len(args)
    return int(LIBC.syscall(c_long(num), *[c_long(a) for a in args]))


def open_read(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    os.close(fd)


def exec_path(path: str, argv0: str | None = None) -> int:
    argv = [argv0 or path]
    if path.endswith(".sh"):
        argv = [path]
    pid = os.fork()
    if pid == 0:
        try:
            prctl_set_name("ksbench")
            os.execv(path, argv)
        except OSError as exc:
            print(f"execv failed: {exc}", file=sys.stderr)
            os._exit(127)
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    return 128


def setuid0_attempt() -> None:
    LIBC.setuid.restype = c_int
    LIBC.setuid.argtypes = [c_int]
    _ = LIBC.setuid(c_int(0))


def ptrace_attach_child() -> None:
    pid = os.fork()
    if pid == 0:
        prctl_set_name("ksbench-child")
        time.sleep(3)
        os._exit(0)

    try:
        LIBC.ptrace.restype = c_long
        LIBC.ptrace.argtypes = [c_long, c_long, c_void_p, c_void_p]
        res = int(LIBC.ptrace(c_long(PTRACE_ATTACH), c_long(pid), c_void_p(0), c_void_p(0)))
        if res == 0:
            # Wait for stop, then detach.
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            _ = int(LIBC.ptrace(c_long(PTRACE_DETACH), c_long(pid), c_void_p(0), c_void_p(0)))
        else:
            _ = ctypes.get_errno()
    finally:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass


def mount_attempt() -> None:
    _ensure_x86_64()
    target = "/tmp/ksbench_mnt"
    os.makedirs(target, exist_ok=True)
    # mount("tmpfs", target, "tmpfs", 0, "")
    src = ctypes.create_string_buffer(b"tmpfs\x00")
    tgt = ctypes.create_string_buffer(target.encode("utf-8") + b"\x00")
    fstype = ctypes.create_string_buffer(b"tmpfs\x00")
    data = ctypes.create_string_buffer(b"\x00")
    LIBC.mount.restype = c_int
    LIBC.mount.argtypes = [c_char_p, c_char_p, c_char_p, c_ulong, c_void_p]
    _ = int(LIBC.mount(src, tgt, fstype, c_ulong(0), ctypes.cast(data, c_void_p)))


def init_module_attempt() -> None:
    _ensure_x86_64()
    # init_module(NULL, 0, NULL) -> typically EINVAL/EPERM but still triggers syscall.
    _ = _syscall(SYS_x86_64["init_module"], 0, 0, 0)


def bpf_syscall_attempt() -> None:
    _ensure_x86_64()
    # bpf(0, NULL, 0) -> EINVAL but triggers syscall.
    _ = _syscall(SYS_x86_64["bpf"], 0, 0, 0)


def connect_ipv4(ip: str, port: int, timeout_s: float = 1.5) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout_s)
        try:
            s.connect((ip, port))
        except OSError:
            pass


def bind_ipv4(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("0.0.0.0", port))
        except OSError:
            pass


def write_protected_shadow() -> None:
    path = "/tmp/shadow"
    with open(path, "wb") as f:
        f.write(b"x")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        os.write(fd, b"y")
        os.close(fd)
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES):
            raise


def ensure_blocked_exec_script() -> str:
    path = "/tmp/ksbench_blocked_exec.sh"
    content = "#!/usr/bin/env sh\nexit 0\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, 0o755)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="KShield benchmark action generator")
    parser.add_argument("action", help="action name")
    parser.add_argument("--comm", default="ksbench", help="task comm/name used for filtering")
    args = parser.parse_args()

    prctl_set_name(args.comm)

    action = args.action
    if action == "open_shadow":
        open_read("/etc/shadow")
        return 0
    if action == "open_kcore":
        open_read("/proc/kcore")
        return 0
    if action == "open_hosts":
        open_read("/etc/hosts")
        return 0
    if action == "exec_true":
        return exec_path("/bin/true")
    if action == "ptrace_attach_child":
        ptrace_attach_child()
        return 0
    if action == "setuid0":
        setuid0_attempt()
        return 0
    if action == "mount_attempt":
        mount_attempt()
        return 0
    if action == "bpf_syscall":
        bpf_syscall_attempt()
        return 0
    if action == "init_module_attempt":
        init_module_attempt()
        return 0
    if action == "connect_blocked_ip":
        connect_ipv4("203.0.113.1", 80)
        return 0
    if action == "connect_localhost_closed":
        connect_ipv4("127.0.0.1", 1)
        return 0
    if action == "bind_blocked_port":
        bind_ipv4(4444)
        return 0
    if action == "bind_blocked_port_repeat3":
        for _ in range(3):
            bind_ipv4(4444)
            time.sleep(0.15)
        return 0
    if action == "exec_blocked_path":
        path = ensure_blocked_exec_script()
        return exec_path(path)
    if action == "write_protected_shadow":
        write_protected_shadow()
        return 0

    die(f"unknown action: {action}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

