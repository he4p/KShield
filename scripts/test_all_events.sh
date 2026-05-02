#!/usr/bin/env bash
# Script to safely trigger all KShield supported telemetry events
# Make sure to run the KShield agent in another terminal before running this script!

echo "================================================="
echo "[*] Triggering KShield Telemetry Events"
echo "================================================="

echo ""
echo "[*] 1. Testing execve, fork, and exit..."
bash -c "echo '   -> Subshell executed successfully'"

echo ""
echo "[*] 2. Testing file_open..."
cat /etc/hosts > /dev/null
echo "   -> /etc/hosts opened"

echo ""
echo "[*] 3. Testing file_write..."
echo "write test" > /tmp/kshield_write_test.txt
rm /tmp/kshield_write_test.txt
echo "   -> Wrote to /tmp/kshield_write_test.txt"

echo ""
echo "[*] 4. Testing socket_connect..."
curl -s -m 2 -o /dev/null http://example.com || true
echo "   -> HTTP request sent to example.com"

echo ""
echo "[*] 5. Testing socket_bind..."
# bind to a high port for 1 second in the background
timeout 1 nc -l -p 12345 2>/dev/null &
echo "   -> Bound to port 12345"
sleep 1

echo ""
echo "[*] 6. Testing ptrace..."
# using strace on a simple command to trigger ptrace_attach
strace -e trace=none echo "   -> Strace executed" > /dev/null 2>&1 || true

echo ""
echo "[*] 7. Testing mmap (PROT_EXEC | MAP_ANONYMOUS)..."
python3 -c "
import ctypes
try:
    libc = ctypes.CDLL(None)
    # PROT_READ(1) | PROT_WRITE(2) | PROT_EXEC(4) = 7
    # MAP_PRIVATE(2) | MAP_ANONYMOUS(32) = 34
    res = libc.mmap(0, 4096, 7, 34, -1, 0)
    print('   -> mmap executed successfully')
except Exception as e:
    print(f'   -> mmap failed: {e}')
" || true

echo ""
echo "[*] 8. Testing mprotect (PROT_EXEC)..."
python3 -c "
import ctypes
try:
    libc = ctypes.CDLL(None)
    mem = libc.valloc(4096)
    # PROT_READ(1) | PROT_WRITE(2) | PROT_EXEC(4) = 7
    libc.mprotect(mem, 4096, 7)
    print('   -> mprotect executed successfully')
except Exception as e:
    print(f'   -> mprotect failed: {e}')
" || true

echo ""
echo "[*] 9. Testing setuid..."
python3 -c "
import os
try:
    os.setuid(1000)
    print('   -> setuid executed')
except PermissionError:
    print('   -> setuid attempted (denied without sudo, but event is still logged)')
" || true

echo ""
echo "[*] 10. Testing mount..."
mkdir -p /tmp/kshield_mnt
sudo mount -t tmpfs tmpfs /tmp/kshield_mnt 2>/dev/null || true
echo "   -> mount attempted"
sudo umount /tmp/kshield_mnt 2>/dev/null || true
rmdir /tmp/kshield_mnt

echo ""
echo "[*] 11. Testing bpf syscall..."
python3 -c "
import ctypes
try:
    libc = ctypes.CDLL(None)
    # SYS_bpf is 321 on x86_64
    libc.syscall(321, 0, 0, 0)
    print('   -> bpf syscall executed')
except Exception:
    print('   -> bpf syscall attempted')
" || true

echo ""
echo "[*] Note: module_load (init_module/finit_module) is skipped to avoid safely altering kernel state."
echo "================================================="
echo "[+] All events triggered! Check your KShield Agent / Manager."
echo "================================================="
