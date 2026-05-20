# Current Detectors

Here are all the out-of-the-box detectors available in Ataree:

- **Blocked Bind Port**: Highlights bind attempts denied by port policy.
- **Blocked Egress Connection**: Highlights outbound network connections blocked by policy.
- **Blocked Exec Path**: Highlights execution denied by selected exec path policy.
- **Blocked Ptrace**: Highlights ptrace access denied by policy.
- **Blocked Sensitive Write**: Highlights denied writes to protected targets.
- **BPF Syscall Use**: Flags direct bpf syscall use from userspace.
- **CVE-2026-43284 ESP-in-UDP Splice**: Flags ESP packets parsed by esp_input, catching potential exploitation of the SKBFL_SHARED_FRAG decrypt-in-place bug.
- **CVE-2026-46333 Exploitation Attempt**: Flags usage of pidfd_getfd to copy file descriptors from privileged processes, indicating the ssh-keysign-pwn race condition.
- **Disable or Modify Audit System**: Flags attempts to execute audit tooling or access Linux audit configuration and logs.
- **Disable or Modify Firewall**: Flags firewall tooling execution or access to persistent firewall configuration.
- **Disable or Modify Security Tools**: Flags direct tampering with common Linux security and monitoring tools.
- **Downgrade Attack**: Flags package manager execution and crypto policy configuration access that can indicate forced downgrade attempts.
- **Impair Command History Logging**: Flags access to shell command history files commonly cleared to reduce forensic visibility.
- **Indicator Blocking**: Flags access to hosts, DNS, and logging configuration that can block security telemetry or indicators.
- **Interactive Shell Execution**: Flags execution of common interactive shells.
- **Kernel Module Load Attempt**: Flags runtime kernel module loading attempts.
- **Mount Activity**: Flags mount syscall activity for manual review.
- **Kernel Memory Recon**: Flags reads of /proc/kcore which often indicate kernel memory reconnaissance.
- **Ptrace Attach Attempt**: Flags ptrace activity that can indicate live process tampering or debugging.
- **Repeated Bind Denials**: Flags repeated blocked bind attempts against the same port and process.
- **Sensitive Shadow Access**: Flags access attempts against /etc/shadow.
- **Setuid To Root**: Flags attempts to change effective uid to 0.
- **Spoof Security Alerting**: Flags access to local logging sockets, log files, and alerting configuration used to spoof or suppress alerts.