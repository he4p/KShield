# Extension Plan

This is the next-phase plan for KShield after the detector engine and expanded LSM policy work now in the repo.

## Phase 1: Completed in This Iteration

- Add a universal detector definition format using TOML.
- Persist detector hits separately from raw events.
- Expand telemetry beyond `execve` into file access, ptrace, and module load attempts.
- Expand LSM enforcement beyond `socket_connect` into `socket_bind`.
- Surface detector hits and detector inventory in the dashboard.

## Phase 2: Kernel Telemetry Expansion

- Add process ancestry and parent PID to event payloads.
- Add `setuid`, `mount`, and `bpf` syscall visibility.
- Capture richer file metadata for sensitive paths.
- Add optional container and namespace context when available.

## Phase 3: Detector Semantics

- Support multi-event correlation windows, not just single-event matches.
- Add threshold detectors such as repeated failed binds or bursty ptrace attempts.
- Add allowlists and suppression rules per detector.
- Add detector test fixtures and offline replay of saved event streams.

## Phase 4: Enforcement

- Add executable deny rules for selected paths or hashes.
- Add sensitive-file write protection.
- Add optional ptrace deny rules.
- Add scoped policy application per agent rather than global policy only.

## Phase 5: Operations and UX

- Turn the manager into a persistent systemd service on the host.
- Add dashboard filters for detector ID, severity, and agent.
- Add event-to-detection linking in the UI.
- Add export endpoints for JSON and CSV.
- Add health and lag indicators for detector reloads and policy syncs.
