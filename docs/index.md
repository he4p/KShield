# Unified Shield

**Unified Shield** is a Linux runtime security project built using eBPF, combining the robustness of the KShield telemetry manager and agent with modern documentation and UI methodologies.

It observes kernel activity in real time and streams structured events securely to an IPS Control Plane (Manager) for inspection, filtering, analysis, and active enforcement via LSM hooks.

## Overview

At its core, Unified Shield uses:

- **eBPF Agent (Rust)**: BPF programs tracing `sys_enter_*`, `esp_input`, and other core kernel tracepoints, effectively mapping raw kernel state to telemetry structures.
- **Python Manager**: A fast backend server ingesting streams of telemetry over a REST API and correlating them with runtime `.toml` detectors.
- **LSM Enforcement**: Actively blocking unauthorized file writes, network hooks, and `ptrace` manipulations without incurring context-switching overhead.
- **Dashboard**: A gorgeous, glassmorphic frontend UI pulling metrics securely via REST.

## Core Features

- **Novel 0-Day Detection**: Accurately intercepting explicit mechanisms such as CVE-2026-43284 IPsSec ESP UDP fast-paths and CVE-2026-46333 `pidfd_getfd` exploit attempts.
- **Extensible Detection**: Add new logic via `manager/detectors/*.toml` files that are automatically synchronized to the kernel and manager state; zero compilation required. 
- **Beautiful UX**: A fully modern, beautifully orchestrated, natively responsive dark mode display for Security Operators.

!!! tip "Quick Start"
    Check out the **[API Reference](api-reference.md)** to script against the manager, or read the **[Extensibility Guide](extensibility.md)** to add your very own kernel rules!
