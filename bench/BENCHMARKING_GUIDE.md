# KShield End-to-End Benchmarking Guide

## 1. Overview
The KShield benchmarking suite objectively evaluates the KShield system across two primary dimensions:
- **Detection Quality**: Computes metrics like True Positive Rate (TPR), False Negatives (FN), and overall Accuracy by simulating real-world attacks.
- **System Performance**: Captures runtime impacts including CPU overhead, Memory (RSS) footprint, Event Throughput, and Detection Latency.

The implementation strictly reflects the formalized metrics listed inside `Metriques.txt`.

---

## 2. Benchmark Architecture

### 2.1 Core Components
- **Manager API (`http://127.0.0.1:8080`)**: The benchmark runs externally, interacting directly with the manager API to read generated detections and update active policies.
- **Agent Server (`kshield-agent`)**: Intercepts the generated activities. It must be hooked and streaming events to the manager.
- **Orchestrator (`bench/run_benchmark.py`)**: The primary execution script that parses the test suite, launches payloads, tracks PIDs, and calculates metrics.
- **Payload Binary (`bench/ksbench_action.py`)**: A dedicated binary process designed to trigger specific system calls (e.g. `bpf`, `mount`, `ptrace`) or file access patterns representing attacks.
- **Suite Protocol (`bench/suite.default.json`)**: An array of tests categorized into `non_policy_tests` (read-only evaluations) and `policy_tests` (which require dynamic interaction with blocking policies).

---

## 3. Execution Flow (End-to-End)

The full lifecycle for achieving performance analytics follows these phases:

### Phase A: Baseline Generation
Before measuring KShield overhead, the system must determine ambient resource usage. 
```bash
python3 bench/run_benchmark.py --mode baseline --load-secs 20
```
This runs a benign load generator without evaluating detections, capturing steady-state CPU and Memory metrics to `bench/out/baseline.json`.

### Phase B: Monitored Execution
The user executes the monitored benchmark session against the active KShield infrastructure.
```bash
python3 bench/run_benchmark.py --mode monitored --manager-url http://127.0.0.1:8080 --baseline bench/out/baseline.json
```

1. **Pre-flight**: The orchestrator discovers the active manager and agent PIDs (via `ps -eo`). It also captures the baseline snapshot of the current KShield policy profiles.
2. **Launch & Trace**: Iterating through `suite.default.json`, `run_benchmark.py` instantiates `ksbench_action.py` to trigger specific activities alongside a unique `comm` identifier.
3. **Observation window**: For each triggered action, the script pools the Manager's `/api/v1/events` and `/api/v1/detections` endpoints up to a timeout threshold (default 6 seconds).
4. **Classification**: 
   - Uses the JSON suite to check for `expected_detectors`.
   - If expected detectors are observed, it's counted as a **True Positive (TP)**. 
   - If benign activities are evaluated and ignored, it's a **True Negative (TN)**.
5. **Policy Injection**: To run active blocking tests (e.g. `network egress blocking`), the script POSTs temporary policies to the API, sleeps (to allow the agent to sync the eBPF maps), executes the payload verifying `action_rc` failure, and eventually restores the initial policy cleanly.

### Phase C: System Loading
Once discrete testing completes, KShield undergoes a sustained volume test (`load-secs = 20`):
- Iteratively floods open files (`ksbench_action open_hosts`).
- Every second, reads `/proc/stat` and `/proc/meminfo` system resources.
- Targets isolated agent/manager telemetry via `/proc/<pid>/stat` and `/proc/<pid>/statm`.
- Monitors `/api/v1/metrics/summary` to isolate throughput capacity.

---

## 4. Derived Metrics calculations

As defined in `Metriques.txt`:
1. **Accuracy Framework**: Derived strictly from TP, TN, FP, FN metrics gathered in Phase B. 
   *($TPR = TP / (TP + FN)$)*
2. **Surcharge CPU/Memory (%)**: Takes the median usage gathered in Phase C, factoring out ambient consumption using `baseline.json`. 
   *($Overhead\_Percent = (CPU_{monitored} - CPU_{baseline}) / CPU_{baseline} * 100$)*
3. **Latence de Détection**: Computes the drift between the Event log's temporal epoch vs the UTC epoch the API finally served the processed detection.
4. **Throughput**: Calculated through differential reads of the API total events count (`end_total_events - start_total_events`) during the loaded window of `Phase C`.

---

## 5. Output and Presentation
Upon conclusion, the benchmark translates findings into visual/report formats inside `bench/out/`.
- **`report.json`**: Granular logging of metrics, including timeline sequences and detection mapping logs.
- **`generate_html.py`**: A python script that reads the structured `report.json` to synthesize a rich, comprehensive browser-based dashboard layout equipped with interactive `Chart.js` objects. Use this tool via `python3 bench/out/generate_html.py` to generate an end-to-end web presentation that others can intuitively comprehend.
