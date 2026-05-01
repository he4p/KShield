# KShield Benchmark Scripts

These scripts benchmark KShield detection quality and runtime performance using the manager HTTP API.

## Prereqs

- Manager running (default `http://127.0.0.1:8080`)
- Agent running and registered to the manager
- Python 3 (stdlib only)

## Quick run (with your already-running manager/agent)

```bash
cd KShield
python3 bench/run_benchmark.py --manager-url http://127.0.0.1:8080
```

Or via wrapper:

```bash
cd KShield
bash scripts/run_benchmark.sh --manager-url http://127.0.0.1:8080
```

Outputs:

- `bench/out/report.json` (full results)
- `bench/out/report.txt` (human summary)

## Notes on CPU/Mem “overhead”

The benchmark computes CPU/memory during a workload while KShield is running.
To compute **overhead vs. no monitoring**, run a baseline on the same machine/workload:

1) Stop agent + manager, then run:

```bash
python3 bench/run_benchmark.py --mode baseline --load-secs 20
```

2) Start agent + manager again, then run:

```bash
python3 bench/run_benchmark.py --mode monitored --load-secs 20 --baseline bench/out/baseline.json
```

## Customizing the suite

The default suite is `bench/suite.default.json`. You can edit it or pass `--suite <path>`.
