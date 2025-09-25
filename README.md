# Offensive_AI_CON_2025_Framework

This repository contains a complete, lab-safe reference implementation for the talk "The Machine That Hacks Back — agentic API reconnaissance & verification."

It implements an agentic pipeline that turns a blank URL into a reproducible, verifiable test case in an isolated lab:

- Orchestration/Planner with cost-aware simulated annealing and self-play robustness hooks
- Discovery agent with polite crawling, Probabilistic Endpoint Graph (PEG), and multi-modal fingerprinting
- Contract inference engine using Bayesian posterior updates, active sampling, and semantic response clustering
- MCP-style tooling adapters with sandboxing and differential-execution mode
- Verifier ensemble with counterfactual validation and multi-axis confidence taxonomy
- Safety layer with a Policy DSL, capability tokens, rate limiting, immutable audit logs
- Evidence store with cryptographic provenance chains and redaction
- Drift detector and adversarial emulator for pipeline safety testing
- CLI for end-to-end runs and a lab Flask app for safe demos

Quick start (lab only)

1) Create and activate a Python 3.10+ environment.
2) Install dependencies:

```bash
pip install -r requirements.txt
```

3) Start the lab app in a separate terminal (safe, local-only by default):

```bash
python -m lab_app.app
```

4) Run discovery against the lab app and build a PEG:

```bash
python -m agentic_api.cli discover --base-url http://127.0.0.1:5000 --policy ./configs/policy.dsl
```

5) Run contract inference from collected samples:

```bash
python -m agentic_api.cli infer --base-url http://127.0.0.1:5000
```

6) Execute the meta-planner in verify-only mode with approval gates:

```bash
python -m agentic_api.cli plan --policy ./configs/policy.dsl --verify-only
```

7) End-to-end pipeline (read-only by default):

```bash
python -m agentic_api.cli run --base-url http://127.0.0.1:5000 --policy ./configs/policy.dsl
```

Emulator and drift (lab)

- Toggle emulator (WAF/5xx/latency):

```bash
curl -X POST http://127.0.0.1:5000/admin/emulator \
  -H "Content-Type: application/json" \
  -d '{"waf_block": true, "latency_ms": 200, "emulate_5xx": false}'
```

- Introduce version drift:

```bash
curl -X POST http://127.0.0.1:5000/admin/drift -H "Content-Type: application/json" -d '{"version": 2}'
```

- Compare drift between two PEG snapshots:

```bash
python -m agentic_api.cli drift --old artifacts/peg_old.json --new artifacts/peg.json --threshold 0.9
```

Demo scripts (Windows PowerShell)

- `scripts/run_lab.ps1` — simple end-to-end run
- `scripts/demo_plan.ps1` — baseline, drift, compare, end-to-end

Tests

```bash
pytest -q
```

Important safety notes

- Use this framework only in isolated labs or with explicit, written authorization.
- The Policy DSL and safety layer enforce allowlists, rate limits, and approval gates.
- Evidence is minimized/redacted and backed by immutable provenance hashes.

Structure

- `requirements.txt` — Python dependencies
- `src/agentic_api/` — framework modules
- `configs/` — example policies and config
- `lab_app/` — safe Flask app for demos
- `scripts/` — helper scripts (Windows PowerShell)
- `tests/` — minimal tests

For detailed architecture, algorithms, and demo steps, see docstrings within modules and comments in `agentic_api/cli.py`.
Framework to match Kurtis Shelton's talk at Offensive AI Con in San Diego 2025
