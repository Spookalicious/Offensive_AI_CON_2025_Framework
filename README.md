# Offensive_AI_CON_2025_Framework

This repository contains a lab-safe reference implementation for the talk "The Machine That Hacks Back — agentic API reconnaissance & verification."

It implements an agentic pipeline that turns a blank URL into a reproducible, verifiable test case in an isolated lab:

- Orchestration/Planner with cost-aware simulated annealing and explainable per-step rationales
- Discovery agent with polite crawling, Probabilistic Endpoint Graph (PEG), and multi-modal fingerprinting (headers/size/latency/TLS)
- Contract inference engine with posterior-like schema inference and active-sampling prioritization
- MCP-style tooling adapters (typed contracts) with differential-execution mode
- Verifier ensemble with counterfactual validation and multi-axis confidence taxonomy
- Safety layer with a Policy DSL, capability tokens, rate limiting, kill switch, immutable audit logs
- Evidence store with cryptographic provenance chains and redaction
- Drift detector, semantic clustering, and adversarial emulator (WAF/5xx/latency)
- CLI for end-to-end runs and a lab Flask app for demos

Quick start (lab only)

1) Create and activate a Python 3.10+ environment.
2) Install dependencies:

```bash
pip install -r requirements.txt
```

3) Start the lab app in a separate terminal:

```bash
python -m lab_app.app
```

4) Discovery → PEG:

```bash
python -m agentic_api.cli discover --base-url http://127.0.0.1:5000 --policy ./configs/policy.dsl
```

5) Inference:

```bash
python -m agentic_api.cli infer
```

6) Plan (verify-only):

```bash
python -m agentic_api.cli plan --policy ./configs/policy.dsl --verify-only
```

7) End-to-end (read-only):

```bash
python -m agentic_api.cli run --base-url http://127.0.0.1:5000 --policy ./configs/policy.dsl
```

8) Semantic clustering:

```bash
python -m agentic_api.cli semantic --eps 0.5 --min-samples 2
```

9) Drift compare:

```bash
python -m agentic_api.cli drift --old artifacts/peg_old.json --new artifacts/peg.json --threshold 0.9
```

Emulator (lab)

```bash
curl -X POST http://127.0.0.1:5000/admin/emulator \
  -H "Content-Type: application/json" \
  -d '{"waf_block": true, "latency_ms": 200, "emulate_5xx": false}'
```

Tests

```bash
pytest -q
```

Safety notes

- Use only in isolated labs or with explicit, written authorization.
- Policy DSL enforces allowlists, rate limits, and approval gates.
- Evidence is redacted and hashed; no raw payloads stored in central logs.

Artifacts

- `artifacts/peg.json`, `artifacts/inferred_schema.json`, `artifacts/plan.json`,
  `artifacts/evidence_card.json`, `artifacts/semantic_clusters.json`, `artifacts/drift_report.json`,
  `artifacts/audit/audit.jsonl`
