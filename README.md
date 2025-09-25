# Offensive_AI_CON_2025_Framework

This repository contains a lab-safe reference implementation for the talk "The Machine That Hacks Back — agentic API reconnaissance & verification."

It implements an agentic pipeline that turns a blank URL into a reproducible, verifiable test case in an isolated lab:

- Orchestration/Planner with cost-aware simulated annealing and explainable per-step rationales
- Discovery agent with polite crawling, Probabilistic Endpoint Graph (PEG), and multi-modal fingerprinting (headers/size/latency/TLS)
- Contract inference engine with posterior-like schema inference and active-sampling prioritization
- MCP-style tooling adapters (typed contracts) with differential-execution mode, plus adapters for Nuclei and Burp
- Verifier ensemble with counterfactual validation and multi-axis confidence taxonomy
- Safety layer with a Policy DSL, capability tokens, rate limiting, kill switch, immutable audit logs
- Evidence store with cryptographic provenance chains and redaction
- Drift detector, semantic clustering, and adversarial emulator (WAF/5xx/latency)
- CLI for end-to-end runs and a lab Flask app for demos

Quick start (lab only)

```bash
python -m lab_app.app
python -m agentic_api.cli discover --base-url http://127.0.0.1:5000 --policy ./configs/policy.dsl
python -m agentic_api.cli infer
python -m agentic_api.cli plan --policy ./configs/policy.dsl --verify-only
python -m agentic_api.cli run --base-url http://127.0.0.1:5000 --policy ./configs/policy.dsl
```

Advanced commands

```bash
# Semantic clustering over PEG
a python -m agentic_api.cli semantic --eps 0.5 --min-samples 2

# Drift compare
python -m agentic_api.cli drift --old artifacts/peg_old.json --new artifacts/peg.json --threshold 0.9

# Mutations from inferred schema
python -m agentic_api.cli mutate --limit 25

# Snapshots and fuzz-diff reconciliation
python -m agentic_api.cli snapshot --limit 25 --output snapshot_old.json
python -m agentic_api.cli snapshot --limit 25 --output snapshot_new.json
python -m agentic_api.cli fuzzdiff --old artifacts/snapshot_old.json --new artifacts/snapshot_new.json

# Nuclei (requires nuclei installed)
python -m agentic_api.cli nuclei --url http://127.0.0.1:5000

# Burp (requires Burp REST API + BURP_API_KEY)
python -m agentic_api.cli burp --action scan --url http://127.0.0.1:5000
python -m agentic_api.cli burp --action status --scan-id <id>

# Safe chain demo against lab PoCs
python -m agentic_api.cli chain --base-url http://127.0.0.1:5000
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
  `artifacts/snapshot_*.json`, `artifacts/fuzzdiff_report.json`, `artifacts/nuclei_result.json`, `artifacts/burp_result.json`,
  `artifacts/chain_evidence.json`, `artifacts/audit/audit.jsonl`
