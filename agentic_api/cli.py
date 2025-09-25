import argparse
import json
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any

from .policy import Policy, PolicyToken, PolicyParser, KeyManager
from .safety import ScopeEngine, RateLimiter, KillSwitch
from .evidence import EvidenceStore
from .safety import AuditLogger


def ensure_directories() -> None:
    Path("artifacts").mkdir(parents=True, exist_ok=True)
    Path("artifacts/evidence").mkdir(parents=True, exist_ok=True)
    Path("artifacts/audit").mkdir(parents=True, exist_ok=True)
    Path("configs/keys").mkdir(parents=True, exist_ok=True)


def load_policy(policy_path: str) -> Policy:
    parser = PolicyParser()
    with open(policy_path, "r", encoding="utf-8") as f:
        text = f.read()
    return parser.parse(text)


def _ensure_not_killed() -> None:
    if KillSwitch().active():
        print("Kill switch active. Aborting.")
        sys.exit(2)


def command_discover(args: argparse.Namespace) -> None:
    from .discovery import DiscoveryAgent

    _ensure_not_killed()
    ensure_directories()
    policy = load_policy(args.policy) if args.policy else Policy.default_lab()
    keys = KeyManager()
    if not keys.keypair_exists():
        keys.generate()
    policy_token = PolicyToken.from_policy(policy, keys)
    rate_limiter = RateLimiter(max_rps=policy.max_rps)
    scope = ScopeEngine(policy, policy_token, keys)
    store = EvidenceStore(keys=keys)
    audit = AuditLogger()

    agent = DiscoveryAgent(scope=scope, rate_limiter=rate_limiter, evidence_store=store)
    peg = agent.discover(base_url=args.base_url, max_depth=args.max_depth)
    peg_path = Path("artifacts") / "peg.json"
    with open(peg_path, "w", encoding="utf-8") as f:
        json.dump(peg.to_dict(), f, indent=2)
    audit.log({"stage": "discover", "peg": str(peg_path)})
    print(f"Discovery complete. PEG saved to {peg_path}")


def command_infer(args: argparse.Namespace) -> None:
    from .inference import InferenceEngine
    from .discovery import PEG

    _ensure_not_killed()
    ensure_directories()
    peg_path = Path("artifacts") / "peg.json"
    if not peg_path.exists():
        print("PEG not found. Run discover first.")
        sys.exit(1)
    with open(peg_path, "r", encoding="utf-8") as f:
        peg_dict = json.load(f)
    peg = PEG.from_dict(peg_dict)

    engine = InferenceEngine()
    schema = engine.infer(peg)
    schema_path = Path("artifacts") / "inferred_schema.json"
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
    AuditLogger().log({"stage": "infer", "schema": str(schema_path)})
    print(f"Inference complete. Schema saved to {schema_path}")


def command_plan(args: argparse.Namespace) -> None:
    from .planner import MetaPlanner
    from .discovery import PEG

    _ensure_not_killed()
    ensure_directories()
    peg_path = Path("artifacts") / "peg.json"
    if not peg_path.exists():
        print("PEG not found. Run discover first.")
        sys.exit(1)
    with open(peg_path, "r", encoding="utf-8") as f:
        peg_dict = json.load(f)
    peg = PEG.from_dict(peg_dict)

    policy = load_policy(args.policy) if args.policy else Policy.default_lab()
    keys = KeyManager()
    if not keys.keypair_exists():
        keys.generate()
    policy_token = PolicyToken.from_policy(policy, keys)
    scope = ScopeEngine(policy, policy_token, keys)

    planner = MetaPlanner(scope=scope, verify_only=args.verify_only)
    plan = planner.propose_plan(peg)
    plan_path = Path("artifacts") / "plan.json"
    with open(plan_path, "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2)
    AuditLogger().log({"stage": "plan", "plan": str(plan_path), "steps": len(plan.get("steps", []))})
    print(f"Plan created. Saved to {plan_path}")


def command_run(args: argparse.Namespace) -> None:
    from .discovery import DiscoveryAgent
    from .inference import InferenceEngine
    from .planner import MetaPlanner
    from .verifier import Verifier

    _ensure_not_killed()
    ensure_directories()
    policy = load_policy(args.policy) if args.policy else Policy.default_lab()
    keys = KeyManager()
    if not keys.keypair_exists():
        keys.generate()
    policy_token = PolicyToken.from_policy(policy, keys)
    rate_limiter = RateLimiter(max_rps=policy.max_rps)
    scope = ScopeEngine(policy, policy_token, keys)
    store = EvidenceStore(keys=keys)
    audit = AuditLogger()

    agent = DiscoveryAgent(scope=scope, rate_limiter=rate_limiter, evidence_store=store)
    peg = agent.discover(base_url=args.base_url, max_depth=args.max_depth)
    with open(Path("artifacts") / "peg.json", "w", encoding="utf-8") as f:
        json.dump(peg.to_dict(), f, indent=2)
    audit.log({"stage": "discover"})

    inference = InferenceEngine()
    schema = inference.infer(peg)
    with open(Path("artifacts") / "inferred_schema.json", "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
    audit.log({"stage": "infer"})

    planner = MetaPlanner(scope=scope, verify_only=True)
    plan = planner.propose_plan(peg)
    with open(Path("artifacts") / "plan.json", "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2)
    audit.log({"stage": "plan", "steps": len(plan.get("steps", []))})

    verifier = Verifier()
    result = verifier.execute_and_evaluate(plan)
    with open(Path("artifacts") / "evidence_card.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    audit.log({"stage": "verify", "confidence": result.get("confidence_axes", {}).get("confidence_score", 0.0)})
    print("Run complete. Evidence card saved to artifacts/evidence_card.json")


def command_drift(args: argparse.Namespace) -> None:
    from .drift import DriftDetector

    old_path = args.old
    new_path = args.new
    detector = DriftDetector()
    report = detector.compare(old_path, new_path, threshold=args.threshold)
    out = Path("artifacts") / "drift_report.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    AuditLogger().log({"stage": "drift", "changes": report.get("count", 0)})
    print(f"Drift report saved to {out}")


def command_semantic(args: argparse.Namespace) -> None:
    from .discovery import PEG
    from .semcluster import cluster_peg

    peg_path = Path("artifacts") / "peg.json"
    if not peg_path.exists():
        print("PEG not found. Run discover first.")
        sys.exit(1)
    with open(peg_path, "r", encoding="utf-8") as f:
        peg_dict = json.load(f)
    peg = PEG.from_dict(peg_dict)

    result = cluster_peg(peg, eps=args.eps, min_samples=args.min_samples)
    out = Path("artifacts") / "semantic_clusters.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    AuditLogger().log({"stage": "semantic", "clusters": len(result.get("clusters", []))})
    print(f"Semantic clustering saved to {out}")


def command_nuclei(args: argparse.Namespace) -> None:
    from .adapters_nuclei import NucleiAdapter, NucleiConfig

    adapter = NucleiAdapter(NucleiConfig())
    hs = adapter.handshake()
    print(json.dumps({"handshake": hs}, indent=2))
    res = adapter.run({"url": args.url})
    out = Path("artifacts") / "nuclei_result.json"
    out.write_text(json.dumps(res, indent=2), encoding="utf-8")
    AuditLogger().log({"stage": "nuclei", "count": res.get("summary", {}).get("count", 0)})
    print(f"Nuclei result saved to {out}")


def command_burp(args: argparse.Namespace) -> None:
    from .adapters_burp import BurpAdapter, BurpConfig

    adapter = BurpAdapter(BurpConfig())
    hs = adapter.handshake()
    print(json.dumps({"handshake": hs}, indent=2))
    if args.action == "scan":
        res = adapter.run({"action": "scan", "url": args.url})
    else:
        res = adapter.run({"action": "status", "scan_id": args.scan_id})
    out = Path("artifacts") / "burp_result.json"
    out.write_text(json.dumps(res, indent=2), encoding="utf-8")
    AuditLogger().log({"stage": "burp", "ok": res.get("ok", False)})
    print(f"Burp result saved to {out}")


def command_mutate(args: argparse.Namespace) -> None:
    from .discovery import PEG
    from .inference import InferenceEngine
    from .mutator import ParamMutator

    peg_path = Path("artifacts") / "peg.json"
    if not peg_path.exists():
        print("PEG not found. Run discover first.")
        sys.exit(1)
    with open(peg_path, "r", encoding="utf-8") as f:
        peg_dict = json.load(f)
    peg = PEG.from_dict(peg_dict)

    schema_path = Path("artifacts") / "inferred_schema.json"
    if not schema_path.exists():
        print("Schema not found. Run infer first.")
        sys.exit(1)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    hints: Dict[str, Dict[str, Any]] = {k: v for k, v in schema.get("fields", {}).items() if isinstance(v, dict)}

    mut = ParamMutator()
    urls: List[str] = list(peg.graph.nodes())
    variants: Dict[str, List[str]] = {}
    for u in urls[: args.limit]:
        variants[u] = mut.mutate_url(u, hints)
    out = Path("artifacts") / "mutations.json"
    out.write_text(json.dumps({"variants": variants}, indent=2), encoding="utf-8")
    AuditLogger().log({"stage": "mutate", "urls": len(urls[: args.limit])})
    print(f"Mutations saved to {out}")


def command_snapshot(args: argparse.Namespace) -> None:
    from .discovery import PEG
    from .adapters import HttpAdapter

    peg_path = Path("artifacts") / "peg.json"
    if not peg_path.exists():
        print("PEG not found. Run discover first.")
        sys.exit(1)
    with open(peg_path, "r", encoding="utf-8") as f:
        peg_dict = json.load(f)
    peg = PEG.from_dict(peg_dict)

    http = HttpAdapter()
    endpoints: List[str] = list(peg.graph.nodes())[: args.limit]
    results: List[Dict[str, Any]] = []
    for url in endpoints:
        parsed = http.parse(http.run({"adapter": "http", "action": "verify", "method": "GET", "url": url}))
        results.append({"url": url, "result": parsed})
    out = Path("artifacts") / args.output
    out.write_text(json.dumps({"results": results}, indent=2), encoding="utf-8")
    AuditLogger().log({"stage": "snapshot", "count": len(results)})
    print(f"Snapshot saved to {out}")


def command_fuzzdiff(args: argparse.Namespace) -> None:
    from .fuzzdiff import reconcile

    old = json.loads(Path(args.old).read_text(encoding="utf-8"))
    new = json.loads(Path(args.new).read_text(encoding="utf-8"))

    def to_maps(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        return {e["url"]: e["result"] for e in doc.get("results", [])}

    old_map = to_maps(old)
    new_map = to_maps(new)
    common = sorted(set(old_map.keys()) & set(new_map.keys()))
    report = reconcile(common, [old_map[u] for u in common], [new_map[u] for u in common])
    out = Path("artifacts") / "fuzzdiff_report.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    AuditLogger().log({"stage": "fuzzdiff", "working": report.get("working", 0), "total": report.get("total", 0)})
    print(f"Fuzz-diff report saved to {out}")


def command_chain(args: argparse.Namespace) -> None:
    import requests

    base = args.base_url.rstrip("/")
    evidence: List[Dict[str, Any]] = []
    # Step 1: admin without token (expected 403)
    r1 = requests.get(f"{base}/poc/admin", timeout=5)
    evidence.append({"step": "admin_no_token", "status": r1.status_code})
    # Step 2: weak bypass with any token (expected 200)
    r2 = requests.get(f"{base}/poc/admin", headers={"X-Token": "valid-user"}, timeout=5)
    evidence.append({"step": "admin_weak_bypass", "status": r2.status_code})
    # Step 3: data leak (keys count increases when internal=true)
    r3a = requests.get(f"{base}/poc/user?id=1&internal=false", timeout=5).json()
    r3b = requests.get(f"{base}/poc/user?id=1&internal=true", timeout=5).json()
    evidence.append({"step": "user_leak_keys", "keys_no_internal": len(r3a.keys()), "keys_with_internal": len(r3b.keys())})
    # Step 4: logic flaw (crafted flag doubles discount)
    r4a = requests.get(f"{base}/poc/checkout?id=1&price=100&crafted=false", timeout=5).json()
    r4b = requests.get(f"{base}/poc/checkout?id=1&price=100&crafted=true", timeout=5).json()
    evidence.append({"step": "logic_flaw_total", "total_normal": r4a.get("total"), "total_crafted": r4b.get("total")})

    out = Path("artifacts") / "chain_evidence.json"
    out.write_text(json.dumps({"evidence": evidence}, indent=2), encoding="utf-8")
    AuditLogger().log({"stage": "chain", "steps": len(evidence)})
    print(f"Chain evidence saved to {out}")


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Agentic API pipeline CLI (lab-safe)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_discover = subparsers.add_parser("discover", help="Run discovery to build a PEG")
    p_discover.add_argument("--base-url", required=True)
    p_discover.add_argument("--policy", required=False, default="configs/policy.dsl")
    p_discover.add_argument("--max-depth", type=int, default=2)
    p_discover.set_defaults(func=command_discover)

    p_infer = subparsers.add_parser("infer", help="Run contract inference from PEG")
    p_infer.add_argument("--base-url", required=False)
    p_infer.set_defaults(func=command_infer)

    p_plan = subparsers.add_parser("plan", help="Build a verification plan from PEG")
    p_plan.add_argument("--policy", required=False, default="configs/policy.dsl")
    p_plan.add_argument("--verify-only", action="store_true")
    p_plan.set_defaults(func=command_plan)

    p_run = subparsers.add_parser("run", help="End-to-end pipeline (read-only)")
    p_run.add_argument("--base-url", required=True)
    p_run.add_argument("--policy", required=False, default="configs/policy.dsl")
    p_run.add_argument("--max-depth", type=int, default=2)
    p_run.set_defaults(func=command_run)

    p_drift = subparsers.add_parser("drift", help="Compare two PEG files for drift")
    p_drift.add_argument("--old", required=True)
    p_drift.add_argument("--new", required=True)
    p_drift.add_argument("--threshold", type=float, default=0.9)
    p_drift.set_defaults(func=command_drift)

    p_sem = subparsers.add_parser("semantic", help="Cluster PEG semantically and infer param associations")
    p_sem.add_argument("--eps", type=float, default=0.5)
    p_sem.add_argument("--min-samples", type=int, default=2)
    p_sem.set_defaults(func=command_semantic)

    p_nuclei = subparsers.add_parser("nuclei", help="Run nuclei against a single URL")
    p_nuclei.add_argument("--url", required=True)
    p_nuclei.set_defaults(func=command_nuclei)

    p_burp = subparsers.add_parser("burp", help="Run burp action (scan/status)")
    p_burp.add_argument("--action", choices=["scan", "status"], required=True)
    p_burp.add_argument("--url", required=False)
    p_burp.add_argument("--scan-id", required=False)
    p_burp.set_defaults(func=command_burp)

    p_mut = subparsers.add_parser("mutate", help="Generate benign parameter variants from inferred schema")
    p_mut.add_argument("--limit", type=int, default=25)
    p_mut.set_defaults(func=command_mutate)

    p_snap = subparsers.add_parser("snapshot", help="Create a snapshot of endpoint results from PEG")
    p_snap.add_argument("--limit", type=int, default=25)
    p_snap.add_argument("--output", default="snapshot.json")
    p_snap.set_defaults(func=command_snapshot)

    p_fdiff = subparsers.add_parser("fuzzdiff", help="Reconcile two snapshots and summarize diffs")
    p_fdiff.add_argument("--old", required=True)
    p_fdiff.add_argument("--new", required=True)
    p_fdiff.set_defaults(func=command_fuzzdiff)

    p_chain = subparsers.add_parser("chain", help="Run a safe chain against lab PoC endpoints")
    p_chain.add_argument("--base-url", required=True)
    p_chain.set_defaults(func=command_chain)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
