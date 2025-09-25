import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .policy import Policy, PolicyToken, PolicyParser, KeyManager
from .safety import ScopeEngine, RateLimiter, KillSwitch


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
    from .evidence import EvidenceStore

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

    agent = DiscoveryAgent(scope=scope, rate_limiter=rate_limiter, evidence_store=store)
    peg = agent.discover(base_url=args.base_url, max_depth=args.max_depth)
    peg_path = Path("artifacts") / "peg.json"
    with open(peg_path, "w", encoding="utf-8") as f:
        json.dump(peg.to_dict(), f, indent=2)
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
    print(f"Plan created. Saved to {plan_path}")


def command_run(args: argparse.Namespace) -> None:
    from .discovery import DiscoveryAgent
    from .inference import InferenceEngine
    from .planner import MetaPlanner
    from .verifier import Verifier
    from .evidence import EvidenceStore

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

    # 1) Discover
    agent = DiscoveryAgent(scope=scope, rate_limiter=rate_limiter, evidence_store=store)
    peg = agent.discover(base_url=args.base_url, max_depth=args.max_depth)
    with open(Path("artifacts") / "peg.json", "w", encoding="utf-8") as f:
        json.dump(peg.to_dict(), f, indent=2)

    # 2) Infer
    inference = InferenceEngine()
    schema = inference.infer(peg)
    with open(Path("artifacts") / "inferred_schema.json", "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)

    # 3) Plan
    planner = MetaPlanner(scope=scope, verify_only=True)
    plan = planner.propose_plan(peg)
    with open(Path("artifacts") / "plan.json", "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2)

    # 4) Execute + Verify
    verifier = Verifier()
    result = verifier.execute_and_evaluate(plan)
    with open(Path("artifacts") / "evidence_card.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print("Run complete. Evidence card saved to artifacts/evidence_card.json")


def command_drift(args: argparse.Namespace) -> None:
    from .drift import DriftDetector

    old_path = args.old
    new_path = args.new
    detector = DriftDetector()
    report = detector.compare(old_path, new_path, threshold=args.threshold)
    out = Path("artifacts") / "drift_report.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Drift report saved to {out}")


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

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
