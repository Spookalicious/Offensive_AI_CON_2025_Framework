from __future__ import annotations

import random
from typing import Any, Dict, List

from .adapters import HttpAdapter


class Verifier:
    def __init__(self) -> None:
        self.http = HttpAdapter()

    def _statistical_eval(self, result: Dict[str, Any]) -> float:
        sc = result.get("status_code", 0)
        return 1.0 if 200 <= sc < 400 else 0.2 if sc else 0.0

    def _rule_eval(self, result: Dict[str, Any]) -> float:
        headers = result.get("headers", {})
        ct = headers.get("Content-Type", "")
        return 0.8 if ("json" in ct or "html" in ct) else 0.4

    def _sft_eval(self, result: Dict[str, Any]) -> float:
        # Placeholder small model: derivative heuristic
        length = result.get("content_length", 0)
        return 0.7 if length > 0 else 0.3

    def _ensemble(self, result: Dict[str, Any]) -> float:
        scores = [
            self._statistical_eval(result),
            self._rule_eval(result),
            self._sft_eval(result),
        ]
        return sum(scores) / len(scores)

    def execute_and_evaluate(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        steps: List[Dict[str, Any]] = plan.get("steps", [])
        evidences: List[Dict[str, Any]] = []
        for step in steps:
            parsed = self.http.parse(self.http.run(step))
            score = self._ensemble(parsed)
            # counterfactual: replay HEAD vs GET difference as a benign check
            cf = self.http.parse(self.http.run({**step, "method": "HEAD"}))
            agree = abs(self._ensemble(cf) - score) < 0.3
            evidences.append({"result": parsed, "score": score, "counterfactual_agree": agree})

        confidence = sum(e["score"] for e in evidences) / max(1, len(evidences)) if evidences else 0.0
        return {
            "summary": "Verification results",
            "confidence_axes": {
                "reproducibility": 0.7 if evidences else 0.0,
                "semantic_impact": confidence,
                "collateral_risk": 0.2,
                "confidence_score": confidence,
            },
            "artifacts": evidences,
        }
