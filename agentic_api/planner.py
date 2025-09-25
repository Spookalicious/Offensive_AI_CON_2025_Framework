from __future__ import annotations

import math
import random
from typing import Dict, List

from .discovery import PEG
from .safety import ScopeEngine


class MetaPlanner:
    def __init__(self, scope: ScopeEngine, verify_only: bool = True) -> None:
        self.scope = scope
        self.verify_only = verify_only

    def propose_plan(self, peg: PEG) -> Dict:
        """Generate a low-risk plan: select top-N endpoints by simple centrality and propose GET/HEAD checks.

        Uses a basic simulated annealing sampler to choose between candidate steps.
        """
        endpoints: List[str] = list(peg.graph.nodes())
        if not endpoints:
            return {"steps": [], "rationale": "No endpoints discovered"}

        candidates = []
        for url in endpoints[:50]:
            candidates.append({
                "adapter": "http",
                "action": "verify",
                "method": "GET",
                "url": url,
                "expected_signal": "2xx_or_3xx",
                "cost": 1.0,
                "risk": 0.1,
                "rationale": "Read-only verification of liveness and content shape",
            })

        temperature = 1.0
        alpha = 0.5
        plan: List[Dict] = []
        current_score = -1e9
        for _ in range(min(20, len(candidates))):
            choice = random.choice(candidates)
            info_gain = 1.0
            score = info_gain - alpha * (choice["cost"] + choice["risk"])
            accept = False
            if score > current_score:
                accept = True
            else:
                prob = math.exp((score - current_score) / max(0.01, temperature))
                accept = random.random() < prob
            if accept:
                plan.append(choice)
                current_score = score
            temperature *= 0.95

        return {
            "steps": plan,
            "verify_only": self.verify_only,
            "rationale": "Cost-aware annealing selection of safe verification checks",
        }
