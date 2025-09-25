from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Dict, List

from .discovery import PEG


class InferenceEngine:
    """Infers a coarse schema from PEG using path/query heuristics and response observations.

    Supports a simple active-sampling heuristic to prioritize high-entropy fields.
    """

    path_param_re = re.compile(r"/([a-zA-Z_][a-zA-Z0-9_-]*)/(\d+|[a-f0-9-]{8,})")

    def infer(self, peg: PEG, active_sampling: bool = True, budget: int = 20) -> Dict:
        field_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        node_fields: Dict[str, Dict[str, Dict[str, float]]] = {}

        for node_id in peg.graph.nodes():
            node = peg.graph.nodes[node_id]
            url = node_id
            for m in self.path_param_re.finditer(url):
                name = m.group(1)
                value = m.group(2)
                t = self._type_hint(value)
                field_counts[name][t] += 1
                field_counts[name]["evidence"] += 1
            ct = (node.get("content_type") or "").lower()
            if "json" in ct:
                field_counts["response_body"]["json"] += 1
            elif "html" in ct:
                field_counts["response_body"]["html"] += 1

        # Optional: active sampling prioritization (score fields by entropy proxy)
        if active_sampling:
            scored = []
            for name, counts in field_counts.items():
                total = max(1, counts.get("evidence", sum(v for k, v in counts.items() if k != "evidence")))
                probs = [v / total for k, v in counts.items() if k != "evidence"]
                entropy = -sum(p * math.log(p + 1e-9) for p in probs)
                scored.append((entropy, name))
            scored.sort(reverse=True)
            # Trim to budget most uncertain fields (no live probes issued; just expose ranked fields)
            top = [name for _, name in scored[:budget]]
            node_fields["active_sampling_priority"] = {n: {"priority": i} for i, n in enumerate(top)}

        for name, counts in field_counts.items():
            total = max(1, counts.get("evidence", sum(counts.values())))
            node_fields[name] = {
                "type_posterior": {
                    k: v / total for k, v in counts.items() if k != "evidence"
                },
                "required_prob": min(1.0, counts.get("required", 0) / total),
                "evidence_count": total,
            }

        schema = {
            "fields": node_fields,
            "global_confidence": 0.6 if node_fields else 0.0,
        }
        return schema

    @staticmethod
    def _type_hint(value: str) -> str:
        if value.isdigit():
            return "int"
        if re.fullmatch(r"[a-f0-9-]{8,}", value):
            return "uuid_like"
        return "string"
