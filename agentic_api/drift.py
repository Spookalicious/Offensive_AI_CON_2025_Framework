from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


class DriftDetector:
    def __init__(self, path: str | Path = "artifacts/peg.json") -> None:
        self.path = Path(path)

    def load_vectors(self) -> Dict[str, List[float]]:
        if not self.path.exists():
            return {}
        d = json.loads(self.path.read_text(encoding="utf-8"))
        vectors: Dict[str, List[float]] = {}
        for n in d.get("nodes", []):
            vectors[n["id"]] = n.get("fingerprint", [])
        return vectors

    @staticmethod
    def similarity(a: List[float], b: List[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        num = sum(x * y for x, y in zip(a, b))
        den1 = sum(x * x for x in a) ** 0.5
        den2 = sum(y * y for y in b) ** 0.5
        if den1 == 0 or den2 == 0:
            return 0.0
        return num / (den1 * den2)

    def compare(self, old_path: str | Path, new_path: str | Path, threshold: float = 0.9) -> Dict:
        old = DriftDetector(old_path).load_vectors()
        new = DriftDetector(new_path).load_vectors()
        changes = []
        for k, v in new.items():
            s = self.similarity(v, old.get(k, []))
            if s < threshold:
                changes.append({"endpoint": k, "similarity": s})
        return {"changes": changes, "count": len(changes)}
