from __future__ import annotations

from typing import Any, Dict, List


class ChainExecutor:
    def __init__(self) -> None:
        pass

    def run(self, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        executed: List[Dict[str, Any]] = []
        state: Dict[str, Any] = {}
        for s in steps:
            if not self._preconditions_met(s, state):
                executed.append({"step": s, "ok": False, "reason": "preconditions failed"})
                continue
            # In a full system this would call adapters; here we record intended effect
            effect = s.get("effect", {})
            state.update(effect)
            executed.append({"step": s, "ok": True, "state": state.copy()})
        return {"executed": executed}

    def _preconditions_met(self, step: Dict[str, Any], state: Dict[str, Any]) -> bool:
        req = step.get("requires", {})
        for k, v in req.items():
            if state.get(k) != v:
                return False
        return True
