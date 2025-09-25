from __future__ import annotations

from typing import Any, Dict, List


def normalize_result(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": result.get("status_code", 0),
        "length": result.get("content_length", 0),
        "content_type": (result.get("headers", {}) or {}).get("Content-Type", ""),
    }


def diff_results(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    na = normalize_result(a)
    nb = normalize_result(b)
    return {
        "status_changed": na["status"] != nb["status"],
        "length_changed": na["length"] != nb["length"],
        "type_changed": na["content_type"] != nb["content_type"],
    }


def reconcile(endpoints: List[str], baseline: List[Dict[str, Any]], current: List[Dict[str, Any]]) -> Dict[str, Any]:
    working = 0
    changed = 0
    summary: List[Dict[str, Any]] = []
    for ep, a, b in zip(endpoints, baseline, current):
        d = diff_results(a, b)
        if any(d.values()):
            changed += 1
        else:
            working += 1
        summary.append({"endpoint": ep, "diff": d})
    total = len(endpoints)
    return {
        "working": working,
        "changed": changed,
        "total": total,
        "message": f"{working} of {total} calls still work",
        "summary": summary,
    }
