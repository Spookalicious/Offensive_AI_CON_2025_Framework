from __future__ import annotations

import json
import re
from typing import Dict, List, Tuple

import numpy as np
from sklearn.cluster import DBSCAN

from .discovery import PEG


_param_re = re.compile(r"/([a-zA-Z_][a-zA-Z0-9_-]*)/(\d+|[a-f0-9-]{8,})")


def _extract_params(url: str) -> List[str]:
    return [m.group(1) for m in _param_re.finditer(url or "")]


def cluster_peg(peg: PEG, eps: float = 0.5, min_samples: int = 2) -> Dict:
    nodes = list(peg.graph.nodes())
    if not nodes:
        return {"clusters": [], "associations": {}, "params": {}}

    # Build matrix from fingerprint vectors
    vectors: List[List[float]] = []
    for n in nodes:
        vec = peg.graph.nodes[n].get("fingerprint", [])
        vectors.append(vec)
    X = np.array(vectors, dtype=float)
    if X.size == 0:
        return {"clusters": [], "associations": {}, "params": {}}

    # Cluster with DBSCAN
    model = DBSCAN(eps=eps, min_samples=min_samples)
    labels = model.fit_predict(X).tolist()

    # Param association: which path params correlate with which cluster ids
    param_bag: Dict[str, List[int]] = {}
    for n, label in zip(nodes, labels):
        for p in _extract_params(n):
            param_bag.setdefault(p, []).append(label)

    associations: Dict[str, Dict[str, float]] = {}
    for p, labs in param_bag.items():
        if not labs:
            continue
        counts: Dict[int, int] = {}
        for l in labs:
            counts[l] = counts.get(l, 0) + 1
        total = float(sum(counts.values()))
        associations[p] = {str(k): v / total for k, v in counts.items()}

    return {
        "clusters": [{"node": n, "label": int(l)} for n, l in zip(nodes, labels)],
        "associations": associations,
        "params": {n: _extract_params(n) for n in nodes},
    }
