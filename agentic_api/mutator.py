from __future__ import annotations

import urllib.parse
from typing import Dict, List, Tuple


class ParamMutator:
    def __init__(self) -> None:
        pass

    def mutate_url(self, url: str, hints: Dict[str, Dict]) -> List[str]:
        variants = [url]
        parsed = urllib.parse.urlparse(url)
        qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        for field, meta in hints.items():
            tp = (meta.get("type_posterior") or {})
            if field in qs:
                variants += self._mutate_value(url, qs, field, tp)
        return list(dict.fromkeys(variants))

    def _mutate_value(self, url: str, qs: Dict[str, str], field: str, tp: Dict[str, float]) -> List[str]:
        out: List[str] = []
        candidates = []
        # Benign candidates derived from type hints
        if tp.get("int", 0) > 0.3:
            candidates += ["0", "1", "42"]
        if tp.get("uuid_like", 0) > 0.3:
            candidates += ["00000000-0000-0000-0000-000000000000"]
        candidates += [qs.get(field, ""), "", "test"]
        for c in candidates:
            new_qs = qs.copy()
            new_qs[field] = c
            new_query = urllib.parse.urlencode(new_qs)
            parts = list(urllib.parse.urlparse(url))
            parts[4] = new_query
            out.append(urllib.parse.urlunparse(parts))
        return out
