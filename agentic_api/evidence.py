from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from .policy import KeyManager


class EvidenceStore:
    """Stores structured evidence with provenance hash chains and minimal raw artifacts."""

    SENSITIVE_HEADER_KEYS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "api-key"}

    def __init__(self, root: str | Path = "artifacts/evidence", keys: Optional[KeyManager] = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.keys = keys

    @staticmethod
    def _hash_dict(d: Dict[str, Any]) -> str:
        blob = json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def write_structured(self, name: str, content: Dict[str, Any], parent_hash: str = "") -> Dict[str, Any]:
        record = {
            "parent": parent_hash,
            "content": content,
        }
        h = self._hash_dict(record)
        out = {"hash": h, **record}
        path = self.root / f"{name}.json"
        path.write_text(json.dumps(out, indent=2), encoding="utf-8")
        return out

    def redact_body(self, body: str, keep_len: bool = True) -> str:
        if body is None:
            return ""
        if keep_len:
            return f"<redacted:{len(body)}B>"
        return "<redacted>"

    def redact_headers(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        sanitized: Dict[str, Any] = {}
        for k, v in (headers or {}).items():
            if k is None:
                continue
            if k.lower() in self.SENSITIVE_HEADER_KEYS:
                sanitized[k] = "<redacted>"
            else:
                sanitized[k] = v
        return sanitized
