from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from pydantic import BaseModel, Field


class AdapterContract(BaseModel):
    name: str
    version: str
    capabilities: list[str] = Field(default_factory=lambda: ["verify-only", "differential"])


class Step(BaseModel):
    adapter: str
    action: str
    method: str = "GET"
    url: str
    expected_signal: str = "2xx_or_3xx"
    cost: float = 1.0
    risk: float = 0.1
    rationale: Optional[str] = None


@dataclass
class AdapterResult:
    ok: bool
    status_code: int
    content_length: int
    headers: Dict[str, str]


class Adapter:
    name = "base"

    def handshake(self) -> Dict[str, Any]:
        return AdapterContract(name=self.name, version="0.1").model_dump()

    def run(self, step: Dict[str, Any]) -> AdapterResult:  # pragma: no cover - interface
        raise NotImplementedError

    def parse(self, result: AdapterResult) -> Dict[str, Any]:
        return {
            "ok": result.ok,
            "status_code": result.status_code,
            "content_length": result.content_length,
            "headers": result.headers,
        }


class HttpAdapter(Adapter):
    name = "http"

    def run(self, step: Dict[str, Any]) -> AdapterResult:
        s = Step(**step)
        try:
            if s.method.upper() == "HEAD":
                resp = requests.head(s.url, timeout=5)
            elif s.method.upper() == "POST":
                resp = requests.post(s.url, json={"_": "synthetic"}, timeout=5)
            else:
                resp = requests.get(s.url, timeout=5)
            return AdapterResult(
                ok=resp.ok,
                status_code=resp.status_code,
                content_length=len(resp.content or b"") if hasattr(resp, "content") else 0,
                headers={k: v for k, v in resp.headers.items()},
            )
        except Exception:
            return AdapterResult(ok=False, status_code=0, content_length=0, headers={})

    def differential(self, step_a: Dict[str, Any], step_b: Dict[str, Any]) -> Dict[str, Any]:
        ra = self.run(step_a)
        rb = self.run(step_b)
        delta = {
            "status_diff": rb.status_code - ra.status_code,
            "length_diff": rb.content_length - ra.content_length,
        }
        return {
            "a": self.parse(ra),
            "b": self.parse(rb),
            "delta": delta,
        }
