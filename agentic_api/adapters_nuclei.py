from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from pydantic import BaseModel

from .adapters import Adapter, AdapterContract


class NucleiConfig(BaseModel):
    bin_path: str = "nuclei"
    templates_dir: str | None = None
    severity: List[str] = ["low", "medium"]
    rate_limit: int = 50
    timeout: int = 10


class NucleiAdapter(Adapter):
    name = "nuclei"

    def __init__(self, config: NucleiConfig | None = None) -> None:
        self.config = config or NucleiConfig()

    def handshake(self) -> Dict[str, Any]:
        c = AdapterContract(name=self.name, version="0.1", capabilities=["verify-only", "differential"]).model_dump()
        return {**c, "config": self.config.model_dump()}

    def _build_cmd(self, url: str) -> List[str]:
        cmd = [self.config.bin_path, "-u", url, "-json", "-rl", str(self.config.rate_limit), "-timeout", str(self.config.timeout)]
        if self.config.templates_dir:
            cmd += ["-t", self.config.templates_dir]
        if self.config.severity:
            cmd += ["-severity", ",".join(self.config.severity)]
        return cmd

    def _run_nuclei(self, url: str) -> Dict[str, Any]:
        cmd = self._build_cmd(url)
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
            findings: List[Dict[str, Any]] = []
            for line in proc.stdout.splitlines():
                try:
                    findings.append(json.loads(line))
                except Exception:
                    continue
            return {
                "ok": proc.returncode == 0 or bool(findings),
                "returncode": proc.returncode,
                "findings": findings,
                "stderr": proc.stderr[:2000],
            }
        except FileNotFoundError:
            return {"ok": False, "error": "nuclei not found"}

    def run(self, step: Dict[str, Any]) -> Dict[str, Any]:
        url = step.get("url")
        result = self._run_nuclei(url)
        return {
            "ok": result.get("ok", False),
            "summary": {
                "count": len(result.get("findings", [])),
                "by_template": self._by_key(result.get("findings", []), "template-id"),
                "by_severity": self._by_key(result.get("findings", []), "info.severity"),
            },
        }

    @staticmethod
    def _by_key(items: List[Dict[str, Any]], dotted_key: str) -> Dict[str, int]:
        parts = dotted_key.split(".")
        counts: Dict[str, int] = {}
        for it in items:
            cur: Any = it
            for p in parts:
                if isinstance(cur, dict):
                    cur = cur.get(p)
                else:
                    cur = None
                    break
            key = str(cur) if cur is not None else "unknown"
            counts[key] = counts.get(key, 0) + 1
        return counts

    def differential(self, step_a: Dict[str, Any], step_b: Dict[str, Any]) -> Dict[str, Any]:
        ra = self.run(step_a)
        rb = self.run(step_b)
        delta = {
            "count_diff": rb["summary"]["count"] - ra["summary"]["count"],
        }
        return {"a": ra, "b": rb, "delta": delta}
