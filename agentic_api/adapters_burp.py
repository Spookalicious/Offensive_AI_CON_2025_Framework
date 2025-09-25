from __future__ import annotations

import os
from typing import Any, Dict

import requests
from pydantic import BaseModel

from .adapters import Adapter, AdapterContract


class BurpConfig(BaseModel):
    base_url: str = "http://127.0.0.1:1337"
    api_key_env: str = "BURP_API_KEY"


class BurpAdapter(Adapter):
    name = "burp"

    def __init__(self, config: BurpConfig | None = None) -> None:
        self.config = config or BurpConfig()

    def handshake(self) -> Dict[str, Any]:
        return {**AdapterContract(name=self.name, version="0.1").model_dump(), "config": self.config.model_dump()}

    def _headers(self) -> Dict[str, str]:
        api_key = os.environ.get(self.config.api_key_env, "")
        return {"Authorization": f"Bearer {api_key}"} if api_key else {}

    def run(self, step: Dict[str, Any]) -> Dict[str, Any]:
        action = step.get("action", "scan")
        if action == "scan":
            return self._launch_scan(step)
        if action == "status":
            return self._scan_status(step.get("scan_id"))
        return {"ok": False, "error": "unknown action"}

    def _launch_scan(self, step: Dict[str, Any]) -> Dict[str, Any]:
        target = step.get("url")
        try:
            r = requests.post(f"{self.config.base_url}/v0.1/scan", json={"url": target}, headers=self._headers(), timeout=10)
            if r.ok:
                data = r.json()
                return {"ok": True, "scan_id": data.get("id"), "message": "scan started"}
            return {"ok": False, "error": r.text[:2000]}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _scan_status(self, scan_id: str | None) -> Dict[str, Any]:
        if not scan_id:
            return {"ok": False, "error": "missing scan_id"}
        try:
            r = requests.get(f"{self.config.base_url}/v0.1/scan/{scan_id}", headers=self._headers(), timeout=10)
            if r.ok:
                data = r.json()
                return {
                    "ok": True,
                    "progress": data.get("progress"),
                    "findings": data.get("findings", []),
                }
            return {"ok": False, "error": r.text[:2000]}
        except Exception as e:
            return {"ok": False, "error": str(e)}
